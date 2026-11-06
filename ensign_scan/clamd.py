"""Minimal clamd unix-socket client, plus a clamscan CLI fallback.

How clamd gets at a file
------------------------
clamd runs as its own unprivileged user (`clamav`), not as you. There are
two ways to hand it a file:

  * SCAN <path>  -- clamd opens the path itself, as `clamav`. Anything
                    `clamav` can't read comes back "Permission denied",
                    and the only fix is granting `clamav` standing read
                    access (ACLs), which reaches far more than one file.
  * FILDES       -- Ensign opens the file as you, then passes clamd the
                    already-open descriptor over the Unix socket
                    (SCM_RIGHTS). The kernel checked *your* permission at
                    open(); clamd gets a handle to that one file, for that
                    one scan, and no permission on anything. This is what
                    `clamdscan --fdpass` does.

Ensign uses FILDES whenever clamd supports it, and falls back to SCAN
(with a warning) when it doesn't. It refuses to send anything to a clamd
running as root: clamd parses untrusted files, and ClamAV itself advises
against running it as root.
"""
from __future__ import annotations

import os
import re
import shutil
import socket
import struct
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .models import ScanStatus

_FOUND_RE = re.compile(r":\s+(.+?)\s+FOUND")

# clamd labels a FILDES reply with its own descriptor number ("fd[10]: OK"),
# not a path. Swapped for the real path so stored results and reports read
# the same whichever way a file was scanned.
_FD_LABEL_RE = re.compile(r"^fd\[\d+\]:")

# clamd's wording for "file too large to scan" is inconsistent across
# versions -- some report it plainly, others substitute the misleading
# "Can't allocate memory" for the exact same underlying condition
# (a known, longstanding clamd quirk, not an actual OOM).
_SIZE_LIMIT_MARKERS = ("size limit exceeded", "size limit reached", "can't allocate memory")


def is_size_limit_error(raw: str) -> bool:
    """True if a clamd response indicates a size-limit rejection, not a
    genuine scan failure -- these call for a different remedy (raise the
    limit, or fall back to the clamscan CLI) than a real error does."""
    text = raw.lower()
    return any(marker in text for marker in _SIZE_LIMIT_MARKERS)


_PERMISSION_MARKERS = ("access denied", "permission denied")


def is_permission_error(raw: str) -> bool:
    """True if a clamd response indicates it couldn't read the file due
    to permissions -- as opposed to a size limit or a genuine scan
    failure. Used to distinguish "clamd was refused" from "clamd tried
    and something went wrong."""
    text = raw.lower()
    return any(marker in text for marker in _PERMISSION_MARKERS)


def clamscan_cli_available() -> bool:
    return shutil.which("clamscan") is not None


def scan_with_clamscan_cli(filepath: Path | str, timeout: float = 180.0) -> "ScanOutcome":
    """Fall back to the clamscan CLI for one file, bypassing clamd's
    configured MaxFileSize/MaxScanSize entirely via explicit overrides.

    Only meant for files the daemon has already rejected as too large.
    Each invocation loads the whole signature database fresh -- seconds,
    not milliseconds -- so this is not something to run routinely.
    """
    try:
        result = subprocess.run(
            ["clamscan", "--no-summary", "--infected",
             "--max-filesize=0", "--max-scansize=0", str(filepath)],
            capture_output=True, text=True, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return ScanOutcome(ScanStatus.ERROR, f"clamscan CLI fallback failed: {exc}")

    output = result.stdout.strip()
    if result.returncode == 0:
        return ScanOutcome(ScanStatus.CLEAN, output or "OK (clamscan CLI fallback)")
    if result.returncode == 1:
        match = _FOUND_RE.search(output)
        threat = match.group(1) if match else "Unknown"
        return ScanOutcome(ScanStatus.INFECTED, output, threat)
    return ScanOutcome(ScanStatus.ERROR, output or f"clamscan CLI exited {result.returncode}")


@dataclass(frozen=True)
class ScanOutcome:
    status: ScanStatus
    raw: str
    threat_name: str | None = None


class ClamdClient:
    def __init__(self, socket_path: str, timeout: float = 300.0):
        self.socket_path = socket_path
        self.timeout = timeout

    def _command(self, command: str) -> str:
        """Send one command and read the full reply.

        clamd terminates replies with a newline; a single recv(4096)
        can truncate long responses, so read until the terminator.
        """
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            sock.connect(self.socket_path)
            sock.sendall(f"n{command}\n".encode())
            chunks: list[bytes] = []
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
                if data.endswith(b"\n"):
                    break
        return b"".join(chunks).decode().strip()

    def ping(self) -> bool:
        """True if clamd is up and answering on the socket."""
        try:
            return self._command("PING") == "PONG"
        except OSError:
            return False

    def max_threads(self) -> int | None:
        """clamd's own MaxThreads limit, read from its STATS output.

        Sending more concurrent scans than this just queues inside the
        daemon (and overflows MaxQueue under sustained load), so it is
        the true ceiling for useful worker-pool size.
        """
        try:
            stats = self._command("STATS")
        except OSError:
            return None
        match = re.search(r"THREADS:.*?\bmax\s+(\d+)", stats)
        return int(match.group(1)) if match else None

    def signature_version(self) -> int | None:
        """The loaded signature database's version number, via VERSION.

        The middle field of "ClamAV <engine>/<sig-version>/<build date>"
        (e.g. 27455). It rises with each database release, so comparing two
        of them says how many releases apart two scans were. None if clamd
        is unreachable or the response doesn't parse -- "unknown", not 0.
        """
        try:
            version = self._command("VERSION")
        except OSError:
            return None
        parts = version.split("/")
        if len(parts) < 3:
            return None
        try:
            return int(parts[-2])
        except ValueError:
            return None

    def signature_age_days(self) -> int | None:
        """Days since the loaded signature database was built, via VERSION.

        Response format: "ClamAV <engine>/<sig-version>/<build date>",
        e.g. "ClamAV 1.2.0/27455/Wed Jan 15 08:12:00 2026". Returns None
        if clamd is unreachable or the response doesn't parse -- callers
        should treat that as "unknown," not "stale."
        """
        try:
            version = self._command("VERSION")
        except OSError:
            return None
        parts = version.split("/")
        if len(parts) < 3:
            return None
        date_str = parts[-1].strip()
        try:
            built = datetime.strptime(date_str, "%a %b %d %H:%M:%S %Y")
        except ValueError:
            return None
        return (datetime.now() - built).days

    # -- what the daemon can do, and who it runs as --------------------

    def commands(self) -> set[str] | None:
        """The commands this clamd recognizes, via VERSIONCOMMANDS.

        Reply format: "ClamAV 1.5.4/27455/<date>| COMMANDS: SCAN QUIT ...".
        None if clamd is unreachable or the reply has no COMMANDS list.
        A listed command can still be switched off in clamd.conf; scan_fd()
        reports that case as an ERROR outcome rather than hiding it.
        """
        try:
            reply = self._command("VERSIONCOMMANDS")
        except OSError:
            return None
        _, sep, listed = reply.partition("COMMANDS:")
        return set(listed.split()) if sep else None

    def supports_fildes(self) -> bool:
        cmds = self.commands()
        return cmds is not None and "FILDES" in cmds

    def daemon_uid(self) -> int | None:
        """Effective UID clamd is running as right now, or None if unknown.

        Asks the kernel who is on the other end of the socket (SO_PEERCRED)
        and then reads that process's *current* UID from /proc. The /proc
        step matters: SO_PEERCRED reports credentials from when the socket
        was set up, and a clamd that starts as root and then drops to
        `User clamav` would still look like root from SO_PEERCRED alone.

        When systemd socket activation owns the socket, the peer is PID 1
        (systemd itself), so the clamd process is looked up by name instead.
        None means "couldn't tell" (no /proc access, e.g. mounted with
        hidepid), which callers must not read as "safe" or "root".
        """
        pid = None
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect(self.socket_path)
                raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                      struct.calcsize("3i"))
                pid, _uid, _gid = struct.unpack("3i", raw)
        except OSError:
            return None
        if pid and pid > 1:
            uid = _effective_uid(pid)
            if uid is not None:
                return uid
        # Socket activation (pid 1) or an unreadable peer: find clamd by name.
        uids = [u for u in (_effective_uid(p) for p in _pids_named("clamd")) if u is not None]
        if not uids:
            return None
        return 0 if 0 in uids else uids[0]

    # -- scanning ------------------------------------------------------

    def scan(self, filepath: Path | str) -> ScanOutcome:
        """Scan one file via clamd's SCAN command (path mode).

        clamd opens the path itself, so this only works for files the
        `clamav` user can read. Used only when clamd doesn't support
        FILDES; scan_fd() is the normal path.
        """
        try:
            response = self._command(f"SCAN {filepath}")
        except OSError as exc:
            return ScanOutcome(ScanStatus.ERROR, f"Scan error: {exc}")
        return _outcome(response)

    def scan_fd(self, fd: int, label: str) -> ScanOutcome:
        """Scan an already-open file by passing its descriptor (FILDES).

        `fd` must be a read-only descriptor for a regular file, opened by
        the caller (fsutil.open_for_scan does both checks). The command
        and the descriptor go in two sends, the way clamd's own clients do
        it: "zFILDES\\0", then one dummy byte carrying the fd as SCM_RIGHTS
        ancillary data. The kernel gives clamd its own copy of the
        descriptor; the caller still owns and closes `fd`.

        clamd never replies if the descriptor doesn't arrive -- it just
        waits -- so the socket timeout is what ends a stuck request.
        `label` (normally the path) replaces clamd's "fd[N]" in the reply.
        """
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect(self.socket_path)
                sock.sendall(b"zFILDES\0")
                socket.send_fds(sock, [b"\0"], [fd])
                chunks: list[bytes] = []
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    chunks.append(data)
                    if data.endswith(b"\0"):
                        break
        except OSError as exc:
            return ScanOutcome(ScanStatus.ERROR, f"{label}: Scan error (fd passing): {exc} ERROR")
        response = b"".join(chunks).rstrip(b"\0").decode(errors="replace").strip()
        if not response:
            return ScanOutcome(ScanStatus.ERROR, f"{label}: no reply from clamd ERROR")
        # A function, not a replacement string: re.sub reads backslashes in
        # a replacement string as escapes, so a file named "a\1b" would
        # raise and stop the whole scan.
        return _outcome(_FD_LABEL_RE.sub(lambda _m: f"{label}:", response, count=1))


def _outcome(response: str) -> ScanOutcome:
    """Turn one clamd scan reply into a ScanOutcome."""
    if response.endswith("OK"):
        return ScanOutcome(ScanStatus.CLEAN, response)
    if "FOUND" in response:
        match = _FOUND_RE.search(response)
        threat = match.group(1) if match else "Unknown"
        return ScanOutcome(ScanStatus.INFECTED, response, threat)
    return ScanOutcome(ScanStatus.ERROR, response)


def _effective_uid(pid: int) -> int | None:
    """A process's effective UID from /proc/<pid>/status ("Uid:" line:
    real, effective, saved, filesystem). None if it can't be read."""
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("Uid:"):
                    return int(line.split()[2])
    except (OSError, ValueError, IndexError):
        return None
    return None


def _pids_named(name: str) -> list[int]:
    """PIDs whose /proc/<pid>/comm is exactly `name`."""
    pids = []
    try:
        entries = os.listdir("/proc")
    except OSError:
        return pids
    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/comm") as f:
                if f.read().strip() == name:
                    pids.append(int(entry))
        except OSError:
            continue
    return pids
