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

# clamd labels a FILDES reply with its own descriptor number ("fd[10]: OK"),
# not a path. Swapped for the real path so stored results and reports read
# the same whichever way a file was scanned.
_FD_LABEL_RE = re.compile(r"^fd\[\d+\]: ")

# clamscan's and clamd's name for "this file went past a scan limit, so it
# was not (fully) scanned" when AlertExceedsMax / --alert-exceeds-max is on:
# Heuristics.Limits.Exceeded.MaxFileSize, .MaxScanSize, .MaxRecursion, ...
# Reported as FOUND, but it is not an infection.
LIMITS_EXCEEDED_PREFIX = "Heuristics.Limits.Exceeded"

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


# --- clamd's size limits ------------------------------------------------------
#
# A file larger than clamd's MaxFileSize, or with more data than MaxScanSize,
# is not scanned -- and clamd still answers "OK" for it, unless the admin set
# AlertExceedsMax. So Ensign reads the limits from clamd's config and sends
# larger files to clamscan instead, with the limits switched off.
#
# ClamAV itself can't scan a file past about 2 GiB, whatever the settings:
# its code still uses 32-bit sizes in places (ClamAV's developers, on the
# clamav-users list, 2023). Measured on ClamAV 1.5.4: 2,147,483,645 bytes is
# the largest file scanned, one byte more is refused. Such files can't be
# checked by any ClamAV tool; clamscan reports them as
# Heuristics.Limits.Exceeded.MaxFileSize, and Ensign records them as
# "incomplete" -- never as clean.

# ClamAV's defaults since 1.0 (older releases used 25M and 100M). Used when
# clamd's config can't be found or read, and for any setting it leaves out.
DEFAULT_MAX_FILE_SIZE = 100 * 2**20
DEFAULT_MAX_SCAN_SIZE = 400 * 2**20
# The largest value ClamAV documents for MaxFileSize ("up to 2000MB").
# Anything bigger always goes to clamscan, which gives the real answer --
# so if a future ClamAV raises its ceiling, those files simply get scanned.
CLAMAV_MAX_SETTING = 2000 * 2**20

# Where distributions put clamd's config, for when clamd's command line
# doesn't say (Arch, Debian/Ubuntu: clamd.conf; Fedora: clamd.d/scan.conf).
_CONFIG_CANDIDATES = ("/etc/clamav/clamd.conf", "/etc/clamd.d/scan.conf", "/etc/clamd.conf")
_SIZE_RE = re.compile(r"^(\d+)([kKmMgG]?)$")
_SIZE_UNITS = {"": 1, "k": 2**10, "m": 2**20, "g": 2**30}
_CLAMSCAN_LINE_RE = re.compile(r"^/proc/self/fd/(\d+): (.*)$")


@dataclass(frozen=True)
class ClamdLimits:
    max_file_size: int           # bytes; 0 = no limit set (ClamAV's own ceiling still applies)
    max_scan_size: int           # bytes; 0 = no limit set
    database_dir: str | None     # clamd's DatabaseDirectory, so clamscan uses the same signatures
    alert_exceeds_max: bool
    source: str                  # the config file read, or why the defaults are in use

    @property
    def scan_limit(self) -> int:
        """Files of this size or larger go to clamscan instead of clamd."""
        limits = [n for n in (self.max_file_size, self.max_scan_size) if n > 0]
        return min(limits + [CLAMAV_MAX_SETTING])


def _parse_size(text: str) -> int | None:
    match = _SIZE_RE.match(text.strip().strip('"'))
    if not match:
        return None
    return int(match.group(1)) * _SIZE_UNITS[match.group(2).lower()]


def parse_clamd_config(text: str, source: str) -> ClamdLimits:
    """The settings Ensign needs from clamd.conf text. Lines are
    "Option value"; "#" starts a comment; the last occurrence wins."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        key, _, value = line.partition(" ")
        values[key.lower()] = value.strip()

    def size(key: str, default: int) -> int:
        parsed = _parse_size(values.get(key.lower(), ""))
        return default if parsed is None else parsed

    return ClamdLimits(
        max_file_size=size("MaxFileSize", DEFAULT_MAX_FILE_SIZE),
        max_scan_size=size("MaxScanSize", DEFAULT_MAX_SCAN_SIZE),
        database_dir=values.get("databasedirectory", "").strip('"') or None,
        alert_exceeds_max=values.get("alertexceedsmax", "").lower() in ("yes", "true", "1"),
        source=source,
    )


DEFAULT_LIMITS = ClamdLimits(DEFAULT_MAX_FILE_SIZE, DEFAULT_MAX_SCAN_SIZE, None, False, "ClamAV defaults")


def _config_from_cmdline(pid: int) -> str | None:
    """The -c/--config-file path from a clamd process's command line."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            args = [os.fsdecode(a) for a in f.read().split(b"\0") if a]
    except OSError:
        return None
    for i, arg in enumerate(args):
        if arg in ("-c", "--config-file") and i + 1 < len(args):
            return args[i + 1]
        if arg.startswith("--config-file="):
            return arg.split("=", 1)[1]
    return None


def read_clamd_limits(pids: list[int] | None = None) -> ClamdLimits:
    """clamd's limits, from the config the running clamd was started with
    (its command line), else the distribution's usual path, else ClamAV's
    defaults. Never raises: unknown limits mean the defaults, which can only
    send more files to clamscan, not fewer -- unless clamd was given higher
    limits in a config Ensign can't see; then clamd scans those files itself."""
    paths = [p for p in (_config_from_cmdline(pid) for pid in (pids or [])) if p]
    paths += [p for p in _CONFIG_CANDIDATES if p not in paths]
    for path in paths:
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                return parse_clamd_config(f.read(), path)
        except FileNotFoundError:
            continue
        except OSError as exc:
            return ClamdLimits(DEFAULT_MAX_FILE_SIZE, DEFAULT_MAX_SCAN_SIZE, None, False,
                               f"ClamAV defaults ({path}: {exc.strerror})")
    return ClamdLimits(DEFAULT_MAX_FILE_SIZE, DEFAULT_MAX_SCAN_SIZE, None, False,
                       "ClamAV defaults (no clamd config found)")


# --- memory, for deciding how many clamscans can run at once ----------------

def memory_available() -> tuple[int, int] | None:
    """(MemAvailable, MemTotal) in bytes, from /proc/meminfo. MemAvailable is
    the kernel's own estimate of what can be used without swapping. None if
    it can't be read."""
    values = {}
    try:
        with open("/proc/meminfo", encoding="ascii", errors="replace") as f:
            for line in f:
                key, _, rest = line.partition(":")
                if key in ("MemAvailable", "MemTotal"):
                    values[key] = int(rest.split()[0]) * 1024  # reported in kB
    except (OSError, ValueError, IndexError):
        return None
    if len(values) < 2:
        return None
    return values["MemAvailable"], values["MemTotal"]


def process_memory(pid: int) -> int | None:
    """A process's resident memory (VmRSS) in bytes, or None."""
    try:
        with open(f"/proc/{pid}/status", encoding="ascii", errors="replace") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return None


# --- clamscan, for what clamd won't scan --------------------------------------

def clamscan_user() -> tuple[int, int] | None:
    """(uid, gid) to run clamscan as. As root, the 'clamav' user, for the
    same reason Ensign refuses a root clamd: clamscan parses untrusted
    files. Otherwise None (run as yourself; nothing to drop). Raises
    LookupError if Ensign runs as root and there is no 'clamav' user."""
    if os.geteuid() != 0:
        return None
    import pwd
    try:
        entry = pwd.getpwnam("clamav")
    except KeyError:
        raise LookupError("no 'clamav' user to run clamscan as") from None
    return entry.pw_uid, entry.pw_gid


def scan_fds_with_clamscan(
    fds: list[int], limits: ClamdLimits, timeout: float, run_as: tuple[int, int] | None = None
) -> dict[int, "ScanOutcome"]:
    """Scan already-open files with one clamscan run, limits switched off.

    The descriptors are inherited by clamscan and named to it as
    /proc/self/fd/N -- inside clamscan, that is the very file Ensign opened.
    So, like FILDES: no file is reopened by path (it can't be swapped in
    between, and clamscan needs no permission on it), and clamscan's output
    names each file by its fd number, never by a filename someone chose.

    One run for many files, because each run loads the whole signature
    database (seconds, and up to a GB or two of memory, on top of clamd's
    copy). `run_as` drops clamscan to that (uid, gid) -- see clamscan_user().

    Returns an outcome per fd; "raw" is clamscan's line(s) for that file.
    """
    argv = ["clamscan", "--no-summary", "--stdout",
            "--max-filesize=0", "--max-scansize=0", "--alert-exceeds-max"]
    if limits.database_dir:
        argv.append(f"--database={limits.database_dir}")
    argv += [f"/proc/self/fd/{fd}" for fd in fds]
    kwargs = {}
    if run_as is not None:
        kwargs = {"user": run_as[0], "group": run_as[1], "extra_groups": []}
    try:
        result = subprocess.run(argv, pass_fds=fds, capture_output=True, text=True,
                                timeout=timeout, errors="replace", **kwargs)
    except (OSError, subprocess.SubprocessError) as exc:
        return {fd: ScanOutcome(ScanStatus.ERROR, f"clamscan: couldn't run: {exc}") for fd in fds}

    lines: dict[int, list[str]] = {fd: [] for fd in fds}
    for line in result.stdout.splitlines():
        match = _CLAMSCAN_LINE_RE.match(line)
        if match and int(match.group(1)) in lines:
            lines[int(match.group(1))].append(match.group(2).strip())

    outcomes = {}
    for fd in fds:
        said = lines[fd]
        raw = "clamscan: " + (" / ".join(said) if said else "no result")
        found = [s[: -len(" FOUND")].strip() for s in said if s.endswith(" FOUND")]
        threats = [t for t in found if not t.startswith(LIMITS_EXCEEDED_PREFIX)]
        if threats:
            outcomes[fd] = ScanOutcome(ScanStatus.INFECTED, raw, threats[0])
        elif found:  # only a limits alert: ClamAV didn't (fully) scan it
            outcomes[fd] = ScanOutcome(ScanStatus.INCOMPLETE, raw, found[0])
        elif said and said[-1] == "OK":
            outcomes[fd] = ScanOutcome(ScanStatus.CLEAN, raw)
        else:
            errors = result.stderr.strip().splitlines()
            detail = said[-1] if said else (errors[-1] if errors else "no output")
            outcomes[fd] = ScanOutcome(ScanStatus.ERROR, f"clamscan: {detail}")
    return outcomes


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
            # surrogateescape: a path that isn't valid UTF-8 goes to clamd as
            # its original bytes (a plain .encode() would raise on it).
            sock.sendall(f"n{command}\n".encode("utf-8", "surrogateescape"))
            chunks: list[bytes] = []
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
                if data.endswith(b"\n"):
                    break
        # clamd's reply repeats the path; decode it the same way.
        return b"".join(chunks).decode("utf-8", "surrogateescape").strip()

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

    def limits(self) -> ClamdLimits:
        """clamd's MaxFileSize/MaxScanSize and signature directory, read from
        the config file the running clamd was started with. See
        read_clamd_limits(): never raises, falls back to ClamAV's defaults."""
        return read_clamd_limits(_pids_named("clamd"))

    def memory_in_use(self) -> int | None:
        """How much memory clamd holds, in bytes -- nearly all of it its loaded
        signatures, so about what each clamscan run will need too."""
        sizes = [m for m in (process_memory(pid) for pid in _pids_named("clamd")) if m]
        return max(sizes) if sizes else None

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
        prefix = f"{filepath}: "
        verdict = response[len(prefix):] if response.startswith(prefix) else response
        return _outcome(response, verdict)

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
        # The verdict is read from clamd's own "fd[N]: ..." reply, before the
        # path goes in: the path is chosen by whoever named the file.
        match = _FD_LABEL_RE.match(response)
        verdict = response[match.end():] if match else response
        return _outcome(f"{label}: {verdict}" if match else response, verdict)


def _outcome(response: str, verdict: str) -> ScanOutcome:
    """Turn one clamd scan reply into a ScanOutcome.

    `response` is the whole reply, stored as the scan result. `verdict` is
    that reply with the file's label taken off the front ("OK",
    "Win.Test.EICAR_HDB-1 FOUND", "Access denied. ERROR"), and is the only
    part read: the label is the filename, and a file can be named
    "x: PUA.Harmless FOUND y.exe" to pass off a real detection as a
    harmless one, or named "FOUND.txt" to turn an error into an infection.
    clamd's own words always come last, so they are read from the end.
    """
    verdict = verdict.strip()
    if verdict == "OK":
        return ScanOutcome(ScanStatus.CLEAN, response)
    if verdict.endswith(" FOUND"):
        threat = verdict[: -len(" FOUND")].strip() or "Unknown"
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
