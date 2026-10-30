"""Minimal clamd unix-socket client, plus a clamscan CLI fallback."""
from __future__ import annotations

import re
import shutil
import socket
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .models import ScanStatus

_FOUND_RE = re.compile(r":\s+(.+?)\s+FOUND")

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

    def scan(self, filepath: Path | str) -> ScanOutcome:
        """Scan one file via clamd's SCAN command.

        clamd reads the file itself, so it needs read permission on the
        path (see the ACL notes in the README).
        """
        try:
            response = self._command(f"SCAN {filepath}")
        except OSError as exc:
            return ScanOutcome(ScanStatus.ERROR, f"Scan error: {exc}")

        if response.endswith("OK"):
            return ScanOutcome(ScanStatus.CLEAN, response)
        if "FOUND" in response:
            match = _FOUND_RE.search(response)
            threat = match.group(1) if match else "Unknown"
            return ScanOutcome(ScanStatus.INFECTED, response, threat)
        return ScanOutcome(ScanStatus.ERROR, response)
