"""Single-run lock: only one Ensign that writes to the database at a time.

Why it matters: a scheduled service and a manual run can overlap (systemd
won't start a second copy of the same service, but it knows nothing about a
copy you launched yourself). Two scans at once would hash and scan the same
files twice and compete for the SQLite write lock.

Mechanism: flock(2) on a small file in the data directory. The kernel drops
the lock the moment the holding process exits for any reason -- crash,
kill -9, power loss -- so there is no stale lock to clean up and no PID
check to get wrong. The pid written inside is informational only, for the
"already running" message; the lock itself is the flock.

The lock file is deliberately never deleted. If a finishing run removed it
while another run was opening it, the two could end up locking different
files (one on the deleted inode, one on a freshly created file) and both
proceed.
"""
from __future__ import annotations

import fcntl
import os
from pathlib import Path


class AlreadyRunning(Exception):
    """Another Ensign holds the lock. holder_pid is None if it can't be read."""

    def __init__(self, path: Path, holder_pid: int | None):
        super().__init__(f"{path} is locked by pid {holder_pid}")
        self.path = path
        self.holder_pid = holder_pid


class RunLock:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self._fd: int | None = None

    def acquire(self) -> None:
        """Take the lock without waiting. Raises AlreadyRunning if it's held."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
            writable = True
        except PermissionError:
            # e.g. the file was created by an earlier `sudo` run and is
            # root-owned. flock works on a read-only descriptor, so the
            # lock still holds; we just can't record our pid in it.
            fd = os.open(self.path, os.O_RDONLY)
            writable = False
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            holder = self._read_pid(fd)
            os.close(fd)
            raise AlreadyRunning(self.path, holder) from None
        except BaseException:
            os.close(fd)
            raise
        if writable:
            os.ftruncate(fd, 0)
            os.write(fd, f"{os.getpid()}\n".encode())
        self._fd = fd

    def release(self) -> None:
        """Drop the lock (closing the descriptor releases the flock)."""
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    @staticmethod
    def _read_pid(fd: int) -> int | None:
        try:
            return int(os.pread(fd, 32, 0).split()[0])
        except (OSError, ValueError, IndexError):
            return None
