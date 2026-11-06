"""Filesystem helpers: safe stat, special-file detection, hashing.

Everything here is a small pure-ish function that takes a path and
returns a value or None. No database, no printing (logging only).
"""
from __future__ import annotations

import hashlib
import logging
import os
import stat as statmod
from pathlib import Path

log = logging.getLogger(__name__)

CHUNK_SIZE = 1024 * 1024  # 1 MiB reads; 8 KiB was syscall-heavy on big files


def safe_lstat(path: Path) -> os.stat_result | None:
    """lstat that returns None instead of raising.

    Does NOT follow symlinks -- used for directory-mtime tracking
    (snapshot pruning), where following a symlinked directory would
    risk walking outside the intended tree or looping.
    """
    try:
        return os.lstat(path)
    except OSError as exc:
        log.error("stat failed for %s: %s", path, exc)
        return None


def safe_stat(path: Path) -> os.stat_result | None:
    """stat that returns None instead of raising.

    Follows symlinks (unlike safe_lstat), so a symlink to a regular
    file is scanned through to its target -- the target's content is
    what matters for security scanning, not the symlink itself. stat()
    only reads metadata; it never opens or reads the target, so a
    symlink to a socket or FIFO can't hang here the way a read() would.
    A broken symlink or a loop just becomes None, same as any other
    stat failure. Used for file-level checks; directory traversal still
    uses safe_lstat + os.walk(followlinks=False) and never descends
    into symlinked directories.
    """
    try:
        return os.stat(path)
    except OSError as exc:
        log.error("stat failed for %s: %s", path, exc)
        return None


def stat_or_error(path: Path) -> tuple[os.stat_result | None, OSError | None]:
    """Like safe_stat, but returns the failure instead of logging it, so
    the caller can tell "the file is gone / the symlink is broken"
    (FileNotFoundError) from a real refusal like PermissionError. Follows
    symlinks, same as safe_stat. The caller decides what to log."""
    try:
        return os.stat(path), None
    except OSError as exc:
        return None, exc


def is_scannable(st: os.stat_result) -> bool:
    """True only for regular, non-empty files.

    Expects a safe_stat() result (symlinks already resolved to their
    target) for file candidates. Sockets, pipes, and block/char devices
    hang forever on read; a symlink to one of those still resolves via
    stat() to the target's real type here, so it's correctly excluded
    too -- only the read of a socket/FIFO/device hangs, not the stat.
    One S_ISREG check replaces the four individual
    S_ISSOCK/S_ISFIFO/S_ISBLK/S_ISCHR checks.
    """
    return statmod.S_ISREG(st.st_mode) and st.st_size > 0


class NotScannable(OSError):
    """open_for_scan() opened something that isn't a regular, non-empty
    file -- the path changed between the walk's stat() and the open."""


# O_RDONLY  -- the descriptor clamd receives can only read, never write.
# O_CLOEXEC -- not inherited by anything Ensign runs (clamscan, pacman, ...).
# O_NONBLOCK -- stat() said "regular file", but if the path is swapped for a
#               FIFO before open(), a blocking open() would hang a worker
#               forever waiting for a writer. Non-blocking returns at once,
#               and the fstat() check below rejects it. (It has no effect
#               on reads from a regular file.)
# O_NOCTTY  -- a swapped-in terminal device can't become a controlling tty.
# Not O_NOFOLLOW: symlinks to files are followed on purpose (see scanner.py).
# The fstat() check applies to whatever the link resolved to.
_SCAN_OPEN_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOCTTY


def open_for_scan(path: Path) -> tuple[int, os.stat_result]:
    """Open `path` read-only for hashing and scanning, as the invoking user.

    Returns (fd, fstat result). The caller owns the descriptor and must
    close it. Raises OSError if it can't be opened (permission denied,
    vanished, ...), or NotScannable if what got opened isn't a regular,
    non-empty file.

    Hashing and scanning through this one descriptor means the hash
    recorded and the verdict recorded are for the same file. With
    separate opens by path, the file could be replaced in between and the
    database would pair one file's hash with another file's verdict.
    """
    fd = os.open(path, _SCAN_OPEN_FLAGS)
    try:
        st = os.fstat(fd)
        if not is_scannable(st):
            raise NotScannable(f"{path}: not a regular, non-empty file when opened")
    except BaseException:
        os.close(fd)
        raise
    return fd, st


def sha256_fd(fd: int) -> str:
    """SHA-256 hex digest of an open file, read from the start.

    Uses pread (an explicit offset), so it never moves the descriptor's
    shared position, and raises OSError on a read failure.
    """
    hasher = hashlib.sha256()
    offset = 0
    while True:
        chunk = os.pread(fd, CHUNK_SIZE, offset)
        if not chunk:
            break
        hasher.update(chunk)
        offset += len(chunk)
    return hasher.hexdigest()


def sha256_file(path: Path) -> str | None:
    """SHA-256 hex digest of a file, or None on read failure.

    open() follows symlinks by default, so this works unchanged for a
    symlink path that safe_stat() already confirmed points at a
    regular, non-empty file.
    """
    hasher = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
                hasher.update(chunk)
    except OSError as exc:
        log.error("read failed for %s: %s", path, exc)
        return None
    return hasher.hexdigest()
