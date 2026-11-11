"""Filesystem helpers: safe stat, special-file detection, hashing.

Everything here is a small pure-ish function that takes a path and
returns a value or None. No database, no printing (logging only).
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import stat as statmod
from pathlib import Path

from rich.markup import escape

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


# Control characters: C0 (0x00-0x1F), DEL, and C1 (0x80-0x9F). Terminals act
# on these instead of displaying them -- ESC (0x1B) starts sequences that
# clear the screen, move the cursor, recolour or hide text, set the window
# title or plant a clickable link -- so a filename containing them could
# rewrite or disguise Ensign's own output, including its verdict on that
# very file ("terminal escape injection").
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_NAMED_CONTROLS = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}


def printable(text: object) -> str:
    """Text from the filesystem made safe to show anywhere: every control
    character written out as a visible escape (\\n, \\t, \\x1b, ...), and
    bytes that aren't valid UTF-8 as \\xNN ("caf\\xe9.txt", not
    "caf\ufffd.txt"), so the file can still be found from the output.

    Used for the terminal (through shown()), the log file and desktop
    notifications. Ordinary names are returned unchanged.
    """
    text = str(text)
    try:
        text = text.encode("utf-8", "surrogateescape").decode("utf-8", "backslashreplace")
    except UnicodeEncodeError:
        pass  # a stray surrogate that didn't come from a filename: leave it
    return _CONTROL_CHARS.sub(
        lambda m: _NAMED_CONTROLS.get(m.group(), f"\\x{ord(m.group()):02x}"), text)


def human_size(n: int) -> str:
    """Bytes as "68 B", "4.1 KiB", "2.0 GiB"."""
    size = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"


def shown(text: object) -> str:
    """Make a string from the filesystem safe to print through rich.

    Paths and file names are chosen by whoever created the file, and rich
    reads "[...]" in printed text as markup: a directory named "a[" holding
    one named "b]" gives a path containing "[/b]", which makes rich raise
    and stop the report, and a file named "x[black on black]" hides the
    rest of its own line -- including the verdict. Newlines are shown as
    "\\n" so a name can't start a fake line of output, and every other
    control character is written out too (see printable()).
    """
    return escape(printable(text))


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
