"""Error logging for Ensign: one log file per run, repeats collapsed, old files pruned.

Why not one ever-growing file: a scheduled service runs Ensign many times,
and the same persistent problem (say, a directory it may not read) recurs on
every run. One file per run keeps each run's errors together, and lets old
runs be deleted by age or total size without touching the current one.

Within a run, the first few occurrences of each distinct error are logged in
full; after that they are only counted, and a one-line total per error is
written when the run ends. That is what stops a single repeating condition
(Ensign once logged 302,289 "stat failed" lines for broken symlinks) from
filling the disk.

Files are created lazily: a run with no errors leaves no file behind.
"""
from __future__ import annotations

import atexit
import logging
import threading
import time
from datetime import datetime
from pathlib import Path

from .config import Config
from .fsutil import printable

REPEAT_LIMIT = 20          # full log lines kept per distinct error, per run
LOG_GLOB = "ensign-*.log"  # only files matching this are ever pruned
_FORMAT = "\n    %(asctime)s - %(name)s - %(message)s"

_summary_log = logging.getLogger(__name__)


def _key(record: logging.LogRecord) -> tuple:
    """What counts as "the same error": same logger, level and message
    template, and the same exception type/errno among the arguments.

    The template alone would merge unrelated failures that happen to share
    a format string such as "%s: %s"; adding the exception type keeps a
    PermissionError and a database error apart.
    """
    parts: list = [record.name, record.levelno, str(record.msg)]
    args = record.args if isinstance(record.args, tuple) else ()
    for arg in args:
        if isinstance(arg, BaseException):
            parts.append(f"{type(arg).__name__}:{getattr(arg, 'errno', None)}")
    if record.exc_info and record.exc_info[0] is not None:
        parts.append(record.exc_info[0].__name__)
    return tuple(parts)


class RepeatFilter(logging.Filter):
    """Pass the first `limit` records of each distinct error, count the rest."""

    def __init__(self, limit: int = REPEAT_LIMIT):
        super().__init__()
        self.limit = limit
        self._lock = threading.Lock()
        self._seen: dict[tuple, list] = {}   # key -> [count, label]

    def filter(self, record: logging.LogRecord) -> bool:
        if getattr(record, "ensign_summary", False):
            return True
        key = _key(record)
        with self._lock:
            entry = self._seen.get(key)
            if entry is None:
                label = str(record.msg) + "".join(f" [{p}]" for p in key[3:])
                entry = self._seen[key] = [0, label]
            entry[0] += 1
            return entry[0] <= self.limit

    def suppressed(self) -> list[tuple[str, int]]:
        with self._lock:
            return [(label, n - self.limit) for n, label in self._seen.values() if n > self.limit]


def prune(log_dir: Path, keep_days: int, max_total_mb: int,
          protect: Path | None = None, now: float | None = None) -> list[Path]:
    """Delete old run logs: anything older than `keep_days`, then oldest-first
    until the total is under `max_total_mb`. 0 disables either rule. Only files
    named ensign-*.log are touched, and never `protect` (the current run's)."""
    now = time.time() if now is None else now
    try:
        files = sorted((p for p in log_dir.glob(LOG_GLOB) if p.is_file()),
                       key=lambda p: p.stat().st_mtime)
    except OSError:
        return []
    removed: list[Path] = []

    def drop(path: Path) -> None:
        try:
            path.unlink()
            removed.append(path)
        except OSError:
            pass

    if keep_days > 0:
        cutoff = now - keep_days * 86400
        for path in list(files):
            if path != protect and path.stat().st_mtime < cutoff:
                drop(path)
        files = [p for p in files if p not in removed]
    if max_total_mb > 0:
        cap = max_total_mb * 1024 * 1024
        total = sum(p.stat().st_size for p in files)
        for path in files:          # oldest first
            if total <= cap:
                break
            if path == protect:
                continue
            size = path.stat().st_size
            drop(path)
            total -= size
    return removed


_handler: logging.FileHandler | None = None
_filter: RepeatFilter | None = None
_prev_level: int | None = None
_atexit_registered = False


class _EscapingFormatter(logging.Formatter):
    """Writes each message with control characters escaped (fsutil.printable).

    A filename containing a newline would otherwise start what looks like a
    new, separate log line -- a forged entry -- and one containing terminal
    escapes would act on whoever later reads the log with cat or less.
    Tracebacks are left as they are: Python writes those, not a filename.
    """
    def formatMessage(self, record: logging.LogRecord) -> str:
        record.message = printable(record.message)
        return super().formatMessage(record)


def setup(config: Config, now: datetime | None = None) -> Path:
    """Start logging this run's errors to a new file under <data_dir>/logs/.
    Returns the path the file will have (it is not created until the first error)."""
    global _handler, _filter, _prev_level, _atexit_registered
    shutdown()  # a second call replaces the first rather than doubling up
    log_dir = config.log_dir
    log_dir.mkdir(parents=True, exist_ok=True)
    now = now or datetime.now()
    path = log_dir / f"ensign-{now:%Y%m%d-%H%M%S}.log"
    prune(log_dir, config.log_keep_days, config.log_max_total_mb, protect=path)

    # backslashreplace: a filename that isn't valid UTF-8 is logged as
    # \xNN instead of making the handler fail ("--- Logging error ---")
    # and lose the very line that says what went wrong.
    _handler = logging.FileHandler(path, delay=True, encoding="utf-8", errors="backslashreplace")
    _handler.setFormatter(_EscapingFormatter(_FORMAT))
    _filter = RepeatFilter()
    _handler.addFilter(_filter)
    root = logging.getLogger()
    _prev_level = root.level
    root.setLevel(logging.ERROR)
    root.addHandler(_handler)
    if not _atexit_registered:
        atexit.register(shutdown)
        _atexit_registered = True
    return path


def shutdown() -> None:
    """Write the suppressed-repeats summary, then detach and close the file."""
    global _handler, _filter, _prev_level
    if _handler is None:
        return
    if _filter is not None:
        for label, count in _filter.suppressed():
            _summary_log.error("suppressed %d more of: %s", count, label,
                               extra={"ensign_summary": True})
    root = logging.getLogger()
    root.removeHandler(_handler)
    _handler.close()
    if _prev_level is not None:
        root.setLevel(_prev_level)
    _handler = _filter = _prev_level = None
