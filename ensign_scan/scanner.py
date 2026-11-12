"""
    Core scanning pipeline.

    The pipeline for a tree is a single pass:

        walk -> prune unchanged snapshot subtrees -> stat each file
            -> skip files whose (size, mtime, ctime) match the DB
            -> for the rest, in a thread pool:
                 credential file? -> record as CLASSIFIED, never opened
                 otherwise        -> open once as the user -> hash it
                                     -> pass that same descriptor to clamd
                                     -> upsert
                 larger than clamd scans? -> hash it, then queue the open
                                     descriptor for clamscan, run in
                                     batches with the limits switched off

    Each file is visited exactly once per run. Unchanged files cost one
    stat() call and nothing else — no reads, no hashing, no clamd.

    clamd never opens your files itself (see clamd.py): Ensign opens each
    one with your permissions and hands clamd the open descriptor, so no
    ACL or group grant is needed, and clamd can't read anything Ensign
    didn't give it.

    Symlinks to regular files ARE followed and scanned (via safe_stat, not
    safe_lstat) -- a symlink is a common, low-effort way for something to
    end up outside a scanner's reach, and this is a security tool, so that
    blind spot isn't acceptable by default. Symlinked directories are never
    descended into (os.walk(followlinks=False)), so this can't loop or
    wander outside the configured scan_targets at the directory level.
"""
from __future__ import annotations

import contextlib
import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import NamedTuple

from rich import print
from sqlalchemy.orm import Session

from . import allowlist, secrets
from .clamd import (
    DEFAULT_LIMITS,
    LIMITS_EXCEEDED_PREFIX,
    ClamdClient,
    ClamdLimits,
    ScanOutcome,
    clamscan_cli_available,
    clamscan_user,
    is_size_limit_error,
    memory_available,
    scan_fds_with_clamscan,
)
from .config import Config
from .db import make_engine
from .fsutil import NotScannable, human_size, is_scannable, open_for_scan, safe_lstat, sha256_fd, shown, stat_or_error
from .models import DirectoryRecord, FileRecord, ScanStatus, open_failed_result, path_under, utcnow
from .progress import RunProgress

log = logging.getLogger(__name__)


class ClamdRunsAsRoot(RuntimeError):
    """clamd is running as root; Ensign refuses to send it anything."""


ROOT_CLAMD_MESSAGE = (
    "clamd is running as root. Ensign won't send it any files: clamd parses "
    "untrusted content, so a flaw in it would run with full control of the "
    "machine, and ClamAV itself advises against running it as root. Set "
    "'User clamav' in clamd.conf, then: sudo systemctl restart clamav-daemon"
)


@dataclass(frozen=True)
class IntegrityChange:
    """An INTEGRITY_WATCHED file (authorized_keys, ~/.ssh/config, ...)
    whose contents differ from the last run."""
    path: str
    old_hash: str
    new_hash: str

_STATUS_SYMBOLS = {
    ScanStatus.CLEAN.value: "[green]✓[/green]",
    ScanStatus.INFECTED.value: "[red]![/red]",
    ScanStatus.ERROR.value: "[yellow]✗[/yellow]",
    ScanStatus.PENDING.value: "?",
    ScanStatus.CLASSIFIED.value: "[dim]•[/dim]",
    ScanStatus.INCOMPLETE.value: "[yellow]~[/yellow]",
    ScanStatus.ALLOWED.value: "[cyan]○[/cyan]",
}

# Workers: never more than this, and always this many fewer than clamd's
# MaxThreads, so clamd stays responsive to anything else using it.
_MAX_WORKERS = 12
_CLAMD_HEADROOM = 2

# Large files queued for clamscan are scanned up to this many to a run, or
# until the batch holds this many bytes, whichever comes first. Each run
# loads the whole signature database, so fewer runs is fewer loads; but a
# run scans its files one after another on one core, so smaller batches
# spread the work across the clamscans the budget allows, and no single
# run turns into hours of work at the end. Bytes, not just files: scan time
# follows size. And every queued file holds an open descriptor until its run.
_CLAMSCAN_BATCH = 32
_CLAMSCAN_BATCH_BYTES = 8 * 2**30
# clamscan time allowed per run: a fixed allowance plus 1 s per 5 MiB.
_CLAMSCAN_BASE_TIMEOUT = 300.0
_CLAMSCAN_BYTES_PER_SECOND = 5 * 2**20
# Running clamscans side by side. Each loads its own copy of the
# signatures, about what clamd holds; that figure (with this margin) is
# what another clamscan needs. Two limits, both checked before each one
# starts: together they may use at most clamscan_memory_percent of total
# RAM (a fixed budget, however much is free), and another must fit in
# what is free right now after a reserve kept for everything else on the
# machine -- the larger of 2 GiB and 10% of RAM.
_CLAMSCAN_MEMORY_MARGIN = 1.25
_CLAMSCAN_FALLBACK_MEMORY = 1536 * 2**20  # if clamd's own use can't be read
_MEMORY_RESERVE_MIN = 2 * 2**30
_MEMORY_RESERVE_FRACTION = 0.10
# A clamscan takes a while to load its signatures, and until it has, free
# memory doesn't show it. One started this recently counts as using its
# share already.
_CLAMSCAN_LOADING_SECONDS = 60.0
# Auto: at most this many at once. Each scans on one core, and counts
# against cpu_share alongside the scan workers.
_CLAMSCAN_AUTO_MAX = 8


def _mib(n: int) -> str:
    return f"{n / 2**20:,.0f} MiB"


def _clamd_skipped(outcome: ScanOutcome) -> bool:
    """clamd answered, but didn't scan the file: it is past one of clamd's
    limits. Either an error naming the size limit, or -- with
    AlertExceedsMax -- a Heuristics.Limits.Exceeded.* "detection", which is
    a note that scanning stopped, not an infection."""
    if outcome.status == ScanStatus.ERROR:
        return is_size_limit_error(outcome.raw)
    return (outcome.status == ScanStatus.INFECTED
            and (outcome.threat_name or "").startswith(LIMITS_EXCEEDED_PREFIX))


@dataclass
class _Oversized:
    """A large file waiting for clamscan: hashed, and still open."""
    path: Path
    st: os.stat_result
    fd: int          # -1 once closed
    digest: str
    fd_was: int = -1  # the number it had, to look up its clamscan result

    def __post_init__(self) -> None:
        self.fd_was = self.fd


def _close_queued(batch: list[_Oversized]) -> None:
    """Close each queued file's descriptor exactly once. A number is marked
    closed as soon as it is: the kernel hands closed numbers straight out
    again, to another file, clamd's socket or the database, and closing one
    a second time would close that instead."""
    for item in batch:
        if item.fd >= 0:
            fd, item.fd = item.fd, -1
            with contextlib.suppress(OSError):
                os.close(fd)


class _ClamscanPool:
    """Runs batches of large files through clamscan beside the scan workers,
    as many at once as free memory allows.

    The scan workers hand a full batch to submit() and carry on with the
    files clamd can scan; they never wait for clamscan itself. They wait
    only if batches pile up faster than clamscan gets through them (more
    than `limit + 1` waiting or running): every queued file is an open
    descriptor, and this caps how many are open.

    Before each clamscan starts, memory is read again. It starts only if
    all of them together, it included, stay within `memory_percent` of
    total RAM, and another copy of the signatures fits in what is free
    (MemAvailable) with the reserve left over. The first always starts, so
    large files always get scanned.
    """

    def __init__(self, limit: int, per_copy: int, run_batch, memory_percent: int = 25,
                 cpu_allows=None) -> None:
        self.limit = max(1, limit)
        self.per_copy = per_copy
        self.memory_percent = memory_percent
        # cpu_allows(running) -> may another start, given `running` already?
        self._cpu_allows = cpu_allows or (lambda running: True)
        self._run_batch = run_batch
        self._cond = threading.Condition()
        self._pending = 0                  # submitted, not finished
        self._started: dict[int, float] = {}  # running: thread id -> start time
        self.peak = 0                      # most running at once (for tests and the summary)
        _raise_fd_limit((self.limit + 2) * _CLAMSCAN_BATCH + 256)

    def submit(self, batch: list[_Oversized]) -> None:
        with self._cond:
            while self._pending >= self.limit + 1:
                self._cond.wait()
            self._pending += 1
        threading.Thread(target=self._run, args=(batch,), daemon=True,
                         name="ensign-clamscan").start()

    def wait(self) -> None:
        """Block until every submitted batch is done."""
        with self._cond:
            while self._pending:
                self._cond.wait()

    def _memory_allows_another(self) -> bool:
        mem = memory_available()
        if mem is None:
            return False  # can't tell: one at a time
        available, total = mem
        budget = total * self.memory_percent // 100
        if (len(self._started) + 1) * self.per_copy > budget:
            return False  # the fixed budget: never more than this, however much is free
        reserve = max(_MEMORY_RESERVE_MIN, int(total * _MEMORY_RESERVE_FRACTION))
        now = time.monotonic()
        loading = sum(1 for t in self._started.values() if now - t < _CLAMSCAN_LOADING_SECONDS)
        return available - loading * self.per_copy - reserve >= self.per_copy

    def _run(self, batch: list[_Oversized]) -> None:
        me = threading.get_ident()
        with self._cond:
            while self._started and not (len(self._started) < self.limit
                                         and self._cpu_allows(len(self._started))
                                         and self._memory_allows_another()):
                # woken when a clamscan finishes; checked again every few
                # seconds anyway, since memory can free up elsewhere too
                self._cond.wait(timeout=5)
            self._started[me] = time.monotonic()
            self.peak = max(self.peak, len(self._started))
            running = len(self._started)
        try:
            self._run_batch(batch, running)
        except Exception:  # a batch must never take the scan down with it
            log.exception("clamscan batch failed")
            _close_queued(batch)
        finally:
            with self._cond:
                del self._started[me]
                self._pending -= 1
                self._cond.notify_all()


def _raise_fd_limit(wanted: int) -> None:
    """Raise this process's open-file limit (the soft limit, up to the hard
    one) if it is below `wanted`: queued large files are open descriptors."""
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft != resource.RLIM_INFINITY and soft < wanted:
            target = wanted if hard == resource.RLIM_INFINITY else min(wanted, hard)
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    except (ImportError, OSError, ValueError):
        pass


class _Known(NamedTuple):
    """What the DB remembers about a file, for change detection."""
    size: int | None
    mtime_ns: int
    ctime_ns: int | None
    status: str | None
    sig_version: int | None
    # Scanned whole by clamscan rather than by clamd (scan_result starts
    # "clamscan:"). A large file marked clean by clamd alone was never
    # actually scanned -- see _collect_changed_files.
    by_clamscan: bool = False
    # Recorded as INCOMPLETE because clamscan couldn't be run (not
    # installed, or root with no clamav user): scan_result "not scanned:".
    clamscan_missing: bool = False


@dataclass(frozen=True)
class UnsavedResult:
    """A file Ensign looked at but could not record in its database.

    Kept in memory for the end-of-run report, so a result -- above all an
    infection -- is still reported and alerted on even though the database
    write failed (a full disk, a locked or damaged database). Without this,
    a failed write would turn a detection into "nothing found".
    """
    path: str
    status: str            # "infected", "clean", "error", "classified", or "not scanned"
    threat_name: str | None
    error: str


@dataclass
class TreeStats:
    seen: int = 0
    unchanged: int = 0
    processed: int = 0
    failed: int = 0
    pruned_dirs: int = 0
    excluded_dirs: int = 0
    snapshot_dirs: list[tuple[str, int]] = field(default_factory=list)
    # Directories Ensign could not look inside, so nothing in them was
    # scanned: path -> reason. A dict so a directory reached twice (by
    # overlapping scan targets) is recorded once.
    unreadable_dirs: dict[str, str] = field(default_factory=dict)
    # Paths skipped because stat() said "No such file or directory": broken
    # symlinks (Steam's runtime folders are full of them) and files that
    # vanished mid-walk. A set so overlapping scan targets count each once.
    missing: set[str] = field(default_factory=set)
    # Unchanged files queued for a rescan only because the signature
    # database has moved on since they were last scanned.
    sig_rescan: int = 0
    # Unchanged large files clamd once called clean without scanning them
    # (Ensign 0.4.0 and older trusted that "OK"): rescanned once, by clamscan.
    big_recheck: int = 0


class Scanner:
    def __init__(self, config: Config, clamd: ClamdClient | None = None):
        self.config = config
        self.engine = make_engine(config.db_url)
        self.clamd = clamd or ClamdClient(config.clamd_socket)
        self._workers: int | None = None
        # Signature DB version for the current scan_tree run; None = unknown
        # or not scanning. Fixed at the start of a run so every file is
        # stamped with the same (possibly slightly old, never too new)
        # version -- if clamd reloads mid-run, the next run rescans.
        self._sig_version: int | None = None
        # How files reach clamd: "fd" (FILDES, the normal case) or "path"
        # (SCAN, when clamd lacks FILDES). Decided once, by prepare_clamd().
        self._transport: str | None = None
        self._prepare_lock = threading.Lock()
        # Watched SSH files that changed this run; appended from worker
        # threads, read by the CLI after the scan.
        self.integrity_changes: list[IntegrityChange] = []
        self._integrity_lock = threading.Lock()
        # Results that couldn't be saved (see UnsavedResult), for the report.
        self.unsaved: list[UnsavedResult] = []
        self._unsaved_lock = threading.Lock()
        # Watched files that didn't exist at the last scan of a tree that
        # had been scanned before: a new authorized_keys is a change too.
        self._watched_new: set[str] = set()
        # clamd's size limits, read by prepare_clamd(); None until then.
        self.limits: ClamdLimits | None = None
        # Large files waiting for clamscan, and the clamscans running them.
        self._oversized: list[_Oversized] = []
        self._oversized_bytes = 0  # total size of the files in self._oversized
        self._oversized_lock = threading.Lock()
        self._clamscans: _ClamscanPool | None = None
        self._allowed_pairs: set[tuple[str, str]] | None = None  # see _allowed()
        self.clamd_max_threads: int | None = None  # set when the worker count is resolved
        # Scan workers busy on a file right now: they share the CPU budget
        # with the clamscans.
        self._busy_workers = 0
        self._busy_lock = threading.Lock()
        self._worker_state = threading.local()  # .busy: this thread is counted in _busy_workers
        # The running pass's progress line (its advance()), for files that
        # finish in a clamscan batch; None outside a pass.
        self._advance = None
        self._warned_clamscan: set[str] = set()

    def prepare_clamd(self) -> None:
        """Check clamd once, before the first file is sent to it.

        Raises ClamdRunsAsRoot if clamd runs as root (fail closed: no
        fallback, nothing is scanned). Otherwise picks the transport:
        FILDES when the daemon offers it, else path SCAN with a warning,
        since then clamd can only scan what the clamav user can read.
        """
        with self._prepare_lock:  # worker threads may all arrive at once
            if self._transport is None:
                self._transport = self._choose_transport()
                self.limits = self._read_limits()

    def _read_limits(self) -> ClamdLimits:
        reader = getattr(self.clamd, "limits", None)  # test doubles may not have it
        try:
            limits = reader() if reader is not None else DEFAULT_LIMITS
        except Exception as exc:  # never let this stop a scan: the defaults are safe
            log.error("could not read clamd's limits: %s", exc)
            limits = DEFAULT_LIMITS
        if limits.source.startswith("ClamAV defaults") and reader is not None:
            print(f"[dim]Couldn't read clamd's config ({shown(limits.source)}): assuming files "
                  f"from {_mib(limits.scan_limit)} up are too large for clamd.[/dim]")
        return limits

    @staticmethod
    def _clamscan_usable() -> bool:
        if not clamscan_cli_available():
            return False
        try:
            clamscan_user()
        except LookupError:
            return False
        return True

    def _allowed(self) -> set[tuple[str, str]]:
        """Your allowances (allowlist.py), read once per run."""
        if self._allowed_pairs is None:
            with self._prepare_lock:
                if self._allowed_pairs is None:
                    self._allowed_pairs = allowlist.allowed_pairs(self.engine)
        return self._allowed_pairs

    def _scan_limit(self) -> int:
        return (self.limits or DEFAULT_LIMITS).scan_limit

    def _choose_transport(self) -> str:
        uid = self.clamd.daemon_uid()
        if uid == 0:
            raise ClamdRunsAsRoot(ROOT_CLAMD_MESSAGE)
        if uid is None:
            print("[yellow]! Couldn't confirm which user clamd runs as (no access to "
                  "its /proc entry). Continuing; check with: ps -o user= -C clamd[/yellow]")
        if self.clamd.supports_fildes():
            return "fd"
        print("[yellow]! This clamd can't receive open files (no FILDES). Falling back "
              "to path scanning: clamd can only scan files the 'clamav' user can read, "
              "and the rest are recorded as errors.[/yellow]")
        return "path"

    @property
    def workers(self) -> int:
        """
        Resolved lazily on first access, so maintenance commands
        that never scan (--purge-missing, --suggest-fixes) don't pay
        for a clamd connection they don't need."""
        if self._workers is None:
            self._workers = self._resolve_workers()
        return self._workers

    def _resolve_workers(self) -> int:
        """
        Pick the worker-pool size for this machine.

        An explicit max_workers in the config always wins. Otherwise
        (max_workers = 0, "auto"), size to the real bottleneck: clamd's
        own MaxThreads, minus headroom so the daemon stays responsive
        to other clients, capped by CPU count and a sane floor/ceiling.

        The floor is always 1 -- even on a single-core machine, or if
        clamd reports a very low MaxThreads, this never returns 0 or
        negative. Ensign always runs; a heavily constrained machine just
        processes files one at a time through the same ThreadPoolExecutor
        path rather than needing a separate non-threaded code path.
        """
        if self.config.max_workers > 0:
            return self.config.max_workers
        clamd_max = self.clamd.max_threads()
        self.clamd_max_threads = clamd_max
        if clamd_max is None:
            return min(5, self.cpu_budget())  # daemon unreachable or unparseable; safe default
        cpus = os.cpu_count() or 4
        return max(1, min(clamd_max - _CLAMD_HEADROOM, cpus, _MAX_WORKERS, self.cpu_budget()))

    def cpu_budget(self) -> int:
        """How many CPU threads a scan may keep busy: cpu_share percent of
        them, at least 1. The scan workers and the clamscans share it."""
        return max(1, (os.cpu_count() or 2) * self.config.cpu_share // 100)

    def _cpu_allows_clamscan(self, running: int) -> bool:
        """Another clamscan may start if it, those already running, and the
        scan workers busy right now all fit in the CPU budget."""
        with self._busy_lock:
            busy = self._busy_workers
        return running + busy + 1 <= self.cpu_budget()

    def thread_hint(self) -> str | None:
        """Advice to raise clamd's MaxThreads, or None.

        Only when the worker count is automatic and clamd's MaxThreads is what
        holds it back, though cpu_share allows more: the suggestion is what
        would let the workers fill the CPU budget (MaxThreads = workers + 2),
        never more. Advice only: Ensign never changes clamd's settings itself.
        """
        workers = self.workers  # resolves the count (and clamd_max_threads) if not yet done
        clamd_max = self.clamd_max_threads
        if self.config.max_workers > 0 or clamd_max is None:
            return None
        cpus = os.cpu_count() or 0
        allowed = min(self.cpu_budget(), cpus, _MAX_WORKERS)
        if allowed <= workers:
            return None
        suggested = allowed + _CLAMD_HEADROOM
        return (f"Tip: clamd's MaxThreads {clamd_max} limits Ensign to {workers} workers. "
                f"MaxThreads {suggested} in clamd.conf would allow {allowed}, the most "
                f"cpu_share ({self.config.cpu_share}% of {cpus} CPU threads) permits. "
                f"If you change it, restart clamd.")

    # ------------------------------------------------------------------
    # Tree scanning
    # ------------------------------------------------------------------

    def scan_tree(self, root: Path | str, scan: bool = True) -> TreeStats:
        """Scan every new or changed regular file under `root`."""
        root = Path(os.path.abspath(root))  # stored paths must be absolute; see cli.main
        stats = TreeStats()
        if not root.is_dir():
            print(f"[yellow]Skipping {shown(root)}: not a directory[/yellow]")
            return stats

        if scan:
            self.prepare_clamd()
        self._sig_version = self.clamd.signature_version() if scan else None
        known = self._load_known_files(root)
        candidates = self._collect_changed_files(root, known, stats)

        print(
            f"  {stats.seen} files seen · "
            f"{stats.unchanged} unchanged · "
            f"{stats.pruned_dirs} snapshot subtrees pruned · "
            f"{stats.excluded_dirs} excluded · "
            f"[bold]{len(candidates)} to process[/bold]"
            + (f" ({stats.sig_rescan} because signatures updated)" if stats.sig_rescan else "")
            + (f" ({stats.big_recheck} large files not really scanned before)" if stats.big_recheck else "")
        )
        if candidates:
            results = self._process_all(candidates, scan, "Scan Progress")
            stats.processed = sum(1 for r in results if r is not None)
            stats.failed = len(results) - stats.processed
            print(f"  Completed: {stats.processed}/{len(candidates)} files processed")

        # Only record snapshot mtimes once the tree finished, so a crash
        # mid-run can't mark an unscanned subtree as done.
        self._record_snapshot_dirs(stats.snapshot_dirs)
        return stats

    def _is_excluded(self, path: Path) -> bool:
        """True if path is inside any configured exclude tree."""
        text = str(path)
        return any(
            text == ex or text.startswith(ex + "/")
            for ex in self.config.excludes
        )

    def _collect_changed_files(
        self, root: Path, known: dict[str, _Known], stats: TreeStats
    ) -> list[Path]:
        """Walk once, top-down, returning files that need hashing/scanning."""
        candidates: list[Path] = []
        # os.walk silently skips any directory it can't list unless it is
        # given an onerror callback -- without one, a directory Ensign has
        # no permission to read was never scanned and never mentioned.
        walk = os.walk(
            root, topdown=True, followlinks=False,
            onerror=lambda exc: self._on_walk_error(stats, exc),
        )
        for dirpath, dirnames, filenames in walk:
            # Pruning dirnames in place stops os.walk from descending —
            # excluded trees and unchanged snapshot subtrees are never
            # entered at all. followlinks=False above also means a
            # symlinked directory is never descended into, regardless.
            kept = []
            for name in dirnames:
                subdir = Path(dirpath) / name
                if self._is_excluded(subdir):
                    stats.excluded_dirs += 1
                elif self._should_prune(subdir, stats):
                    stats.pruned_dirs += 1
                else:
                    kept.append(name)
            dirnames[:] = kept

            for name in filenames:
                path = Path(dirpath) / name
                if self._is_excluded(path):
                    continue
                # safe_stat (not safe_lstat) so a symlink to a regular
                # file is followed and scanned through to its target;
                # a broken symlink or one pointing at a socket/device
                # just becomes None or fails is_scannable, same as any
                # other unreadable/unsuitable path.
                st, err = stat_or_error(path)
                if st is None:
                    if isinstance(err, FileNotFoundError):
                        # Nothing there to scan. Counted, not logged: it
                        # used to log an error per path on every run.
                        stats.missing.add(str(path))
                    else:
                        log.error("stat failed for %s: %s", path, err)
                        self._note_if_blocked(dirpath, path, stats)
                    continue
                if not is_scannable(st):
                    continue
                stats.seen += 1
                prev = known.get(str(path))
                if prev is None and known and secrets.is_integrity_watched(str(path)):
                    self._watched_new.add(str(path))
                if prev is None or (prev.size, prev.mtime_ns) != (st.st_size, st.st_mtime_ns):
                    candidates.append(path)
                elif prev.ctime_ns != st.st_ctime_ns:
                    # Includes rows saved before ctime tracking (NULL):
                    # their history can't be vouched for, so they are
                    # rescanned once and get a ctime recorded.
                    candidates.append(path)
                elif self._signatures_moved_on(prev):
                    stats.sig_rescan += 1
                    candidates.append(path)
                elif (self.limits is not None and prev.status == ScanStatus.CLEAN.value
                      and (prev.size or 0) >= self._scan_limit() and not prev.by_clamscan):
                    stats.big_recheck += 1
                    candidates.append(path)
                elif prev.clamscan_missing and self.limits is not None and self._clamscan_usable():
                    stats.big_recheck += 1  # clamscan can be run now; it couldn't before
                    candidates.append(path)
                else:
                    stats.unchanged += 1
        return candidates

    def _on_walk_error(self, stats: TreeStats, exc: OSError) -> None:
        """os.walk's onerror hook: called when a directory can't be listed.

        Every error goes to the error log, like safe_stat's failures do.
        Only the ones that mean "Ensign was refused" are reported: a
        directory that vanished or was replaced mid-walk (temp files do
        this constantly) isn't a blind spot, just noise.
        """
        log.error("cannot list %s: %s", exc.filename, exc)
        if isinstance(exc, (FileNotFoundError, NotADirectoryError)):
            return
        stats.unreadable_dirs[str(exc.filename)] = f"cannot list: {exc.strerror or exc}"

    def _note_if_blocked(self, dirpath: str, path: Path, stats: TreeStats) -> None:
        """Called when a file inside `dirpath` couldn't be stat'ed.

        A directory with read but no search (x) permission lists fine, so
        os.walk raises nothing -- but every stat() inside it fails, and
        those files would be skipped with only a log line to show for it.
        stat() fails with PermissionError only when a directory on the way
        lacks search permission, and since os.walk got as far as listing
        `dirpath`, the directory at fault is `dirpath` itself. lstat (not
        stat) is the probe so a symlink with a dead or unreachable target
        isn't mistaken for a blocked directory. Runs only on the failure
        path, and records each directory once.
        """
        if dirpath in stats.unreadable_dirs:
            return
        try:
            os.lstat(path)
        except PermissionError:
            stats.unreadable_dirs[dirpath] = (
                "cannot enter: no search (x) permission, files inside were skipped"
            )
        except OSError:
            pass

    def _signatures_moved_on(self, prev: _Known) -> bool:
        """True if a clean file was last scanned under an out-of-date database.

        Only clean verdicts are affected: infected files are already
        re-checked every run, and error/classified rows never got a real
        verdict to go stale. A threshold of 0, or an unknown current
        version, switches this off rather than guessing.
        """
        threshold = self.config.rescan_after_signature_updates
        current = self._sig_version
        # Allowed files too: newer signatures may have fixed the false
        # positive (it turns clean) or flag it with something else (infected).
        if threshold <= 0 or current is None or prev.status not in (
                ScanStatus.CLEAN.value, ScanStatus.ALLOWED.value):
            return False
        if prev.sig_version is None:
            return True  # clean under an unknown database: can't vouch for it
        # current < stamped means the database went backwards (restored
        # backup, different machine): treat as stale too.
        return current < prev.sig_version or current - prev.sig_version >= threshold

    def _load_known_files(self, root: Path) -> dict[str, _Known]:
        # One query up front instead of one query per file during the walk.
        with Session(self.engine) as session:
            rows = session.query(
                FileRecord.filepath, FileRecord.file_size, FileRecord.mtime_ns,
                FileRecord.ctime_ns, FileRecord.scan_status, FileRecord.sig_version,
                FileRecord.scan_result.like("clamscan:%"),
                FileRecord.scan_result.like("not scanned:%"),
            ).filter(path_under(FileRecord.filepath, str(root))).all()
        return {row[0]: _Known(*row[1:6], bool(row[6]), bool(row[7])) for row in rows if row[2] is not None}

    # ------------------------------------------------------------------
    # Snapshot-subtree pruning
    # ------------------------------------------------------------------

    def _is_snapshot_dir(self, path: Path) -> bool:
        """True if path is a snapshot root or inside one. Matched on a whole
        path component, like _is_excluded: "/snaps" must not also match
        "/snaps2", whose subtrees would then be pruned on an unchanged
        directory mtime -- and a file edited in place doesn't change that."""
        text = str(path)
        return any(
            text == root or text.startswith(root + "/")
            for root in (r.rstrip("/") for r in self.config.snapshot_roots)
        )

    def _should_prune(self, path: Path, stats: TreeStats) -> bool:
        if not self._is_snapshot_dir(path):
            return False
        st = safe_lstat(path)
        if st is None:
            return False
        with Session(self.engine) as session:
            record = session.query(DirectoryRecord).filter(
                DirectoryRecord.directory_path == str(path)
            ).first()
            if record and record.mtime_ns == st.st_mtime_ns:
                return True
        stats.snapshot_dirs.append((str(path), st.st_mtime_ns))
        return False

    def _record_snapshot_dirs(self, entries: list[tuple[str, int]]) -> None:
        if not entries:
            return
        with Session(self.engine) as session:
            try:
                for path, mtime_ns in entries:
                    record = session.query(DirectoryRecord).filter(
                        DirectoryRecord.directory_path == path
                    ).first()
                    if record is None:
                        record = DirectoryRecord(
                            directory_path=path,
                            directory_name=os.path.basename(path),
                        )
                        session.add(record)
                    record.mtime_ns = mtime_ns
                    record.last_scanned = utcnow()
                session.commit()
            except Exception as exc:
                session.rollback()
                log.error("recording snapshot dirs failed: %s", exc)

    # ------------------------------------------------------------------
    # Single-file pipeline
    # ------------------------------------------------------------------

    def _process_all(self, paths: list, scan: bool, label: str) -> list[str | None]:
        """Run process_file over `paths` in the worker pool, with the live
        progress line pinned under the per-file output. Returns the hashes
        (None for failures) in input order."""
        with RunProgress(label, len(paths), self.workers) as bar:
            # A file queued for clamscan is counted when clamscan's result is
            # recorded, not when it is queued, and the line stays up until
            # the last clamscan is done: the run isn't finished before that.
            self._advance = bar.advance
            try:
                def work(path) -> str | None:
                    with self._busy_lock:
                        self._busy_workers += 1
                    self._worker_state.busy = True
                    try:
                        digest, status = self._process_file(path, scan)
                    finally:
                        self._worker_state.busy = False
                        with self._busy_lock:
                            self._busy_workers -= 1
                    if status != "queued":
                        bar.advance(status)
                    return digest

                with ThreadPoolExecutor(max_workers=self.workers) as pool:
                    results = list(pool.map(work, paths))
                self.scan_oversized()
            finally:
                self._advance = None
        return results

    def process_file(self, path: Path | str, scan: bool = True) -> str | None:
        """
        Hash one file, optionally clamd-scan it, and upsert the record.

        Returns the hash on success, "" for a credential file recorded
        without being read, None on any failure. Safe to call from worker
        threads: it opens its own short-lived session. A file too large for
        clamd is queued for clamscan; call scan_oversized() to scan the queue.
        """
        return self._process_file(path, scan)[0]

    def _process_file(self, path: Path | str, scan: bool = True) -> tuple[str | None, str]:
        """process_file, plus what happened: the second value is the scan
        status ("clean", "infected", "error", "classified", ...), or "skipped" for a file
        that vanished or isn't a regular file, or "failed" if it couldn't be
        hashed or recorded."""
        path = Path(path)
        st, err = stat_or_error(path)
        if st is None:
            # Gone between the walk listing it and this worker reaching it
            # (browser caches, temp files): nothing to scan, and not an
            # error worth logging. Any other failure is still logged.
            if err is not None and not isinstance(err, FileNotFoundError):
                log.error("stat failed for %s: %s", path, err)
            return None, "skipped"
        if not is_scannable(st):
            return None, "skipped"

        # Credential files are decided on the path and stat() alone, before
        # anything opens them: no hash is taken and clamd never sees them.
        reason = secrets.skip_reason(str(path), os.path.realpath(path), st.st_mode)
        if reason is not None and not self._known_infected(path):
            return self._record_classified(path, st, reason)

        if scan:
            self.prepare_clamd()  # no-op after the first call; raises if clamd is root

        try:
            fd, st = open_for_scan(path)
        except NotScannable:
            return None, "skipped"  # swapped for a FIFO/device/empty file mid-run
        except FileNotFoundError:
            return None, "skipped"
        except OSError as exc:
            # Most often a file owned by root or another user. Recorded as
            # an error, never dropped: a silently missing file reads as
            # "scanned, nothing found", and an old "clean" record for it
            # would stay in place for a file nobody can check any more.
            return self._record_unreadable(path, st, exc)
        try:
            # The link could have been re-pointed between realpath() above
            # and open(). Ask the kernel what was actually opened, and
            # re-check before reading a single byte of it.
            if reason is None:
                try:
                    opened = os.readlink(f"/proc/self/fd/{fd}")
                except OSError:
                    opened = os.path.realpath(path)
                late = secrets.skip_reason(str(path), opened, st.st_mode)
                if late is not None and not self._known_infected(path):
                    return self._record_classified(path, st, late)
            try:
                digest = sha256_fd(fd)
            except OSError as exc:  # opened, but reading failed (an I/O error, say)
                return self._record_unreadable(path, st, exc)
            if not scan:
                outcome = None
            elif st.st_size >= self._scan_limit():
                # clamd would skip this file and still answer "OK". Not sent
                # to clamd at all: queued, still open, for clamscan.
                self._queue_oversized(_Oversized(path, st, fd, digest))
                fd = -1  # the queue owns the descriptor now
                return digest, "queued"
            else:
                outcome = (self.clamd.scan(path) if self._transport == "path"
                           else self.clamd.scan_fd(fd, label=str(path)))
                if _clamd_skipped(outcome):  # a limit Ensign didn't know about
                    self._queue_oversized(_Oversized(path, st, fd, digest))
                    fd = -1
                    return digest, "queued"
        finally:
            if fd >= 0:
                os.close(fd)
        return self._finish(path, st, digest, outcome)

    def _finish(
        self, path: Path, st: os.stat_result, digest: str, outcome: ScanOutcome | None
    ) -> tuple[str | None, str]:
        """Record a hashed (and maybe scanned) file, note SSH-file changes,
        and print its line."""
        if (outcome is not None and outcome.status == ScanStatus.INFECTED and digest
                and (digest, outcome.threat_name or "Unknown") in self._allowed()):
            # You marked this exact content, flagged by this exact signature,
            # as a false positive (allowlist.py). Anything else stays infected.
            outcome = ScanOutcome(ScanStatus.ALLOWED, outcome.raw, outcome.threat_name)
        try:
            previous_hash = self._upsert_file(path, st, digest, outcome)
        except Exception as exc:
            self._remember_unsaved(path, outcome, exc)
            return None, "failed"

        if secrets.is_integrity_watched(str(path)):
            if previous_hash and previous_hash != digest:
                change = IntegrityChange(str(path), previous_hash, digest)
            elif previous_hash is None and str(path) in self._watched_new:
                change = IntegrityChange(str(path), "", digest)  # created since last run
            else:
                change = None  # unchanged, or the very first scan (the baseline)
            if change is not None:
                with self._integrity_lock:
                    self.integrity_changes.append(change)

        status = outcome.status.value if outcome else ScanStatus.PENDING.value
        symbol = _STATUS_SYMBOLS.get(status, "?")
        if outcome is not None and outcome.status == ScanStatus.ALLOWED:
            symbol = f"{symbol} [dim](allowed by you)[/dim]"
        print(f"{symbol} {shown(path.name):.<50} {digest[:16]}… {status}")
        return digest, status

    # ------------------------------------------------------------------
    # Files too large for clamd: clamscan, in batches
    # ------------------------------------------------------------------

    def _queue_oversized(self, item: _Oversized) -> None:
        print(f"[dim]→ {shown(item.path.name)} ({human_size(item.st.st_size)}) is too large for clamd; "
              f"queued for clamscan[/dim]")
        # The full list is swapped for a fresh one under the lock, so nothing
        # is ever added to a batch already handed over.
        with self._oversized_lock:
            self._oversized.append(item)
            self._oversized_bytes += item.st.st_size
            full = (len(self._oversized) >= _CLAMSCAN_BATCH
                    or self._oversized_bytes >= _CLAMSCAN_BATCH_BYTES)
            batch = self._oversized if full else None
            if batch is not None:
                self._oversized, self._oversized_bytes = [], 0
        if batch is not None:
            # A worker waiting for room in the clamscan queue uses no CPU, so
            # it stops counting against the CPU budget while it waits:
            # otherwise workers stuck here would hold the budget and keep the
            # very clamscans they wait on from starting.
            counted = getattr(self._worker_state, "busy", False)
            if counted:
                with self._busy_lock:
                    self._busy_workers -= 1
            try:
                self._clamscan_pool().submit(batch)
            finally:
                if counted:
                    with self._busy_lock:
                        self._busy_workers += 1

    def scan_oversized(self) -> None:
        """Scan every queued large file and wait until all of them are done.
        Safe to call with nothing queued."""
        with self._oversized_lock:
            batch, self._oversized = self._oversized, []
            self._oversized_bytes = 0
        if batch:
            self._clamscan_pool().submit(batch)
        if self._clamscans is not None:
            self._clamscans.wait()

    def _clamscan_pool(self) -> _ClamscanPool:
        with self._oversized_lock:
            if self._clamscans is None:
                measure = getattr(self.clamd, "memory_in_use", None)
                in_use = measure() if measure is not None else None
                per_copy = int((in_use or _CLAMSCAN_FALLBACK_MEMORY) * _CLAMSCAN_MEMORY_MARGIN)
                if self.config.max_clamscans > 0:
                    limit, why = self.config.max_clamscans, "max_clamscans in config"
                else:
                    limit = max(1, min(_CLAMSCAN_AUTO_MAX, self.cpu_budget()))
                    why = f"auto: cpu_share {self.config.cpu_share}%, up to {_CLAMSCAN_AUTO_MAX}"
                percent = self.config.clamscan_memory_percent
                self._clamscans = _ClamscanPool(limit, per_copy, self._clamscan_batch, percent,
                                                cpu_allows=self._cpu_allows_clamscan)
                mem = memory_available()
                budget = (f", {percent}% of RAM ({human_size(mem[1] * percent // 100)}) at most"
                          if mem else "")
                if self._clamscan_usable():
                    print(f"[dim]clamscan: up to {limit} at once ({why}), each needing about "
                          f"{human_size(per_copy)}{budget}; more start only while CPU and memory "
                          f"allow[/dim]")
            return self._clamscans

    def _clamscan_batch(self, batch: list[_Oversized], running: int = 1) -> None:
        total = sum(item.st.st_size for item in batch)
        alongside = f", {running} clamscans running" if running > 1 else ""
        print(f"\n[bold]Scanning {len(batch)} large file(s) ({human_size(total)}) with clamscan[/bold]"
              f"[dim]{alongside}[/dim]")
        advance = self._advance
        by_fd = {item.fd_was: item for item in batch}
        recorded: set[int] = set()

        def record(fd: int, outcome: ScanOutcome) -> None:
            """Record, print and count one file -- as soon as clamscan is done
            with it, not when the whole batch is."""
            item = by_fd.get(fd)
            if item is None or fd in recorded:
                return
            recorded.add(fd)
            status = ScanStatus.ERROR.value
            try:
                status = self._finish(item.path, item.st, item.digest, outcome)[1]
            except Exception:  # one file failing to record must not drop the rest
                log.exception("could not record the clamscan result for %s", item.path)
            if advance is not None:
                advance(status)

        try:
            outcomes = self._clamscan_outcomes(batch, total, record)
        except Exception as exc:  # every file still gets a result, and is counted
            log.exception("clamscan batch failed")
            outcomes = {}
            failed = ScanOutcome(ScanStatus.ERROR, f"clamscan: {exc}")
            for item in batch:
                outcomes[item.fd_was] = failed
        finally:
            _close_queued(batch)
        for item in batch:  # any not reported as it went (no clamscan to run, or it failed)
            record(item.fd_was, outcomes.get(item.fd_was, ScanOutcome(ScanStatus.ERROR, "clamscan: no result")))

    def _clamscan_outcomes(self, batch: list[_Oversized], total: int,
                           on_result=None) -> dict[int, ScanOutcome]:
        def not_scanned(why: str) -> dict[int, ScanOutcome]:
            with self._oversized_lock:
                first = why not in self._warned_clamscan
                self._warned_clamscan.add(why)
            if first:
                print(f"[yellow]! Large files can't be scanned: {why}. They are recorded as "
                      f"not fully scanned, never as clean.[/yellow]")
            return {item.fd: ScanOutcome(ScanStatus.INCOMPLETE, f"not scanned: {why}") for item in batch}

        if not clamscan_cli_available():
            return not_scanned("clamd skips files this size, and the 'clamscan' command isn't "
                               "installed (it comes with ClamAV)")
        try:
            run_as = clamscan_user()
        except LookupError as exc:
            return not_scanned(f"Ensign won't run clamscan as root, and there is {exc}")
        timeout = _CLAMSCAN_BASE_TIMEOUT + total / _CLAMSCAN_BYTES_PER_SECOND
        return scan_fds_with_clamscan([item.fd for item in batch], self.limits or DEFAULT_LIMITS,
                                      timeout, run_as, on_result=on_result)

    def _remember_unsaved(self, path: Path, outcome: ScanOutcome | None, exc: Exception) -> None:
        """A result the database refused: say so now, keep it for the report."""
        status = outcome.status.value if outcome else "not scanned"
        threat = outcome.threat_name if outcome else None
        with self._unsaved_lock:
            self.unsaved.append(UnsavedResult(str(path), status, threat, str(exc)))
        log.error("result not saved for %s (%s): %s", path, status, exc)
        if status == ScanStatus.INFECTED.value:
            print(f"[bold red]! {shown(path.name)}: {shown(threat)} FOUND -- but the result "
                  f"couldn't be saved. It is listed at the end of this run.[/bold red]")
        else:
            print(f"[red]✗ Couldn't save the result for {shown(path.name)} ({status}): "
                  f"{shown(exc)}[/red]")

    def _known_infected(self, path: Path) -> bool:
        """True if the database already has this file as INFECTED. Such a
        file is never skipped as a credential file, even if its name
        matches: a found infection must not quietly turn into "classified"."""
        with Session(self.engine) as session:
            status = session.query(FileRecord.scan_status).filter(
                FileRecord.filepath == str(path)
            ).scalar()
        return status == ScanStatus.INFECTED.value

    def _record_classified(
        self, path: Path, st: os.stat_result, reason: str
    ) -> tuple[str | None, str]:
        """Record a credential file without reading it. The hash is stored
        as "" (the column can't be NULL), and any hash an older version
        stored for it is overwritten."""
        outcome = ScanOutcome(ScanStatus.CLASSIFIED, reason)
        try:
            self._upsert_file(path, st, "", outcome)
        except Exception as exc:
            self._remember_unsaved(path, outcome, exc)
            return None, "failed"
        status = ScanStatus.CLASSIFIED.value
        print(f"{_STATUS_SYMBOLS[status]} {shown(path.name):.<50} {'not read':<17} {status}")
        return "", status

    def _record_unreadable(
        self, path: Path, st: os.stat_result, exc: OSError
    ) -> tuple[str | None, str]:
        """Record a file Ensign couldn't open or read as an ERROR.

        Its hash isn't known, so a stored one is kept (an integrity
        baseline survives a spell of being unreadable). The errors pass
        retries it on every run, and error_summary()/suggest_fixes() list it.
        """
        log.error("could not read %s: %s", path, exc)
        outcome = ScanOutcome(ScanStatus.ERROR, open_failed_result(exc))
        try:
            self._upsert_file(path, st, None, outcome)
        except Exception as db_exc:
            self._remember_unsaved(path, outcome, db_exc)
            return None, "failed"
        status = ScanStatus.ERROR.value
        reason = exc.strerror or type(exc).__name__
        print(f"{_STATUS_SYMBOLS[status]} {shown(path.name):.<50} {'not read':<17} {status} ({shown(reason)})")
        return None, status

    def _upsert_file(
        self, path: Path, st: os.stat_result, digest: str | None, outcome: ScanOutcome | None
    ) -> str | None:
        """Insert or update the file's row. Returns the hash the row held
        before this update, or None if the file wasn't in the database.

        digest=None means "not known this time": a stored hash is kept,
        and a new row gets "" (the column can't be NULL)."""
        with Session(self.engine) as session:
            try:
                record = session.query(FileRecord).filter(
                    FileRecord.filepath == str(path)
                ).first()
                previous_hash = record.file_hash if record is not None else None
                if record is None:
                    record = FileRecord(filepath=str(path), filename=path.name, file_hash=digest or "")
                    session.add(record)
                if digest is not None:
                    record.file_hash = digest
                record.file_size = st.st_size
                record.mtime_ns = st.st_mtime_ns
                record.ctime_ns = st.st_ctime_ns
                if outcome is not None:
                    record.scan_status = outcome.status.value
                    record.scan_result = outcome.raw
                    record.threat_name = outcome.threat_name
                    record.last_scanned = utcnow()
                    if outcome.status in (ScanStatus.CLEAN, ScanStatus.INFECTED, ScanStatus.ALLOWED):
                        record.sig_version = self._sig_version
                session.commit()
            except Exception:
                session.rollback()
                raise
        return previous_hash

    def purge_missing(self) -> int:
        """
        Delete records whose files no longer exist on disk.

        Temp files that vanished between scans otherwise sit in the DB
        forever — often with ERROR status — and pollute every report
        and rescan pass. Returns the number of records removed.
        """
        with Session(self.engine) as session:
            paths = [row[0] for row in session.query(FileRecord.filepath)]
        missing = [p for p in paths if not os.path.lexists(p)]
        if not missing:
            print("No missing files to purge.")
            return 0
        with Session(self.engine) as session:
            try:
                for chunk_start in range(0, len(missing), 500):
                    chunk = missing[chunk_start:chunk_start + 500]
                    session.query(FileRecord).filter(
                        FileRecord.filepath.in_(chunk)
                    ).delete(synchronize_session=False)
                session.commit()
            except Exception as exc:
                session.rollback()
                log.error("purge_missing failed: %s", exc)
                raise
        print(f"Purged {len(missing)} records for files that no longer exist.")
        return len(missing)

    # ------------------------------------------------------------------
    # Rescans — one generic helper instead of three near-copies
    # ------------------------------------------------------------------

    def rescan_infected(self) -> None:
        self._rescan("infected", FileRecord.scan_status == ScanStatus.INFECTED.value)

    def rescan_errors(self) -> None:
        self._rescan("errored", FileRecord.scan_status == ScanStatus.ERROR.value)

    def rescan_stale(self, days: int | None = None) -> None:
        days = days if days is not None else self.config.rescan_after_days
        cutoff = utcnow() - timedelta(days=days)
        self._rescan(
            f"stale (>{days} days)",
            (FileRecord.last_scanned < cutoff) | (FileRecord.last_scanned.is_(None)),
        )

    def _rescan(self, label: str, *criteria) -> None:
        # Fetch plain path strings, not ORM objects — detached instances
        # outliving their session is a bug waiting to happen.
        with Session(self.engine) as session:
            paths = [row[0] for row in session.query(FileRecord.filepath).filter(*criteria)]
        print(f"\nRescanning {len(paths)} {label} files…")
        if not paths:
            return
        self.prepare_clamd()
        # Stamp these verdicts with the database that actually produced them.
        self._sig_version = self.clamd.signature_version()
        self._process_all(paths, True, f"Rescan Progress ({label})")
