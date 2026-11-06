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

import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import NamedTuple

from rich import print
from sqlalchemy.orm import Session

from . import secrets
from .clamd import ClamdClient, ScanOutcome, clamscan_cli_available, is_size_limit_error, scan_with_clamscan_cli
from .config import Config
from .db import make_engine
from .fsutil import NotScannable, is_scannable, open_for_scan, safe_lstat, sha256_fd, shown, stat_or_error
from .models import DirectoryRecord, FileRecord, ScanStatus, path_under, utcnow
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
}


class _Known(NamedTuple):
    """What the DB remembers about a file, for change detection."""
    size: int | None
    mtime_ns: int
    ctime_ns: int | None
    status: str | None
    sig_version: int | None


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


class Scanner:
    def __init__(self, config: Config, clamd: ClamdClient | None = None):
        self.config = config
        self.engine = make_engine(config.db_url)
        self.clamd = clamd or ClamdClient(config.clamd_socket)
        self._workers: int | None = None
        self._warned_no_clamscan_cli = False
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
        # Watched files that didn't exist at the last scan of a tree that
        # had been scanned before: a new authorized_keys is a change too.
        self._watched_new: set[str] = set()

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
        if clamd_max is None:
            return 5  # daemon unreachable or unparseable; safe default
        cpus = os.cpu_count() or 4
        return max(1, min(clamd_max - 2, cpus, 12))

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
        if threshold <= 0 or current is None or prev.status != ScanStatus.CLEAN.value:
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
            ).filter(path_under(FileRecord.filepath, str(root))).all()
        return {row[0]: _Known(*row[1:]) for row in rows if row[2] is not None}

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
            def work(path) -> str | None:
                digest, status = self._process_file(path, scan)
                bar.advance(status)
                return digest

            with ThreadPoolExecutor(max_workers=self.workers) as pool:
                return list(pool.map(work, paths))

    def process_file(self, path: Path | str, scan: bool = True) -> str | None:
        """
        Hash one file, optionally clamd-scan it, and upsert the record.

        Returns the hash on success, "" for a credential file recorded
        without being read, None on any failure. Safe to call from worker
        threads: it opens its own short-lived session.
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
            log.error("read failed for %s: %s", path, exc)
            return None, "failed"
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
            except OSError as exc:
                log.error("read failed for %s: %s", path, exc)
                return None, "failed"
            if not scan:
                outcome = None
            elif self._transport == "path":
                outcome = self.clamd.scan(path)
            else:
                outcome = self.clamd.scan_fd(fd, label=str(path))
        finally:
            os.close(fd)

        if (
            outcome is not None
            and outcome.status == ScanStatus.ERROR
            and is_size_limit_error(outcome.raw)
        ):
            # clamd rejected this file for size, not content -- fall back
            # to the clamscan CLI with limits explicitly disabled, so a
            # legitimately large file still gets a real verdict instead
            # of a permanent error.
            if clamscan_cli_available():
                print(f"[dim]→ {shown(path.name)} exceeds clamd's size limit, falling back to clamscan CLI…[/dim]")
                outcome = scan_with_clamscan_cli(path)
            elif not self._warned_no_clamscan_cli:
                print("[yellow]! Some files exceed clamd's size limit and the 'clamscan' CLI "
                      "isn't installed to fall back on — install clamav's clamscan for full coverage.[/yellow]")
                self._warned_no_clamscan_cli = True

        try:
            previous_hash = self._upsert_file(path, st, digest, outcome)
        except Exception as exc:
            print(f"[red]✗ DB error on {shown(path.name)}: {shown(exc)}[/red]")
            log.error("%s: %s", path, exc)
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
        print(f"{symbol} {shown(path.name):.<50} {digest[:16]}… {status}")
        return digest, status

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
            print(f"[red]✗ DB error on {shown(path.name)}: {shown(exc)}[/red]")
            log.error("%s: %s", path, exc)
            return None, "failed"
        status = ScanStatus.CLASSIFIED.value
        print(f"{_STATUS_SYMBOLS[status]} {shown(path.name):.<50} {'not read':<17} {status}")
        return "", status

    def _upsert_file(
        self, path: Path, st: os.stat_result, digest: str, outcome: ScanOutcome | None
    ) -> str | None:
        """Insert or update the file's row. Returns the hash the row held
        before this update, or None if the file wasn't in the database."""
        with Session(self.engine) as session:
            try:
                record = session.query(FileRecord).filter(
                    FileRecord.filepath == str(path)
                ).first()
                previous_hash = record.file_hash if record is not None else None
                if record is None:
                    record = FileRecord(filepath=str(path), filename=path.name, file_hash=digest)
                    session.add(record)
                record.file_hash = digest
                record.file_size = st.st_size
                record.mtime_ns = st.st_mtime_ns
                record.ctime_ns = st.st_ctime_ns
                if outcome is not None:
                    record.scan_status = outcome.status.value
                    record.scan_result = outcome.raw
                    record.threat_name = outcome.threat_name
                    record.last_scanned = utcnow()
                    if outcome.status in (ScanStatus.CLEAN, ScanStatus.INFECTED):
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
