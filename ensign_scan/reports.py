"""Read-only reporting queries. Nothing in here mutates the database."""
from __future__ import annotations

import datetime
import os

from rich import print
from rich.padding import Padding
from rich.table import Table
from sqlalchemy import func, or_
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from . import explanations, pkgdb
from .clamd import is_permission_error
from .fsutil import shown
from .models import FileRecord, ScanStatus, path_under


def _note(icon: str, text: str, label: str | None = None, indent: int = 2) -> None:
    """Print a dim, indented note whose wrapped lines hang under the text
    (not under the icon), so it can't visually run into the next entry."""
    grid = Table.grid(padding=(0, 1))
    grid.add_column(no_wrap=True)
    grid.add_column()
    body = f"{label}: {shown(text)}" if label else shown(text)
    grid.add_row(f"[dim]{icon}[/dim]", f"[dim]{body}[/dim]")
    print(Padding(grid, (0, 0, 0, indent)))


def _human_size(n: int) -> str:
    size = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"


def _file_facts(filepath: str) -> str:
    """One local line of context about a flagged file: does it still exist,
    how big, how old, and does a package own it. Everything here is a local
    stat or a read-only ownership query to the system's package manager
    (see pkgdb); nothing leaves the machine."""
    try:
        st = os.lstat(filepath)
    except OSError:
        return "no longer on disk (or not readable now)"
    modified = datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d")
    parts = [_human_size(st.st_size), f"modified {modified}"]
    backend = pkgdb.active()
    state, pkg = backend.owner(filepath)
    if state == "owned":
        hint = backend.verify_command(pkg.split()[0])
        parts.append(f"owned by package {pkg}" + (f" (check it with: {hint})" if hint else ""))
    elif state == "unowned":
        parts.append(f"not owned by any {backend.label} package")
    return " · ".join(parts)


def _scope_filter(paths: list[str] | None):
    """Restrict a query to files under the given paths, or None for no
    restriction. Each path can be a directory (matches everything under
    it) or an exact file. Used so a run scoped to specific targets
    reports on just those targets, not the entire tracked system."""
    if not paths:
        return None
    conditions = []
    for p in paths:
        text = str(p).rstrip("/")
        conditions.append(FileRecord.filepath == text)
        conditions.append(path_under(FileRecord.filepath, text))
    return or_(*conditions)


def suggest_fixes(engine: Engine, top: int = 10, paths: list[str] | None = None) -> None:
    """Report files clamd was refused, grouped by directory. Advisory only.

    Ensign passes clamd an open descriptor for each file (see clamd.py),
    so clamd needs no permission on your files, and a permission-denied
    result should be rare. When one does show up, the cause is almost
    always outside Ensign's reach:

      * AppArmor/SELinux confining clamd: a policy can refuse even a
        descriptor that was handed to it.
      * a clamd without FILDES, so Ensign fell back to path scanning and
        clamd had to open files itself (the run warns about this).
      * rows from before this version, not yet retried.

    This no longer prints setfacl commands. A recursive grant gave the
    clamav user standing read access to everything under a directory --
    including excluded trees, directories Ensign couldn't list, and files
    created later -- and no check could see all of that ahead of time.
    Records whose files are gone are pointed at --purge-missing instead.

    If `paths` is given, only files under those paths are reported.
    """
    with Session(engine) as session:
        query = session.query(FileRecord.filepath, FileRecord.scan_result).filter(
            FileRecord.scan_status == ScanStatus.ERROR.value
        )
        scope = _scope_filter(paths)
        if scope is not None:
            query = query.filter(scope)
        rows = query.all()

    hotspots: dict[str, list[str]] = {}
    for filepath, result in rows:
        if is_permission_error(result or ""):
            hotspots.setdefault(os.path.dirname(filepath), []).append(filepath)

    if not hotspots:
        return

    print(f"\n=== FILES CLAMD COULD NOT READ ({len(hotspots)} directories) ===")
    print("clamd was refused these files even though Ensign passed it an open handle.")
    print("Usually AppArmor/SELinux confining clamd, or a clamd that can't receive")
    print("open files (the run warns if so). Ensign doesn't suggest permission changes.\n")

    stale_only = 0
    for parent, files in sorted(hotspots.items(), key=lambda kv: -len(kv[1]))[:top]:
        present = [p for p in files if os.path.lexists(p)]
        count = len(files)
        label = f"{count} file" + ("s" if count != 1 else "")
        if not present:
            stale_only += 1
            print(f"  {shown(parent)}  ({label}, no longer on disk)")
        else:
            print(f"  {shown(parent)}  ({label})")
    print()
    if stale_only:
        print("Records for files that no longer exist: clear them with --purge-missing.")
    print("Once the cause is fixed, retry these with: --rescan-errors")


def integrity_report(changes) -> None:
    """Print SSH files (authorized_keys, ~/.ssh/config, ~/.ssh/rc) whose
    contents changed, or that appeared, since the last run. `changes` is
    Scanner.integrity_changes.

    These aren't malware signatures; they're the places an intruder edits
    to get back in (an added key) or to run code (a ProxyCommand, an rc
    script). A change you made yourself is expected -- this just makes
    sure no change goes unnoticed.
    """
    if not changes:
        return
    print(f"\n[bold yellow]=== SSH FILES CHANGED SINCE LAST RUN ({len(changes)}) ===[/bold yellow]")
    print("If you didn't make these changes, inspect them now.\n")
    for change in sorted(changes, key=lambda c: c.path):
        print(f"  [yellow]![/yellow] {shown(change.path)}")
        if change.old_hash:
            print(f"      was {change.old_hash[:16]}…  now {change.new_hash[:16]}…")
        else:
            print(f"      new file since the last run ({change.new_hash[:16]}…)")


def error_summary(engine: Engine, top: int = 10, paths: list[str] | None = None) -> None:
    """Group ERROR files by cause and by directory hotspot.

    Thousands of individual error rows are unreadable; almost all of
    them collapse into a handful of causes (usually clamd permission
    denials) concentrated in a few directory trees.

    If `paths` is given, only errors under those paths are counted.
    """
    with Session(engine) as session:
        query = session.query(
            FileRecord.filepath, FileRecord.scan_result
        ).filter(FileRecord.scan_status == ScanStatus.ERROR.value)
        scope = _scope_filter(paths)
        if scope is not None:
            query = query.filter(scope)
        rows = query.all()

    if not rows:
        return

    causes: dict[str, int] = {}
    dirs: dict[str, int] = {}
    for filepath, result in rows:
        # clamd replies look like "/path: message ERROR" — strip the
        # path so identical causes group together.
        raw = result or "unknown"
        message = raw.split(": ", 1)[1] if ": " in raw else raw
        causes[message] = causes.get(message, 0) + 1
        parent = os.path.dirname(filepath)
        dirs[parent] = dirs.get(parent, 0) + 1

    print(f"\n=== ERROR BREAKDOWN ({len(rows)} files) ===")
    print("By cause:")
    for message, count in sorted(causes.items(), key=lambda kv: -kv[1])[:top]:
        print(f"  {count:>6}  {shown(message[:90])}")
    print("Directory hotspots:")
    for parent, count in sorted(dirs.items(), key=lambda kv: -kv[1])[:top]:
        print(f"  {count:>6}  {shown(parent)}")


def unreadable_report(unreadable: dict[str, str], top: int = 10) -> None:
    """Print the directories Ensign could not look inside during this run.

    These are blind spots, not errors on a file: nothing under them was
    hashed or scanned. Unlike the other reports this isn't a database
    query -- the walk retries every directory on every run, so the list
    is rebuilt each time and there's nothing to store.

    A path with a listed ancestor is dropped: the ancestor already
    explains why it was never reached. (A directory that can be listed
    but not entered fails again one level down, for instance.)
    """
    if not unreadable:
        return

    listed: list[str] = []
    for path in sorted(unreadable):
        if not any(path.startswith(kept.rstrip("/") + "/") for kept in listed):
            listed.append(path)

    print(f"\n=== UNREADABLE DIRECTORIES ({len(listed)}) ===")
    print("Ensign could not look inside these, so nothing in them was scanned.")
    for path in listed[:top]:
        print(f"  {shown(path)}")
        print(f"    {shown(unreadable[path])}")
    if len(listed) > top:
        print(f"  … and {len(listed) - top} more (all are in the error log)")


def _print_unverified(unverified, backend) -> None:
    """Files the package manager could not read. These were never compared
    against the package, so they are NOT mismatches -- reported separately,
    grouped by package so a root-only package doesn't bury the real findings."""
    n = len({m.filepath for m in unverified})
    label = backend.label
    print(f"\n-- {n} file{'s' if n != 1 else ''} {label} could not verify (not mismatches) --")
    if os.geteuid() == 0:
        print(f"  {label} could not read these even as root; the files may be missing or damaged.")
    else:
        print(f"  {label} wasn't run as root, so root-only files could not be opened. To check "
              f"them, run: {backend.verify_all_command}")
    by_pkg: dict[str, list] = {}
    for m in unverified:
        by_pkg.setdefault(m.package, []).append(m)
    for pkg, items in sorted(by_pkg.items()):
        reasons = sorted({m.reason for m in items})
        print(f"  {shown(pkg)}: {len(items)} file{'s' if len(items) != 1 else ''} "
              f"({shown(', '.join(reasons))})")
        for m in items[:3]:
            print(f"    {shown(m.filepath)}")
        if len(items) > 3:
            print(f"    … and {len(items) - 3} more")
    for reason in sorted({m.reason for m in unverified}):
        note = backend.explain_reason(reason)
        if note:
            _note("ⓘ", f"{reason}: {note}")


def _print_excluded(excluded) -> None:
    """Files the system's own settings told the package manager not to
    install (dpkg path-exclude: minimal and container installs drop docs,
    man pages and translations this way). Expected, so shown as a count
    with the biggest folders, not one line per file."""
    paths = sorted({m.filepath for m in excluded})
    print(f"\n-- {len(paths)} file{'s' if len(paths) != 1 else ''} left out on purpose by this "
          f"system's path-exclude settings (expected, not a concern) --")
    by_dir: dict[str, int] = {}
    for path in paths:
        top = "/".join(path.split("/")[:4]) or path  # e.g. /usr/share/doc
        by_dir[top] = by_dir.get(top, 0) + 1
    for top, count in sorted(by_dir.items(), key=lambda kv: -kv[1])[:5]:
        print(f"  {shown(top)}/…  {count}")


def package_report(engine: Engine, result, backend) -> None:
    """Print a package manager's verify results, cross-referenced against
    Ensign's own tracked files where possible. Purely informational.

    `result` is a pkgdb VerifyResult (or pacman's equivalent); `backend`
    supplies the wording, so the same report serves pacman, dpkg and rpm.
    """
    label = backend.label
    if result is None:
        print(f"[yellow]{label} is not installed on this system — skipping.[/yellow]")
        return
    if result.error:
        print(f"[red]✗ {label} verification failed: {result.error}[/red]")
        return

    # pacman prints one line per mismatch; dpkg and rpm one line per file,
    # which can hold several. Count lines either way.
    parsed = getattr(result, "parsed_line_count", 0) or len(result.mismatches)
    print(f"\n=== {label.upper()} FILE INTEGRITY ({parsed} of "
          f"{result.candidate_line_count} candidate lines parsed) ===")
    if result.candidate_line_count and not result.mismatches:
        print(f"[yellow]! {label} reported mismatch-shaped lines but none matched the expected "
              f"format — the parser may need updating for this {label} version. Run "
              f"'{backend.verify_all_command.removeprefix('sudo ')}' directly to see the raw "
              f"output.[/yellow]")
        return
    if not result.mismatches:
        print(f"No mismatches — all installed files match {label}'s records.")
        return

    with Session(engine) as session:
        known = {
            row[0]: row[1]
            for row in session.query(FileRecord.filepath, FileRecord.scan_status)
        }

    excluded = [m for m in result.mismatches if m.excluded]
    rest = [m for m in result.mismatches if not m.excluded]
    # Couldn't-read beats is-a-config-file: an unread /etc/sudoers was never
    # compared, so it can't count as "edited on purpose".
    unverified = [m for m in rest if m.unverified]
    real = [m for m in rest if not m.is_config and not m.unverified]
    configs = [m for m in rest if m.is_config and not m.unverified]

    if real:
        # One heading per file, then each way it differs: a file with a
        # size AND a checksum change is one file, not two.
        by_file: dict[tuple[str, str], list[str]] = {}
        for m in real:
            by_file.setdefault((m.package, m.filepath), []).append(m.reason)
        n = len(by_file)
        print(f"\n-- {n} file{'s' if n != 1 else ''} differ{'s' if n == 1 else ''} from {label}'s records --")
        for (package, filepath), reasons in by_file.items():
            status = known.get(filepath)
            tracked = f"Ensign last saw this file: {status}" if status else "not tracked by Ensign"
            print(f"  {shown(package)}: {shown(filepath)}")
            for reason in reasons:
                print(f"    {shown(reason)} — {tracked}")
                reason_note = backend.explain_reason(reason)
                if reason_note:
                    _note("ⓘ", reason_note, indent=4)
    elif unverified or excluded:
        print(f"\nNo files differ from {label}'s records.")

    if unverified:
        _print_unverified(unverified, backend)

    if configs:
        # Package managers mark these files as configuration specifically so
        # they won't complain when you edit them -- a mismatch here means
        # "you configured your system," not "something is wrong."
        by_path: dict[str, list[str]] = {}
        for m in configs:
            by_path.setdefault(m.filepath, []).append(m.reason)
        n = len(by_path)
        print(f"\n-- {n} {backend.config_word} file{'s' if n != 1 else ''} "
              f"locally modified (expected, not a concern) --")
        for path, reasons in by_path.items():
            print(f"  {shown(path)}  ({shown(', '.join(reasons))})")

    if excluded:
        _print_excluded(excluded)


def pacman_report(engine: Engine, result) -> None:
    """The pacman report. Kept under its old name for existing callers."""
    from .pkgdb.pacman import PacmanBackend
    package_report(engine, result, PacmanBackend())


def scan_summary(engine: Engine, paths: list[str] | None = None) -> dict[str, int]:
    """If `paths` is given, only files under those paths are counted —
    otherwise this summarizes the entire database."""
    scope = _scope_filter(paths)
    with Session(engine) as session:
        total_q = session.query(func.count(FileRecord.id))
        status_q = session.query(FileRecord.scan_status, func.count(FileRecord.id)).group_by(FileRecord.scan_status)
        if scope is not None:
            total_q = total_q.filter(scope)
            status_q = status_q.filter(scope)
        total = total_q.scalar() or 0
        rows = status_q.all()
    counts = dict(rows)

    print("\n=== SCAN SUMMARY ===")
    print(f"Total files:     {total}")
    print(f"✓ Clean:         {counts.get(ScanStatus.CLEAN.value, 0)}")
    print(f"! Infected:      {counts.get(ScanStatus.INFECTED.value, 0)}")
    print(f"✗ Errors:        {counts.get(ScanStatus.ERROR.value, 0)}")
    print(f"? Pending:       {counts.get(ScanStatus.PENDING.value, 0)}")
    print(f"• Classified:    {counts.get(ScanStatus.CLASSIFIED.value, 0)}")

    return {"total": total, **{s.value: counts.get(s.value, 0) for s in ScanStatus}}


def list_infected(engine: Engine, paths: list[str] | None = None,
                  files_per_threat: int = 25) -> list[dict]:
    """Print infected files grouped by threat name, so a signature that hits
    many files (a game's assets, say) is explained once, not once per file.
    Returns one dict per infected file, as before."""
    with Session(engine) as session:
        query = session.query(
            FileRecord.filepath,
            FileRecord.threat_name,
            FileRecord.last_scanned,
            FileRecord.scan_result,
        ).filter(FileRecord.scan_status == ScanStatus.INFECTED.value)
        scope = _scope_filter(paths)
        if scope is not None:
            query = query.filter(scope)
        rows = query.all()

    if not rows:
        print("No infected files found")
        return []

    groups: dict[str | None, list] = {}
    for row in rows:
        groups.setdefault(row.threat_name, []).append(row)
    ordered = sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0] or ""))

    print(f"\n=== INFECTED FILES ({len(rows)} files, {len(groups)} "
          f"{'threat' if len(groups) == 1 else 'threats'}) ===")
    results = []
    for threat, group in ordered:
        group.sort(key=lambda r: r.filepath)
        count = f"{len(group)} file{'s' if len(group) != 1 else ''}"
        print(f"\nThreat: {shown(str(threat))}  ({count})")
        explanation = explanations.explain_threat(threat)
        if explanation:
            _note("ⓘ", explanation.description)
            if explanation.false_positive_note:
                label = "Hint" if explanation.decoded else "Known false positive"
                _note("›", explanation.false_positive_note, label=label)
        for i, (filepath, _t, scanned, detail) in enumerate(group):
            if i < files_per_threat:
                print(f"\n  File: {shown(filepath)}")
                print(f"  Scanned: {scanned}")
                print(f"  Details: {shown((detail or '')[:200])}")
                _note("›", _file_facts(filepath), label="Context", indent=2)
            elif i == files_per_threat:
                print(f"\n  … and {len(group) - files_per_threat} more files with this "
                      f"threat (all are recorded in the database)")
            results.append({"filepath": filepath, "threat": threat, "scanned": scanned})
    return results


def file_info(engine: Engine, filepath: str) -> None:
    with Session(engine) as session:
        record = session.query(FileRecord).filter(
            FileRecord.filepath == filepath
        ).first()
        if record is None:
            print(f"File not found in database: {shown(filepath)}")
            return
        print("\n=== FILE INFO ===")
        print(f"Path: {shown(record.filepath)}")
        print(f"Hash: {record.file_hash}")
        print(f"Size: {record.file_size} bytes")
        print(f"Scan Status: {record.scan_status}")
        if record.threat_name:
            print(f"Threat: {shown(record.threat_name)}")
        print(f"Last Scanned: {record.last_scanned}")
