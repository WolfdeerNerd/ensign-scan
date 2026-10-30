"""Read-only reporting queries. Nothing in here mutates the database."""
from __future__ import annotations

import datetime
import os

from rich import print
from rich.markup import escape
from rich.padding import Padding
from rich.table import Table
from sqlalchemy import func, or_
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from . import explanations, pacman, secrets
from .models import FileRecord, ScanStatus


def _note(icon: str, text: str, label: str | None = None, indent: int = 2) -> None:
    """Print a dim, indented note whose wrapped lines hang under the text
    (not under the icon), so it can't visually run into the next entry."""
    grid = Table.grid(padding=(0, 1))
    grid.add_column(no_wrap=True)
    grid.add_column()
    body = f"{label}: {escape(text)}" if label else escape(text)
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
    how big, how old, and does a pacman package own it. Everything here is
    a local stat or a read-only `pacman -Qo`; nothing leaves the machine."""
    try:
        st = os.lstat(filepath)
    except OSError:
        return "no longer on disk (or not readable now)"
    modified = datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d")
    parts = [_human_size(st.st_size), f"modified {modified}"]
    state, pkg = pacman.owner(filepath)
    if state == "owned":
        name = pkg.split()[0]
        parts.append(f"owned by package {pkg} (check it with: pacman -Qkk {name})")
    elif state == "unowned":
        parts.append("not owned by any pacman package")
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
        conditions.append(FileRecord.filepath.like(f"{text}/%"))
    return or_(*conditions)


def _secrets_beneath(parent: str, sensitive_paths: list[str]) -> str | None:
    """First path in `sensitive_paths` that lies anywhere under `parent`
    (any depth), returned relative to `parent`; None if there isn't one.

    Matches on `parent + "/"` as a whole prefix, so /data/pb2/x is not
    "under" /data/pb -- a bare startswith(parent) would say it was.
    """
    prefix = parent.rstrip("/") + "/"
    for path in sensitive_paths:
        if path.startswith(prefix):
            return path[len(prefix):]
    return None


def suggest_fixes(engine: Engine, top: int = 10, paths: list[str] | None = None) -> None:
    """Print copy-pasteable setfacl commands for permission error hotspots.

    Purely advisory — nothing here runs a permission change. Directories
    are flagged for manual review instead of getting a suggested command
    if EITHER the directory name OR any file beneath it, at any depth,
    matches a secrets pattern — checking only the directory name would
    miss a wallet file sitting in a generically-named folder, and
    checking only the files that errored would miss one that was already
    reclassified, or that sits in a subdirectory: the suggested
    `setfacl -R` recurses through the whole subtree, and its `-d` form
    is inherited by anything created there later. Dotfiles (like .netrc)
    living loose in $HOME are covered the same way, since their
    "directory" is just the home folder itself.

    If `paths` is given, only hotspots under those paths are reported —
    otherwise this reports on every error in the whole database,
    regardless of what this particular run scanned. That scope picks
    which hotspots to report; it deliberately does NOT narrow the
    secrets check above, because the command would still touch
    everything beneath the directory.
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
        text = (result or "").lower()
        if "denied" in text or "permission" in text:
            parent = os.path.dirname(filepath)
            hotspots.setdefault(parent, []).append(filepath)

    if not hotspots:
        return

    # Every ERROR/CLASSIFIED record that looks like a secrets store,
    # loaded once and unscoped (see the docstring). These are the files
    # clamd currently can't read -- the ones a recursive grant would newly
    # expose. Filtered in Python with an exact prefix match rather than
    # SQL LIKE, where '_' and '%' in a directory name act as wildcards.
    # Stale records are kept on purpose: with the -d default ACL, a
    # deleted wallet that gets recreated would inherit the grant.
    with Session(engine) as session:
        guard_rows = session.query(FileRecord.filepath).filter(
            FileRecord.scan_status.in_([ScanStatus.ERROR.value, ScanStatus.CLASSIFIED.value])
        ).all()
    sensitive_paths = sorted(p for (p,) in guard_rows if secrets.is_likely_secrets_path(p))

    print(f"\n=== SUGGESTED FIXES ({len(hotspots)} directories) ===")
    print("Advisory only — review each command before running it.\n")

    for parent, paths in sorted(hotspots.items(), key=lambda kv: -len(kv[1]))[:top]:
        missing = [p for p in  paths if not os.path.lexists(p)]
        present = [p for p in paths if p not in missing]

        if missing and not present:
            # Every file in this hotspot is gone -- a setfacl fix would
            # be useless advice. Point at --purge-missing instead.
            count = len(missing)
            label = f"{count} file" + ("s" if count != 1 else "")
            print(f"    {parent} ({label})")
            print(f"        File{'s' if count != 1 else ''} no longer ")
            print(f"        exist{'s' if count == 1 else ''} on disk - this looks like ")
            print(f"        a stale record, not a permission issue.")
            print(f"        Run: python3 main.py --purge-missing\n")
            continue

        count = len(paths)
        label = f"{count} file" + ("s" if count != 1 else "")
        dir_match = secrets.is_likely_secrets_path(parent)
        beneath = None if dir_match else _secrets_beneath(parent, sensitive_paths)
        if dir_match or beneath:
            print(f"  [yellow]! {parent}[/yellow]  ({label})")
            reason = "directory name" if dir_match else f"contains {beneath}"
            print(f"    Looks like a secrets/credentials store ({reason}) — review manually.\n")
        else:
            print(f"  {parent}  ({label})")
            print(f"    sudo setfacl -R -m g:clamav:rX '{parent}'")
            print(f"    sudo setfacl -R -d -m g:clamav:rX '{parent}'\n")


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
        print(f"  {count:>6}  {message[:90]}")
    print("Directory hotspots:")
    for parent, count in sorted(dirs.items(), key=lambda kv: -kv[1])[:top]:
        print(f"  {count:>6}  {parent}")


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

    shown: list[str] = []
    for path in sorted(unreadable):
        if not any(path.startswith(kept.rstrip("/") + "/") for kept in shown):
            shown.append(path)

    print(f"\n=== UNREADABLE DIRECTORIES ({len(shown)}) ===")
    print("Ensign could not look inside these, so nothing in them was scanned.")
    for path in shown[:top]:
        print(f"  {escape(path)}")
        print(f"    {unreadable[path]}")
    if len(shown) > top:
        print(f"  … and {len(shown) - top} more (all are in the error log)")


def _print_unverified(unverified) -> None:
    """Files pacman could not read. These were never compared against the
    package, so they are NOT mismatches -- reported separately, grouped by
    package so a root-only package doesn't bury the real findings."""
    n = len(unverified)
    print(f"\n-- {n} file{'s' if n != 1 else ''} pacman could not verify (not mismatches) --")
    if os.geteuid() == 0:
        print("  pacman could not read these even as root; the files may be missing or damaged.")
    else:
        print("  pacman wasn't run as root, so root-only files could not be opened. To check "
              "them, run: sudo pacman -Qkk")
    by_pkg: dict[str, list] = {}
    for m in unverified:
        by_pkg.setdefault(m.package, []).append(m)
    for pkg, items in sorted(by_pkg.items()):
        reasons = sorted({m.reason for m in items})
        print(f"  {escape(pkg)}: {len(items)} file{'s' if len(items) != 1 else ''} "
              f"({escape(', '.join(reasons))})")
        for m in items[:3]:
            print(f"    {escape(m.filepath)}")
        if len(items) > 3:
            print(f"    … and {len(items) - 3} more")
    for reason in sorted({m.reason for m in unverified}):
        note = explanations.explain_pacman_reason(reason)
        if note:
            _note("ⓘ", f"{reason}: {note}")


def pacman_report(engine: Engine, result) -> None:
    """Print pacman -Qkk mismatches, cross-referenced against Ensign's
    own tracked files where possible. Purely informational."""
    if result is None:
        print("[yellow]pacman is not installed on this system — skipping.[/yellow]")
        return
    if result.error:
        print(f"[red]✗ pacman verification failed: {result.error}[/red]")
        return

    print(f"\n=== PACMAN FILE INTEGRITY ({len(result.mismatches)} of {result.candidate_line_count} candidate lines parsed) ===")
    if result.candidate_line_count and not result.mismatches:
        print("[yellow]! pacman reported mismatch-shaped lines but none matched the expected "
              "format — the parser may need updating for this pacman version. Run 'pacman -Qkk' "
              "directly to see the raw output.[/yellow]")
        return
    if not result.mismatches:
        print("No mismatches — all installed files match pacman's records.")
        return

    with Session(engine) as session:
        known = {
            row[0]: row[1]
            for row in session.query(FileRecord.filepath, FileRecord.scan_status)
        }

    unverified = [m for m in result.mismatches if m.unverified and not m.is_backup]
    real = [m for m in result.mismatches if not m.is_backup and not m.unverified]
    backups = [m for m in result.mismatches if m.is_backup]

    if real:
        print(f"\n-- {len(real)} file{'s' if len(real) != 1 else ''} differ from pacman's records --")
        for m in real:
            status = known.get(m.filepath)
            tracked = f"Ensign last saw this file: {status}" if status else "not tracked by Ensign"
            print(f"  {escape(m.package)}: {escape(m.filepath)}")
            print(f"    {escape(m.reason)} — {tracked}")
            reason_note = explanations.explain_pacman_reason(m.reason)
            if reason_note:
                _note("ⓘ", reason_note, indent=4)
    elif unverified:
        print("\nNo files differ from pacman's records.")

    if unverified:
        _print_unverified(unverified)

    if backups:
        # pacman marks these files "backup" specifically so it won't
        # complain when you edit them -- a mismatch here means "you
        # configured your system," not "something is wrong."
        print(f"\n-- {len(backups)} backup/config file{'s' if len(backups) != 1 else ''} "
              f"locally modified (expected, not a concern) --")
        by_path: dict[str, list[str]] = {}
        for m in backups:
            by_path.setdefault(m.filepath, []).append(m.reason)
        for path, reasons in by_path.items():
            print(f"  {path}  ({', '.join(reasons)})")


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
        print(f"\nThreat: {escape(str(threat))}  ({count})")
        explanation = explanations.explain_threat(threat)
        if explanation:
            _note("ⓘ", explanation.description)
            if explanation.false_positive_note:
                label = "Hint" if explanation.decoded else "Known false positive"
                _note("›", explanation.false_positive_note, label=label)
        for i, (filepath, _t, scanned, detail) in enumerate(group):
            if i < files_per_threat:
                print(f"\n  File: {escape(filepath)}")
                print(f"  Scanned: {scanned}")
                print(f"  Details: {escape((detail or '')[:200])}")
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
            print(f"File not found in database: {filepath}")
            return
        print("\n=== FILE INFO ===")
        print(f"Path: {record.filepath}")
        print(f"Hash: {record.file_hash}")
        print(f"Size: {record.file_size} bytes")
        print(f"Scan Status: {record.scan_status}")
        if record.threat_name:
            print(f"Threat: {record.threat_name}")
        print(f"Last Scanned: {record.last_scanned}")
