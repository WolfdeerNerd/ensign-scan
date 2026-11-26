"""Read-only reporting queries. Nothing in here mutates the database."""
from __future__ import annotations

import datetime
from collections import namedtuple
import os
import textwrap
from pathlib import Path

from rich import get_console, print
from rich.cells import cell_len
from rich.markup import escape
from sqlalchemy import func, or_
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from . import explanations, pkgdb
from .clamd import is_permission_error
from .commands import prefix
from .fsutil import human_size as _human_size, print_unwrapped, printable, shown
from .models import is_open_failed
from .models import FileRecord, ScanStatus, path_under


# Indent of a flagged file's details, under its "  File:" line.
_DETAIL = " " * 6


def _note(icon: str, text: str, label: str | None = None, indent: int = 2) -> None:
    """Print a dim, indented note whose wrapped lines hang under the text
    (not under the icon), so it can't visually run into the next entry.

    Wrapped here, at spaces only, rather than by a Rich table: a table pads
    every line with spaces out to its column width, and those come along
    when the text is copied."""
    body = f"{label}: {printable(text)}" if label else printable(text)
    lead = " " * indent
    hang = " " * (cell_len(icon) + 1)
    width = max(20, get_console().width - indent - len(hang))
    lines = textwrap.wrap(body, width, break_long_words=False, break_on_hyphens=False) or [""]
    for i, line in enumerate(lines):
        start = f"[dim]{escape(icon)}[/dim] " if i == 0 else hang
        get_console().print(f"{lead}{start}[dim]{escape(line)}[/dim]", soft_wrap=True)


def _file_facts(filepath: str, owner: bool = True) -> str:
    """One local line of context about a flagged file: does it still exist,
    how big, how old, and does a package own it. Everything here is a local
    stat or a read-only ownership query to the system's package manager
    (see pkgdb); nothing leaves the machine.

    owner=False leaves the package out, when the report already shows it
    from evidence.py, checked against this very content."""
    try:
        st = os.lstat(filepath)
    except OSError:
        return "no longer on disk (or not readable now)"
    modified = datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d")
    parts = [_human_size(st.st_size), f"modified {modified}"]
    if not owner:
        return " · ".join(parts)
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
    unopened: dict[str, list[str]] = {}
    for filepath, result in rows:
        if is_open_failed(result):
            unopened.setdefault(os.path.dirname(filepath), []).append(filepath)
        elif is_permission_error(result or ""):
            hotspots.setdefault(os.path.dirname(filepath), []).append(filepath)

    if unopened:
        _print_hotspots(
            f"FILES ENSIGN COULD NOT OPEN ({len(unopened)} directories)",
            ["The user running Ensign can't read these, so they were not scanned. Usually",
             "files owned by root (created with sudo, say) or by another user. Ensign",
             "doesn't suggest permission changes; it retries these on every run."],
            unopened, top)
    if not hotspots:
        return

    _print_hotspots(
        f"FILES CLAMD COULD NOT READ ({len(hotspots)} directories)",
        ["clamd was refused these files even though Ensign passed it an open handle.",
         "Usually AppArmor/SELinux confining clamd, or a clamd that can't receive",
         "open files (the run warns if so). Ensign doesn't suggest permission changes."],
        hotspots, top)


def _print_hotspots(title: str, intro: list[str], hotspots: dict[str, list[str]], top: int) -> None:
    """One suggest_fixes() section: directories with the most refused files first."""
    print(f"\n=== {title} ===")
    for line in intro:
        print(line)
    print()

    stale_only = 0
    for parent, files in sorted(hotspots.items(), key=lambda kv: -len(kv[1]))[:top]:
        present = [p for p in files if os.path.lexists(p)]
        count = len(files)
        label = f"{count} file" + ("s" if count != 1 else "")
        if not present:
            stale_only += 1
            print_unwrapped(f"  {shown(parent)}  ({label}, no longer on disk)")
        else:
            print_unwrapped(f"  {shown(parent)}  ({label})")
    print()
    if stale_only:
        print(f"Records for files that no longer exist: clear them with: {shown(prefix())} purge-missing")
    print(f"Once the cause is fixed, retry these with: {shown(prefix())} rescan-errors")


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
        print_unwrapped(f"  [yellow]![/yellow] {shown(change.path)}")
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
        print_unwrapped(f"  {count:>6}  {shown(parent)}")


def incomplete_report(engine: Engine, top: int = 10, paths: list[str] | None = None) -> None:
    """List files ClamAV could not fully scan, largest first, and say plainly
    what that means: they are tracked, but nothing vouches for their contents."""
    with Session(engine) as session:
        query = session.query(
            FileRecord.filepath, FileRecord.file_size, FileRecord.threat_name, FileRecord.scan_result
        ).filter(FileRecord.scan_status == ScanStatus.INCOMPLETE.value)
        scope = _scope_filter(paths)
        if scope is not None:
            query = query.filter(scope)
        rows = sorted(query.all(), key=lambda r: -(r[1] or 0))
    if not rows:
        return

    print(f"\n[bold yellow]=== NOT FULLY SCANNED ({len(rows)} files) ===[/bold yellow]")
    print("ClamAV did not check all of these files for malware, so Ensign does not call them "
          "clean. Most are over about 2 GiB, which no ClamAV tool can scan: a limit in ClamAV "
          "itself, not in Ensign or your settings. They are hashed and tracked, and one that "
          "changes is looked at again. Treat them as unverified, especially any you didn't "
          "create or download yourself.")
    swept = sum(1 for r in rows if (r[3] or "").startswith("swept: "))
    if swept:
        print(f"{swept} of them were swept in slices and nothing was found in their raw bytes, "
              f"which doesn't cover what's inside compressed archives.")
    elif any((r[2] or "").endswith("MaxFileSize") for r in rows):
        print("For files over 2 GiB, a sweep in slices can look for malware bytes in them. "
              "It's on by default; if you turned it off (sweep_huge_files = false), "
              "ensign-scan --sweep runs it once.")
    for filepath, size, reason, result in rows[:top]:
        why = reason or result or "unknown"
        if (result or "").startswith("swept: "):
            why = f"{why} · swept, nothing found in the raw bytes"
        print_unwrapped(f"  [yellow]~[/yellow] {shown(filepath)}")
        _note("↳", f"{_human_size(size or 0)} · {why}")
    if len(rows) > top:
        print(f"  … and {len(rows) - top} more")


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
        print_unwrapped(f"  {shown(path)}")
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
            print_unwrapped(f"    {shown(m.filepath)}")
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
        print_unwrapped(f"  {shown(top)}/…  {count}")


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
        for line in getattr(result, "unparsed", ())[:3]:
            print(f"    {shown(line)}")
        return
    unparsed_count = result.candidate_line_count - parsed
    if unparsed_count > 0:
        # Some lines were dropped: say so, and show them as printed, so a
        # finding the parser can't read is never just quietly missing.
        print(f"[yellow]! {unparsed_count} line{'s' if unparsed_count != 1 else ''} from {label} "
              f"couldn't be read by Ensign and {'are' if unparsed_count != 1 else 'is'} not in this "
              f"report. Run '{backend.verify_all_command.removeprefix('sudo ')}' to see "
              f"{'them' if unparsed_count != 1 else 'it'} in full.[/yellow]")
        for line in getattr(result, "unparsed", ())[:3]:
            print(f"    {shown(line)}")
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
            print_unwrapped(f"  {shown(package)}: {shown(filepath)}")
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
            print_unwrapped(f"  {shown(path)}  ({shown(', '.join(reasons))})")

    if excluded:
        _print_excluded(excluded)


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
    allowed = counts.get(ScanStatus.ALLOWED.value, 0)
    if allowed:
        print(f"○ Allowed by you: {allowed}")
    incomplete = counts.get(ScanStatus.INCOMPLETE.value, 0)
    if incomplete:
        print(f"[yellow]~ Not fully scanned: {incomplete}[/yellow]")

    return {"total": total, **{s.value: counts.get(s.value, 0) for s in ScanStatus}}


_InfectedRow = namedtuple("_InfectedRow", "filepath threat_name last_scanned scan_result file_hash id threat_engine last_error")


def list_infected(engine: Engine, paths: list[str] | None = None,
                  files_per_threat: int | None = 25, more_elsewhere: bool = False) -> list[dict]:
    """Print infected files grouped by threat name, so a signature that hits
    many files (a game's assets, say) is explained once, not once per file.
    Returns one dict per infected file, as before.

    more_elsewhere: infections were also found that couldn't be saved (see
    unsaved_report). Then "none found" would be false, so it isn't printed.

    files_per_threat: None lists every file (--list-infected)."""
    from .fpreport import _personal_folder  # fpreport pulls in diagnostics; only needed here
    with Session(engine) as session:
        query = session.query(
            FileRecord.filepath,
            FileRecord.threat_name,
            FileRecord.last_scanned,
            FileRecord.scan_result,
            FileRecord.file_hash,
        )
        # Infected, and also recorded as allowed with no allowance behind it
        # any more: that counts as infected (allowlist.orphaned), even before
        # the next run updates its record.
        # (Filtered here, not with "IN (...)": see allowlist.reconcile.)
        from .allowlist import orphaned
        stale = orphaned(engine)
        query = query.add_columns(FileRecord.id, FileRecord.threat_engine, FileRecord.last_error,
                                  FileRecord.scan_status).filter(
            FileRecord.scan_status.in_((ScanStatus.INFECTED.value, ScanStatus.ALLOWED.value)))
        scope = _scope_filter(paths)
        if scope is not None:
            query = query.filter(scope)
        rows = [_InfectedRow(*row[:8]) for row in query.all()
                if row.scan_status == ScanStatus.INFECTED.value or row.id in stale]
        # Second opinions (evidence.py), only for the content they were checked against.
        from . import evidence
        facts = evidence.for_files(session, {row.id: row.file_hash for row in rows})

    if not rows:
        if not more_elsewhere:
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
        for i, (filepath, _t, scanned, detail, digest, file_id, found_by, failed) in enumerate(group):
            if files_per_threat is None or i < files_per_threat:
                # Each file is its own block: the path, then its details
                # indented under it, so a long list reads down the paths.
                print_unwrapped(f"\n  File: {shown(filepath)}")
                print(f"{_DETAIL}Scanned: {scanned} UTC")
                print_unwrapped(f"{_DETAIL}Details: {shown((detail or '')[:200])}")
                if failed:
                    _note("!", f"Couldn't be checked again ({failed[-160:]}). This is the "
                          f"earlier verdict; the next run tries again.", label="Last check",
                          indent=len(_DETAIL))
                if found_by:
                    from .allowlist import engine_label
                    print(f"{_DETAIL}Found by: {shown(engine_label(found_by))}")
                file_facts = facts.get(file_id, [])
                has_package = any(f.source == evidence.SOURCE_PACKAGE for f in file_facts)
                _note("›", _file_facts(filepath, owner=not has_package), label="Context",
                      indent=len(_DETAIL))
                for fact in file_facts:
                    _note("›", evidence.describe(fact, threat), label=evidence.label(fact, threat),
                          indent=len(_DETAIL))
                # The hash of the content that was flagged: paste it into
                # VirusTotal's search. A lookup sends only the hash, which
                # can't be turned back into the file; uploading sends the file.
                print(f"{_DETAIL}SHA-256: {digest}")
                if _personal_folder(Path(filepath)):
                    _note("›", "In a personal folder: look up the hash, don't upload the file.",
                          indent=len(_DETAIL))
            elif i == files_per_threat:
                print(f"\n  … and {len(group) - files_per_threat} more files with this "
                      f"threat (all are recorded in the database)")
            results.append({"filepath": filepath, "threat": threat, "scanned": scanned})
        print()
        _note("›", f"Think it's a false positive? {prefix()} report PATH checks the file "
              "again and prepares a report for ClamAV (nothing is sent for you).", indent=len(_DETAIL))
    return results


def format_mismatch_report(engine: Engine, paths: list[str] | None = None) -> int:
    """Print files named like a credential format (a .kdbx, a .ppk, an SSH
    key...) whose first bytes say they aren't one. Returns how many.

    A borrowed name is how a payload hides (MITRE ATT&CK T1036.008): before
    0.8.6 these names weren't even opened. clamd's verdict is shown with
    each, since it's still the verdict; this is a reason to look closer,
    not a detection. Every run lists them, until the file changes."""
    with Session(engine) as session:
        query = session.query(
            FileRecord.filepath, FileRecord.format_mismatch, FileRecord.scan_status, FileRecord.file_hash,
        ).filter(FileRecord.format_mismatch.isnot(None))
        scope = _scope_filter(paths)
        if scope is not None:
            query = query.filter(scope)
        rows = sorted(query.all())
    if not rows:
        return 0
    print(f"\n=== NAMED LIKE A CREDENTIAL FILE, BUT ISN'T ONE ({len(rows)} "
          f"file{'s' if len(rows) != 1 else ''}) ===")
    print("Each file below has the name of a credential format (a password vault, a key, a\n"
          "browser's password store) but doesn't start the way that format always does.\n"
          "Malware borrows names like these to look harmless. Check where each came from;\n"
          "if you know it, it may just be misnamed.")
    for filepath, why, status, digest in rows:
        print_unwrapped(f"\n  File: {shown(filepath)}")
        print_unwrapped(f"{_DETAIL}Why: {shown(why)}")
        print(f"{_DETAIL}clamd's verdict: {status}")
        _note("›", _file_facts(filepath), label="Context", indent=len(_DETAIL))
        if digest:
            print(f"{_DETAIL}SHA-256: {digest}")
    return len(rows)


def unsaved_report(unsaved) -> list[dict]:
    """Results Ensign got but couldn't save (scanner.UnsavedResult).

    Printed loudly, infections first, because nothing else in the run's
    output knows about them: every other report reads the database. Returns
    the infected ones in list_infected()'s shape, for the alert.
    """
    if not unsaved:
        return []
    by_path = {u.path: u for u in unsaved}  # a file reached twice is listed once
    items = sorted(by_path.values(), key=lambda u: (u.status != ScanStatus.INFECTED.value, u.path))
    infected = [u for u in items if u.status == ScanStatus.INFECTED.value]

    n = len(items)
    colour = "red" if infected else "yellow"
    print(f"\n[{colour}]=== {n} FILE{'S' if n != 1 else ''} SCANNED BUT NOT SAVED ===[/{colour}]")
    print("  Ensign's database refused these results, so they aren't counted in the summary "
          "above and will be scanned again next run.")
    if infected:
        print(f"[bold red]  {len(infected)} of them {'is' if len(infected) == 1 else 'are'} "
              f"INFECTED:[/bold red]")
    results = []
    for u in items:
        if u.status == ScanStatus.INFECTED.value:
            print(f"\n  [bold red]! {shown(u.threat_name)}[/bold red]")
            print_unwrapped(f"  File: {shown(u.path)}")
            _note("›", _file_facts(u.path), label="Context", indent=len(_DETAIL))
            results.append({"filepath": u.path, "threat": u.threat_name, "scanned": None})
        else:
            print_unwrapped(f"  {shown(u.status)}: {shown(u.path)}")
    print(f"  Reason: {shown(items[0].error)}")
    return results
