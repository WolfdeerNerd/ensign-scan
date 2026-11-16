"""Allowed by you: false positives you have told Ensign to stop flagging.

ClamAV sometimes flags a harmless file. Once you have checked one and are
sure, `ensign-scan --allow PATH` records it as allowed. That is your
judgment, not Ensign's or ClamAV's, so it is kept narrow and in plain view:

- It covers one exact content (the file's SHA-256) flagged by one exact
  signature name. If the file changes, or a different signature hits it,
  it is flagged again. An identical copy elsewhere is covered, since it is
  the same bytes and the same false positive.
- Allowed files are listed in their own section at the end of every run,
  and with --list-allowed. They are never hidden.
- They don't count as infected for alerts or the exit code.
- They are still rescanned when the signatures update, so a false positive
  ClamAV has since fixed simply turns clean.
- --unallow PATH undoes it.

--allow-folder FOLDER --signature NAME does the same for every file under
a folder that one signature flags right now: one confirmation instead of
hundreds. It is a snapshot, with no standing rule for the folder. Each file
gets the allowance above, tied to its own content, so a file that appears
or changes later is flagged again, and the run prints the commands to
allow it once you've checked it. Formats that can run code when a program
loads them (LOADS_CODE_EXTENSIONS) are left out and need their own --allow.

Everything stays in Ensign's own database. ClamAV and its signatures are
not touched, so nothing else using clamd is affected (unlike ClamAV's own
.sfp/.ign2 allow lists, which apply to every program using clamd).
"""
from __future__ import annotations

import os
import shlex
from dataclasses import dataclass
from pathlib import Path

from rich import print
from sqlalchemy import or_
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from .fsutil import open_for_scan, print_unwrapped, sha256_fd, shown
from .models import AllowedFolder, Allowance, FileRecord, ScanStatus, path_under, utcnow

# File formats that can run code the moment a program loads them: Python
# pickles, and the model checkpoints and saved objects built on pickle.
# --allow-folder never includes these. A signature hit on text is usually
# harmless, the same hit on one of these may not be, and in a batch of
# hundreds of files one of them is easy to miss. Each needs its own
# --allow PATH, where it is the only file on screen.
LOADS_CODE_EXTENSIONS = frozenset({".pkl", ".pickle", ".pt", ".pth", ".ckpt", ".bin", ".joblib"})


def loads_code(path: str) -> bool:
    return os.path.splitext(path)[1].lower() in LOADS_CODE_EXTENSIONS


def allowed_pairs(engine: Engine) -> set[tuple[str, str]]:
    """Every (SHA-256, signature name) you have allowed."""
    with Session(engine) as session:
        return {(h, t) for h, t in session.query(Allowance.file_hash, Allowance.threat_name)}


@dataclass
class _Candidate:
    path: str
    digest: str
    threat: str


def _candidate(engine: Engine, path: str) -> _Candidate | str:
    """What --allow would allow for `path`, or why it can't."""
    with Session(engine) as session:
        record = session.query(FileRecord).filter(FileRecord.filepath == path).first()
        if record is None:
            return "Ensign has no record of this file. Scan it first."
        if record.scan_status == ScanStatus.ALLOWED.value:
            return "This file is already allowed."
        if record.scan_status != ScanStatus.INFECTED.value:
            return (f"Only files ClamAV flagged can be allowed; this one is recorded as "
                    f"'{record.scan_status}'.")
        stored, threat = record.file_hash, record.threat_name or "Unknown"
    # Hash it again now: only the exact bytes that were flagged can be
    # allowed, never whatever the file has become since.
    try:
        fd, _st = open_for_scan(Path(path))
    except OSError as exc:
        return f"Ensign can't open this file to check it: {exc.strerror or exc}."
    try:
        digest = sha256_fd(fd)
    finally:
        os.close(fd)
    if digest != stored:
        return ("This file has changed since it was scanned, so it isn't the content ClamAV "
                "flagged. Scan it again first.")
    return _Candidate(path, digest, threat)


def _record(session: Session, found: _Candidate) -> int:
    """Save the allowance for `found` and mark every file with that content
    and signature as allowed. Returns how many files were marked. The
    caller commits."""
    exists = session.query(Allowance).filter(
        Allowance.file_hash == found.digest, Allowance.threat_name == found.threat).first()
    if exists is None:
        session.add(Allowance(file_hash=found.digest, threat_name=found.threat,
                              filepath=found.path, allowed_at=utcnow()))
        session.flush()
    # Every copy of the same content flagged by the same signature.
    copies = session.query(FileRecord).filter(
        FileRecord.file_hash == found.digest,
        FileRecord.threat_name == found.threat,
        FileRecord.scan_status == ScanStatus.INFECTED.value,
    ).all()
    for record in copies:
        record.scan_status = ScanStatus.ALLOWED.value
    return len(copies)


def allow(engine: Engine, path: str, confirm) -> bool:
    """Allow one flagged file. `confirm(prompt) -> bool` asks you to confirm.
    Returns True if it was allowed."""
    found = _candidate(engine, path)
    if isinstance(found, str):
        print_unwrapped(f"[yellow]Not allowed:[/yellow] {shown(path)}\n  {found}")
        return False
    print_unwrapped(f"\n  File:      {shown(found.path)}")
    print(f"  Signature: {shown(found.threat)}")
    print(f"  SHA-256:   {found.digest}")
    print("  Allowing tells Ensign this is a false positive: it stops counting this exact "
          "content, flagged by this exact signature, as infected. If the file changes or "
          "another signature flags it, it's flagged again. Only allow a file you've checked.")
    if not confirm("  Allow it? [y/N] "):
        print("  Not allowed.")
        return False
    with Session(engine) as session:
        marked = _record(session, found)
        session.commit()
    others = marked - 1
    also = f" (and {others} identical {'copy' if others == 1 else 'copies'} elsewhere)" if others > 0 else ""
    print_unwrapped(f"[green]  Allowed{also}.[/green] Undo with: ensign-scan --unallow {shown(found.path)}")
    return True


def unallow(engine: Engine, path: str) -> bool:
    """Undo --allow for the content at `path` (or allowed from there, if
    the file has since gone). Its copies are flagged as infected again."""
    with Session(engine) as session:
        record = session.query(FileRecord).filter(FileRecord.filepath == path).first()
        pairs = set()
        if record is not None and record.scan_status == ScanStatus.ALLOWED.value:
            pairs.add((record.file_hash, record.threat_name))
        for row in session.query(Allowance).filter(Allowance.filepath == path):
            pairs.add((row.file_hash, row.threat_name))
        if not pairs:
            print_unwrapped(f"[yellow]Nothing to undo:[/yellow] {shown(path)} isn't allowed.")
            return False
        flagged = 0
        for digest, threat in pairs:
            session.query(Allowance).filter(
                Allowance.file_hash == digest, Allowance.threat_name == threat).delete()
            flagged += session.query(FileRecord).filter(
                FileRecord.file_hash == digest,
                FileRecord.threat_name == threat,
                FileRecord.scan_status == ScanStatus.ALLOWED.value,
            ).update({FileRecord.scan_status: ScanStatus.INFECTED.value})
        session.commit()
    print_unwrapped(f"[yellow]No longer allowed:[/yellow] {shown(path)} "
                    f"({flagged} file{'s' if flagged != 1 else ''} flagged as infected again).")
    return True


# ----------------------------------------------------------------------
# Allowing a folder's flagged files in one go
# ----------------------------------------------------------------------

def _folder_text(folder: str) -> str:
    return folder.rstrip("/") or "/"


def _command(*words: str) -> str:
    """An ensign-scan command you can paste: every argument shell-quoted."""
    return shown("ensign-scan " + " ".join(shlex.quote(w) for w in words))


def _flagged_under(session: Session, folder: str) -> list[tuple[str, str, str]]:
    """(path, signature, stored SHA-256) of every infected file inside `folder`."""
    rows = session.query(FileRecord.filepath, FileRecord.threat_name, FileRecord.file_hash).filter(
        FileRecord.scan_status == ScanStatus.INFECTED.value,
        path_under(FileRecord.filepath, folder)).all()
    return sorted((path, threat or "Unknown", digest) for path, threat, digest in rows)


def _print_some(paths: list[str], top: int, icon: str = "○") -> None:
    for path in paths[:top]:
        print_unwrapped(f"    [cyan]{icon}[/cyan] {shown(path)}")
    if len(paths) > top:
        print(f"    … and {len(paths) - top} more")


def allow_folder(engine: Engine, folder: str, signature: str | None, confirm, top: int = 10) -> int:
    """Allow every file under `folder` that `signature` flags right now.
    Asks once, after showing what would be allowed and what is left out.
    Returns how many files under the folder were allowed."""
    folder = _folder_text(folder)
    if os.path.lexists(folder) and not os.path.isdir(folder):
        print_unwrapped(f"[yellow]Not allowed:[/yellow] {shown(folder)} is a file, and --allow-folder "
                        f"takes a folder. To allow one file: {_command('--allow', folder)}")
        return 0
    with Session(engine) as session:
        flagged = _flagged_under(session, folder)
    if not flagged:
        print_unwrapped(f"[yellow]Nothing to allow:[/yellow] no file under {shown(folder)} is "
                        f"recorded as infected. Scan it first.")
        return 0
    by_signature: dict[str, list[str]] = {}
    stored_hash: dict[str, str] = {}
    for path, threat, digest in flagged:
        by_signature.setdefault(threat, []).append(path)
        stored_hash[path] = digest
    if signature not in by_signature:
        if signature is None:
            print_unwrapped(f"[yellow]Not allowed:[/yellow] say which signature to allow under "
                            f"{shown(folder)} with --signature NAME.")
        else:
            print_unwrapped(f"[yellow]Nothing to allow:[/yellow] no file under {shown(folder)} is "
                            f"flagged by {shown(signature)} right now.")
        print("  Flagged there now:")
        for threat, paths in sorted(by_signature.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            print(f"    {shown(threat)}  ({len(paths)} file{'s' if len(paths) != 1 else ''})")
        return 0

    paths = by_signature[signature]
    code = [p for p in paths if loads_code(p)]
    rest = [p for p in paths if not loads_code(p)]
    if rest:
        print(f"\n  Checking {len(rest)} file{'s' if len(rest) != 1 else ''} again "
              f"(each one is hashed, so large files take a while)…")
    # An allowance goes by content, so allowing a file would also cover a
    # left-out file holding the very same bytes. Such a file is held back
    # with it, so "left out" always means "still infected". The hashes come
    # from the query above: asking for them again with one "IN (...)" over
    # every left-out path would exceed SQLite's limit on a large folder.
    code_hashes = {stored_hash[p] for p in code}
    ready: list[_Candidate] = []
    not_ready: list[tuple[str, str]] = []
    for path in rest:
        found = _candidate(engine, path)
        if isinstance(found, str):
            not_ready.append((path, found))
        elif found.digest in code_hashes:
            not_ready.append((path, "Its content is identical to a left-out file above. "
                                    "Allow that one by itself first."))
        else:
            ready.append(found)

    print_unwrapped(f"\n  Folder:    {shown(folder)}")
    print(f"  Signature: {shown(signature)}")
    if ready:
        print(f"  To allow:  {len(ready)} file{'s' if len(ready) != 1 else ''}")
        _print_some([c.path for c in ready], top)
    if code:
        print(f"  Left out:  {len(code)} file{'s' if len(code) != 1 else ''} in a format that can "
              f"run code when a program loads it ({', '.join(sorted(LOADS_CODE_EXTENSIONS))}). "
              f"These stay infected. If you've checked one, allow it by itself: "
              f"ensign-scan --allow PATH")
        _print_some(code, top, "!")
    if not_ready:
        print(f"  Left out:  {len(not_ready)} file{'s' if len(not_ready) != 1 else ''} Ensign "
              f"couldn't confirm. These stay infected.")
        for path, why in not_ready[:top]:
            print_unwrapped(f"    [yellow]![/yellow] {shown(path)}\n      {why}")
        if len(not_ready) > top:
            print(f"    … and {len(not_ready) - top} more")
    if not ready:
        print("  Nothing was allowed.")
        return 0
    print("  Allowing tells Ensign these are false positives: it stops counting each file's exact "
          "content, flagged by this exact signature, as infected. Nothing is allowed for being "
          "in this folder: a file that appears here later, or one of these once it changes, is "
          "flagged again. Only allow files you've checked.")
    count = f"these {len(ready)} files" if len(ready) != 1 else "this file"
    if not confirm(f"  Allow {count}? [y/N] "):
        print("  Not allowed.")
        return 0

    inside = {c.path for c in ready}
    with Session(engine) as session:
        marked = sum(_record(session, c) for c in ready)
        now = utcnow()
        row = session.query(AllowedFolder).filter(
            AllowedFolder.folder == folder, AllowedFolder.threat_name == signature).first()
        if row is None:
            session.add(AllowedFolder(folder=folder, threat_name=signature,
                                      allowed_at=now, last_allowed_at=now))
        else:
            row.last_allowed_at = now
        session.commit()
    others = marked - len(inside)
    also = f" (and {others} identical {'copy' if others == 1 else 'copies'} elsewhere)" if others > 0 else ""
    print_unwrapped(f"[green]  Allowed {len(inside)} file{'s' if len(inside) != 1 else ''}{also}.[/green] "
                    f"Undo with: {_command('--unallow-folder', folder, '--signature', signature)}")
    return len(inside)


def unallow_folder(engine: Engine, folder: str, signature: str) -> bool:
    """Undo --allow-folder: everything allowed for `signature` under
    `folder`, or allowed from there (and its identical copies), is flagged
    as infected again, and the folder is forgotten."""
    folder = _folder_text(folder)
    with Session(engine) as session:
        # The folder itself, and any folder inside it you allowed for the
        # same signature: its files are flagged again below, so it must not
        # stay listed, or report them later as "new".
        remembered = session.query(AllowedFolder).filter(
            AllowedFolder.threat_name == signature,
            or_(AllowedFolder.folder == folder, path_under(AllowedFolder.folder, folder)),
        ).delete(synchronize_session=False)
        digests = {h for (h,) in session.query(FileRecord.file_hash).filter(
            FileRecord.scan_status == ScanStatus.ALLOWED.value,
            FileRecord.threat_name == signature,
            path_under(FileRecord.filepath, folder))}
        # Also content that was allowed from this folder and has since
        # changed or gone: its allowance may still cover a copy elsewhere.
        digests |= {h for (h,) in session.query(Allowance.file_hash).filter(
            Allowance.threat_name == signature, path_under(Allowance.filepath, folder))}
        if not remembered and not digests:
            print_unwrapped(f"[yellow]Nothing to undo:[/yellow] nothing under {shown(folder)} is "
                            f"allowed for {shown(signature)}.")
            return False
        flagged = 0
        for digest in digests:
            session.query(Allowance).filter(
                Allowance.file_hash == digest, Allowance.threat_name == signature).delete()
            flagged += session.query(FileRecord).filter(
                FileRecord.file_hash == digest,
                FileRecord.threat_name == signature,
                FileRecord.scan_status == ScanStatus.ALLOWED.value,
            ).update({FileRecord.scan_status: ScanStatus.INFECTED.value})
        session.commit()
    print_unwrapped(f"[yellow]No longer allowed:[/yellow] {shown(signature)} under {shown(folder)} "
                    f"({flagged} file{'s' if flagged != 1 else ''} flagged as infected again).")
    return True


def new_in_allowed_folders(engine: Engine, paths: list[str] | None = None, top: int = 5) -> int:
    """The end-of-run section for folders you ran --allow-folder on: files
    there that the same signature flags and that aren't allowed, because
    they are new or have changed since. They are infected like any other
    (and already listed as such); this adds the commands for allowing them.
    Ensign runs neither. Returns how many files it listed."""
    from .reports import _scope_filter  # reports doesn't import this module; no cycle
    scope = _scope_filter(paths)
    groups: list[tuple[str, str, list[str]]] = []
    with Session(engine) as session:
        folders = session.query(AllowedFolder.folder, AllowedFolder.threat_name).all()
        seen: set[str] = set()
        # Deepest folder first, so a file is listed once, under the most
        # specific folder you allowed.
        for folder, threat in sorted(folders, key=lambda r: (-len(r[0]), r[0], r[1])):
            query = session.query(FileRecord.filepath).filter(
                FileRecord.scan_status == ScanStatus.INFECTED.value,
                FileRecord.threat_name == threat,
                path_under(FileRecord.filepath, folder))
            if scope is not None:
                query = query.filter(scope)
            found = sorted({p for (p,) in query} - seen)
            if found:
                seen.update(found)
                groups.append((folder, threat, found))
    if not groups:
        return 0
    total = sum(len(found) for _f, _t, found in groups)
    print(f"\n[bold]=== NEW IN FOLDERS YOU ALLOWED ({total} file{'s' if total != 1 else ''}) ===[/bold]")
    print("Flagged by a signature you allowed in the same folder before, but these files are new "
          "or have changed since, so they count as infected. Check them first. Ensign runs "
          "neither command for you.")
    for folder, threat, found in sorted(groups):
        print_unwrapped(f"\n  Folder: {shown(folder)}")
        print(f"  Signature: {shown(threat)}  ({len(found)} file{'s' if len(found) != 1 else ''})")
        _print_some(found, top, "!")
        code = sum(1 for p in found if loads_code(p))
        if code < len(found):
            print_unwrapped(f"    Allow them all: {_command('--allow-folder', folder, '--signature', threat)}")
        print_unwrapped(f"    Allow one:      {_command('--allow', found[0])}")
        if code:
            print(f"    {code} of these can run code when a program loads "
                  f"{'it' if code == 1 else 'them'}; --allow-folder leaves "
                  f"{'it' if code == 1 else 'them'} out, so allow each with --allow PATH.")
    return total


def allowed_report(engine: Engine, paths: list[str] | None = None, top: int = 10) -> int:
    """The end-of-run section: files currently allowed, within the run's
    scope (`paths`, as for the other reports). Returns how many there are."""
    from .reports import _scope_filter  # reports doesn't import this module; no cycle
    paths_filter = _scope_filter(paths)
    with Session(engine) as session:
        query = session.query(FileRecord.filepath, FileRecord.threat_name, FileRecord.file_hash).filter(
            FileRecord.scan_status == ScanStatus.ALLOWED.value)
        if paths_filter is not None:
            query = query.filter(paths_filter)
        rows = sorted(query.all(), key=lambda r: (r.threat_name or "", r.filepath))
        when = {(h, t): at for h, t, at in
                session.query(Allowance.file_hash, Allowance.threat_name, Allowance.allowed_at)}
    if not rows:
        return 0
    print(f"\n[bold]=== ALLOWED BY YOU ({len(rows)} file{'s' if len(rows) != 1 else ''}) ===[/bold]")
    print("Flagged by ClamAV, and marked by you as false positives. Not counted as infected. "
          "ensign-scan --list-allowed shows them all; --unallow PATH undoes one.")
    for filepath, threat, digest in rows[:top]:
        date = when.get((digest, threat))
        on = f", allowed {date:%Y-%m-%d}" if date else ""
        print_unwrapped(f"  [cyan]○[/cyan] {shown(filepath)}  [dim]({shown(threat)}{on})[/dim]")
    if len(rows) > top:
        print(f"  … and {len(rows) - top} more (ensign-scan --list-allowed)")
    return len(rows)


def list_allowed(engine: Engine) -> int:
    """Every allowance, with where its content is now."""
    with Session(engine) as session:
        allowances = session.query(Allowance).order_by(Allowance.allowed_at).all()
        where = {}
        for a in allowances:
            where[a.id] = [r.filepath for r in session.query(FileRecord.filepath).filter(
                FileRecord.file_hash == a.file_hash, FileRecord.threat_name == a.threat_name,
                FileRecord.scan_status == ScanStatus.ALLOWED.value)]
        rows = [(a.id, a.filepath, a.threat_name, a.file_hash, a.allowed_at) for a in allowances]
        folders = []
        for f in session.query(AllowedFolder).order_by(AllowedFolder.folder, AllowedFolder.threat_name):
            now_allowed = session.query(FileRecord).filter(
                FileRecord.scan_status == ScanStatus.ALLOWED.value,
                FileRecord.threat_name == f.threat_name,
                path_under(FileRecord.filepath, f.folder)).count()
            folders.append((f.folder, f.threat_name, f.allowed_at, f.last_allowed_at, now_allowed))
    if not rows and not folders:
        print("Nothing is allowed. (ensign-scan --allow PATH marks a flagged file as a false positive.)")
        return 0
    if folders:
        print(f"\n=== FOLDERS YOU RAN --allow-folder ON ({len(folders)}) ===")
        print("A folder allows nothing by itself: each file below it is allowed by its own content.")
        for folder, threat, first, last, now_allowed in folders:
            print_unwrapped(f"\n  Folder:    {shown(folder)}")
            print(f"  Signature: {shown(threat)}")
            again = f", last run {last:%Y-%m-%d %H:%M} UTC" if last != first else ""
            print(f"  Allowed:   {first:%Y-%m-%d %H:%M} UTC{again}")
            print(f"  Files allowed there now: {now_allowed}")
    if not rows:
        return 0
    print(f"\n=== ALLOWED BY YOU ({len(rows)}) ===")
    for row_id, filepath, threat, digest, allowed_at in rows:
        print(f"\n  Signature: {shown(threat)}")
        print_unwrapped(f"  Allowed:   {allowed_at:%Y-%m-%d %H:%M} UTC, from {shown(filepath)}")
        print(f"  SHA-256:   {digest}")
        found = where[row_id]
        if found:
            for p in found:
                print_unwrapped(f"  [cyan]○[/cyan] {shown(p)}")
        else:
            print("  [dim](no file with this content is tracked right now)[/dim]")
    return len(rows)
