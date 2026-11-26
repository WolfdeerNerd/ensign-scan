"""--clamav-report: a false-positive report for ClamAV, ready to submit.

When ClamAV flags a file you're sure is harmless, ClamAV wants to hear about
it, so the signature can be fixed for everyone. Its form (and its clamsubmit
tool) asks for the file itself and the signature name. This prepares the
rest, and leaves the submitting to you:

1. The file is hashed again: the report is about the exact content that was
   flagged, never whatever the file has become since.
2. It is scanned again with the current signatures. If ClamAV no longer
   flags it, it has already been fixed and there is nothing to report.
3. A signature ending in .UNOFFICIAL isn't ClamAV's -- it comes from a
   third-party signature set -- so you're pointed at that set's provider
   instead.
4. The report text goes to a file in Ensign's data folder. It holds the
   signature name, hashes, size, file type and ClamAV versions, and no file
   name, path, username or hostname (and is checked for those, as
   --diagnostics is).
5. The file to attach is named on screen only. It is never copied: if the
   detection were real, a copy would be a second piece of malware.

Submitting sends the file's whole contents to Cisco. Ensign never submits
anything itself.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

from rich import print
from sqlalchemy.orm import Session

from .config import HOME
from .diagnostics import _scrub
from .fsutil import NotScannable, human_size, open_for_scan, print_unwrapped, shell_quote, shown
from .models import FileRecord, ScanStatus, utcnow

FORM_URL = "https://www.clamav.net/reports/fp"
# Folders where a file is likely to be personal. A warning, not a block.
_PERSONAL = ("Documents", "Desktop", "Pictures", "Videos", "Music", "Downloads")


def _hashes(fd: int) -> tuple[str, str]:
    sha, md5 = hashlib.sha256(), hashlib.md5(usedforsecurity=False)
    offset = 0
    while chunk := os.pread(fd, 1 << 20, offset):
        sha.update(chunk)
        md5.update(chunk)
        offset += len(chunk)
    return sha.hexdigest(), md5.hexdigest()


def _mime_type(fd: int) -> str:
    """The file's type as a MIME type only (`file --mime-type`), from its
    first bytes piped in: plain `file` can print document metadata such as
    authors and titles, which may be personal."""
    try:
        head = os.pread(fd, 4 << 20, 0)
        result = subprocess.run(["file", "--brief", "--mime-type", "-"], input=head,
                                capture_output=True, timeout=30)
        kind = result.stdout.decode("ascii", "replace").strip()
        return kind if result.returncode == 0 and kind else "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown (the 'file' command isn't available)"


def _personal_folder(path: Path) -> str | None:
    for name in _PERSONAL:
        folder = HOME / name
        if path == folder or folder in path.parents:
            return name
    return None


def _rescan(scanner, fd: int, path: Path, size: int):
    """Scan the open file again with the current signatures, the way a scan
    would: clamd, or clamscan for files larger than clamd scans."""
    from . import clamd as clamd_mod
    from .scanner import (_CLAMSCAN_BASE_TIMEOUT, _CLAMSCAN_BYTES_PER_SECOND,
                          _CLAMSCAN_MAX_SCANTIME_MS, _scan_cost)
    scanner.prepare_clamd()
    if size >= scanner._scan_limit():
        if not clamd_mod.clamscan_cli_available():
            return None, "this file is larger than clamd scans, and the 'clamscan' command isn't installed"
        try:
            run_as = clamd_mod.clamscan_user()
        except LookupError as exc:
            return None, f"Ensign won't run clamscan as root, and there is {exc}"
        timeout = _CLAMSCAN_BASE_TIMEOUT + _scan_cost(size) / _CLAMSCAN_BYTES_PER_SECOND
        limits = scanner.limits or clamd_mod.DEFAULT_LIMITS
        return clamd_mod.scan_fds_with_clamscan(
            [fd], limits, timeout, run_as, max_scantime_ms=_CLAMSCAN_MAX_SCANTIME_MS)[fd], "clamscan, whole file"
    if scanner._transport == "path":
        return scanner.clamd.scan(path), "clamd, whole file"
    from .scanner import _clamd_skipped
    outcome = scanner.clamd.scan_fd(fd, label=str(path))
    if _clamd_skipped(outcome):
        return None, "clamd skipped it as too large (a limit Ensign didn't know about); scan it again"
    return outcome, "clamd, whole file"


def _evidence(path: Path, sha256: str, threat: str) -> tuple[list[str], list[str], list[str]]:
    """What the package manager and Steam say about the file, asked now rather
    than taken from stored evidence, so the report says what's true today.

    Returns (report lines, draft sentences for the "why", cautions for the
    screen). The game or package name is in the report on purpose: a file in
    a game folder is usually unique to that game, and the name is what lets
    ClamAV's analysts find it. A draft is only offered when the evidence
    supports it, and never for a known malware family's name."""
    from . import pkgdb, steam
    from .explanations import known_family

    lines: list[str] = []
    draft: list[str] = []
    cautions: list[str] = []
    family = known_family(threat)
    if family:
        cautions.append(f"ClamAV names a known malware family ({family}). False positives under "
                        f"such names are rare: real malware has shipped inside official game builds "
                        f"and packages.")
    try:  # a second opinion failing must not stop the report
        state, package = pkgdb.origins([str(path)]).get(str(path), (pkgdb.UNKNOWN, None))
        backend = pkgdb.active().name
    except Exception:
        state, package, backend = pkgdb.UNKNOWN, None, ""
    if package and state == pkgdb.FROM_PACKAGE:
        lines.append(f"Package:          installed by {package} ({backend}), unchanged since")
        draft.append(f"The file is part of the {package} package ({backend}), unchanged from "
                     f"what that package installed.")
    elif package and state == pkgdb.MODIFIED:
        lines.append(f"Package:          belongs to {package} ({backend}), but differs from what "
                     f"the package installed")
        cautions.append(f"It differs from what the {package} package installed, so it isn't the "
                        f"file the package shipped.")
    elif package and state == pkgdb.OWNED:
        lines.append(f"Package:          belongs to {package} ({backend}); couldn't be compared "
                     f"with what the package installed")
    try:
        answer = steam.check(steam.Records(), str(path), sha256)
    except Exception:
        answer = None
    if answer is not None and answer.verdict == steam.MATCH:
        lines.append(f"Steam:            installed by Steam for {answer.game}, exactly as Steam's "
                     f"record of the current build lists it")
        draft.append(f"The file is part of {answer.game}, installed by Steam, and matches Steam's "
                     f"record of the game's current build.")
    elif answer is not None and answer.verdict == steam.DIFFERS:
        lines.append(f"Steam:            a file of {answer.game}, but with other contents than "
                     f"Steam's record of the current build")
        cautions.append(f"Steam's record of {answer.game} lists this file with other contents, so "
                        f"it isn't the file Steam shipped (a pending update can cause this too).")
    elif answer is not None and answer.verdict == steam.WORKSHOP:
        lines.append(f"Steam:            part of a Steam Workshop item for {answer.game} "
                     f"(community-made content)")
        draft.append(f"The file is part of a Steam Workshop item for {answer.game}.")
    if family or cautions:
        draft = []   # nothing that argues for a false positive when the checks point the other way
    return lines, draft, cautions


def _first_flagged(engine, sha256: str):
    """When Ensign first saw ClamAV flag this exact content, under any name
    and in any copy, or None."""
    from sqlalchemy import func

    from .models import CLAMAV_ENGINES, Finding
    try:
        with Session(engine) as session:
            return (session.query(func.min(Finding.first_seen))
                    .filter(Finding.content_hash == sha256, Finding.engine.in_(CLAMAV_ENGINES)).scalar())
    except Exception:  # an older database, say: the date is a nicety
        return None


def make_report(scanner, config, path_text: str) -> Path | None:
    """Prepare the report for one flagged file. Returns where it was written,
    or None (with the reason on screen) if there's nothing to report."""
    path = Path(path_text)
    with Session(scanner.engine) as session:
        record = session.query(FileRecord).filter(FileRecord.filepath == str(path)).first()
        if record is None:
            print_unwrapped(f"[yellow]No report:[/yellow] {shown(path)}\n  Ensign has no record of "
                            f"this file. Scan it first.")
            return None
        status, stored, threat, result = (record.scan_status, record.file_hash,
                                          record.threat_name, record.scan_result or "")
    if status not in (ScanStatus.INFECTED.value, ScanStatus.ALLOWED.value):
        print_unwrapped(f"[yellow]No report:[/yellow] {shown(path)}\n  Only a file ClamAV flagged "
                        f"can be reported as a false positive; this one is recorded as '{status}'.")
        return None
    from .scanner import SWEEP_HIT_PREFIX
    if result.startswith(SWEEP_HIT_PREFIX):
        if "by YARA" in result:
            how = ("YARA found this, using Ensign's translation of a ClamAV signature, in a file "
                   "too large for ClamAV to scan whole")
        else:
            how = "The sweep found this, in a slice of a file too large for ClamAV to scan whole"
        print_unwrapped(f"[yellow]No report:[/yellow] {shown(path)}\n  {how}, so ClamAV couldn't "
                        f"reproduce the detection from the file. The signature name and where it "
                        f"matched are in the file's details, in the infected list at the end of a "
                        f"scan.")
        return None

    try:
        fd, st = open_for_scan(path)
    except (OSError, NotScannable) as exc:
        print_unwrapped(f"[yellow]No report:[/yellow] {shown(path)}\n  Ensign can't open it: {exc}.")
        return None
    try:
        sha256, md5 = _hashes(fd)
        if sha256 != stored:
            print_unwrapped(f"[yellow]No report:[/yellow] {shown(path)}\n  This file has changed "
                            f"since it was scanned, so it isn't the content ClamAV flagged. Scan it "
                            f"again first.")
            return None
        try:
            outcome, how = _rescan(scanner, fd, path, st.st_size)
        except OSError as exc:  # clamd stopped answering, say
            outcome, how = None, f"clamd didn't answer ({exc})"
        mime = _mime_type(fd)
    finally:
        os.close(fd)

    if outcome is None:
        print_unwrapped(f"[yellow]No report:[/yellow] {shown(path)}\n  It couldn't be scanned "
                        f"again: {how}.")
        return None
    if outcome.status == ScanStatus.CLEAN:
        print_unwrapped(f"[green]Nothing to report:[/green] {shown(path)}\n  ClamAV no longer flags "
                        f"this file with its current signatures: the false positive has already "
                        f"been fixed. Ensign's next scan updates its record.")
        return None
    if outcome.status != ScanStatus.INFECTED:
        print_unwrapped(f"[yellow]No report:[/yellow] {shown(path)}\n  Scanning it again didn't "
                        f"give a clear answer ({shown(outcome.raw[-120:])}).")
        return None
    current = outcome.threat_name or "Unknown"
    changed_name = current != threat
    if current.endswith(".UNOFFICIAL"):
        print_unwrapped(f"[yellow]Not a ClamAV signature:[/yellow] {shown(current)}\n  Names ending "
                        f"in .UNOFFICIAL come from a third-party signature set installed alongside "
                        f"ClamAV's own, which ClamAV can't fix. Report it to whoever provides that "
                        f"set (its files are in clamd's signature folder).")
        return None

    version = getattr(scanner.clamd, "version_string", lambda: None)() or "unknown"
    when = utcnow().strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "ClamAV false positive report",
        "",
        f"Signature name:   {current}",
        f"SHA-256:          {sha256}",
        f"MD5:              {md5}",
        f"File size:        {st.st_size:,} bytes"
        + (f" ({human_size(st.st_size)})" if st.st_size >= 1024 else ""),
        f"File type:        {mime}",
        f"ClamAV version:   {version}",
        f"Detected by:      {how}, checked again {when}",
    ]
    if changed_name:
        lines.append(f"Earlier name:     {threat} (newer signatures name it {current})")
    package_lines, draft, cautions = _evidence(path, sha256, current)
    lines += package_lines
    first = _first_flagged(scanner.engine, sha256)
    if first is not None:
        lines.append(f"First flagged:    {first:%Y-%m-%d} (this exact content)")
    lines += ["", "Why I believe this is a false positive:"]
    if draft:
        lines += ["  <A starting point, drafted from the package manager's and Steam's records.",
                  "   Check it, then add in your own words what the file is and where it came from.>"]
        lines += [f"  {sentence}" for sentence in draft]
    else:
        lines += ["  <In your own words: what the file is, and where it came from -- which",
                  "   program, game or download it belongs to.>"]
    lines += ["", "This report contains no file name, path, username or hostname."]
    text = _scrub("\n".join(lines)) + "\n"

    folder = Path(config.data_dir) / "clamav-reports"
    out = folder / f"false-positive-{sha256[:12]}.txt"
    try:
        folder.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as fh:
            fh.write(text)
    except OSError as exc:
        print_unwrapped(f"[yellow]No report:[/yellow] {shown(path)}\n  The report couldn't be "
                        f"saved to {shown(folder)}: {shown(exc.strerror or exc)}. If an earlier "
                        f"run used sudo, that folder may belong to root: remove it with sudo, "
                        f"then try again without sudo.")
        return None

    print(f"\n[bold]ClamAV false positive report: {shown(current)}[/bold]")
    if changed_name:
        print(f"  [dim]Newer signatures name it {shown(current)} (it was {shown(threat)}).[/dim]")
    print_unwrapped(f"  Report: {shown(out)}")
    print("  To submit it:")
    print(f"    1. Open {FORM_URL}")
    print_unwrapped(f"    2. Attach the file itself: {shown(path)}")
    print("       (named here only: the report doesn't contain it)")
    print("    3. Paste the report's details into the form, and say in your own")
    print("       words why it's a false positive.")
    print("  [dim]ClamAV's form asks for an email address. Consider one that isn't tied to[/dim]")
    print("  [dim]your Steam account or anything else of yours.[/dim]")
    sig = shell_quote(current)
    print_unwrapped(f"  Or with ClamAV's own tool: clamsubmit -p {shown(shell_quote(str(path)))} "
                    f"-V {shown(sig)} -N 'Your name' -e 'you@example.com'")
    if cautions:
        print("  [bold yellow]Before you submit:[/bold yellow] Ensign's checks point the other way.")
        for caution in cautions:
            print_unwrapped(f"  [yellow]![/yellow] {caution}")
        print("    A report says you've checked the file is safe. If you're not sure, don't send it.")
    print("  [yellow]Submitting sends the file's whole contents to Cisco (ClamAV's owner).[/yellow]")
    print("  [yellow]Only submit a file with nothing private in it.[/yellow]")
    folder_name = _personal_folder(path)
    if folder_name:
        print(f"  [yellow]! This file is in your {folder_name} folder: make sure it's[/yellow]")
        print("    [yellow]nothing personal before you send it.[/yellow]")
    return out


def make_reports(scanner, config, paths: list[str]) -> int:
    """--clamav-report for each path. Returns how many reports were written."""
    return sum(1 for p in paths if make_report(scanner, config, p) is not None)
