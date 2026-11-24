"""Ensign command-line entry point (the `ensign-scan` command).

All side effects (greeting, logging setup, the scan itself) happen in
main(), not at import time, so the package can be imported by tests or
other scripts without launching a full system scan.
"""
from __future__ import annotations

import sys

if sys.version_info < (3, 11):
    v = sys.version_info
    print(f"Ensign requires Python 3.11 or newer (found {v.major}.{v.minor}).")
    print("It uses the standard-library 'tomllib' module for config parsing.")
    raise SystemExit(1)

import argparse
import dataclasses
import os
import time
from pathlib import Path
from builtins import print as builtin_print
from importlib.metadata import PackageNotFoundError, version as dist_version

from rich import get_console, print

from ensign_scan.config import AS_ROOT, HOME, HOSTNAME, Config, ensure_default_config, legacy_notice
from ensign_scan import (
    allowlist, bigrules, diagnostics, evidence, explanations, findings, fpreport, logo, logsetup, migrate, notify,
    persistence, pkgdb, protect, secrets,
)
from ensign_scan.fsutil import print_unwrapped, shown
from ensign_scan.runlock import AlreadyRunning, RunLock
from ensign_scan.reports import (
    error_summary,
    format_mismatch_report,
    incomplete_report,
    integrity_report,
    list_infected,
    package_report,
    scan_summary,
    suggest_fixes,
    unreadable_report,
    unsaved_report,
)
from ensign_scan.scanner import ClamdUnsafe, Scanner

EXIT_BUSY = 75  # sysexits EX_TEMPFAIL: another Ensign holds the lock; try again later
EXIT_UNSAVED = 1  # the run finished, but some results couldn't be saved (see unsaved_report)
EXIT_INFECTED = 3  # the run finished and infected files are present (outranks EXIT_UNSAVED)
# --persistence: startup entries are new, changed or gone since you last
# acknowledged them. Entries it couldn't read (no root) don't count.
EXIT_PERSISTENCE_PENDING = 4


def ensign_version() -> str:
    """The installed ensign-scan version, read from package metadata.

    pyproject.toml stays the single source of truth: installing the package
    records its version, and this reads it back. Running straight from a
    source checkout that was never installed has no metadata, so say so
    instead of guessing.
    """
    try:
        return dist_version("ensign-scan")
    except PackageNotFoundError:
        return "unknown (not installed; running from source)"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Hash and ClamAV-scan the system.")
    parser.add_argument("--version", action="version",
                        version=f"ensign-scan {ensign_version()}")
    parser.add_argument("targets", nargs="*",
                        help="Directories to scan (default: scan_targets from config)")
    parser.add_argument("--config", metavar="PATH",
                        help="Config file (default: ~/.config/ensign-scan/config.toml)")
    parser.add_argument("--no-scan", action="store_true",
                        help="Hash and record files without ClamAV scanning")
    parser.add_argument("--skip-rescans", action="store_true",
                        help="Skip the infected/error/stale rescan passes")
    parser.add_argument("--purge-missing", action="store_true",
                        help="Remove DB records for files that no longer exist, then exit")
    parser.add_argument("--rescan-errors", action="store_true",
                        help="Retry only files currently marked ERROR, then exit (no full scan)")
    parser.add_argument("--verify-packages", "--verify-pacman", dest="verify_packages", action="store_true",
                        help="Check installed files against the package manager's records, then exit "
                             "(can be slow; --verify-pacman is the old name)")
    parser.add_argument("--diagnostics", action="store_true",
                        help="Print versions, settings and counts for a bug report, then exit. "
                             "Contains no paths, usernames, hostnames or file names.")
    parser.add_argument("--sweep", action="store_true",
                        help="After this scan, sweep files too large for ClamAV (over ~2 GiB) in "
                             "slices. Only needed with sweep_huge_files = false: the sweep is on "
                             "by default")
    parser.add_argument("--update-rules", action="store_true",
                        help="Rebuild the YARA rules for files too large for ClamAV from ClamAV's "
                             "current signatures, check them, then exit. Runs by itself before "
                             "every sweep when the signatures have changed.")
    parser.add_argument("--allow", metavar="PATH", action="append", default=[],
                        help="Mark a file ClamAV flagged as a false positive (this exact content and "
                             "signature only), then exit. Asks to confirm. Can be given more than once.")
    parser.add_argument("--unallow", metavar="PATH", action="append", default=[],
                        help="Undo --allow for a file, then exit")
    parser.add_argument("--allow-folder", metavar="FOLDER",
                        help="Allow every file under FOLDER that one signature flags right now "
                             "(name it with --signature), then exit. Asks once to confirm. Files "
                             "that appear or change later are flagged again.")
    parser.add_argument("--unallow-folder", metavar="FOLDER",
                        help="Undo --allow-folder for FOLDER and --signature, then exit")
    parser.add_argument("--signature", metavar="NAME",
                        help="The signature name for --allow-folder / --unallow-folder, as shown "
                             "in the infected list")
    parser.add_argument("--list-allowed", action="store_true",
                        help="List the folders and files you've allowed, then exit")
    parser.add_argument("--list-allowed-all", action="store_true",
                        help="Like --list-allowed, but also list the files inside each allowed folder")
    parser.add_argument("--list-infected", action="store_true",
                        help="List the infected files from the last scans (all of them, or only "
                             "under the paths given), with their SHA-256, then exit. Doesn't scan")
    parser.add_argument("--clamav-report", metavar="PATH", action="append", default=[],
                        help="Prepare a false-positive report for ClamAV about a file it flagged, "
                             "then exit. Checks the file again first. Nothing is sent: you submit "
                             "it. Can be given more than once.")
    parser.add_argument("--persistence", action="store_true",
                        help="Check the places programs use to start themselves (systemd units, "
                             "shell startup files, autostart, cron, ld.so.preload, pacman hooks) "
                             "for entries that are new, changed or gone since you acknowledged "
                             "them, then exit. Changes nothing.")
    parser.add_argument("--acknowledge", metavar="PATH", action="append", default=[],
                        help="Accept one startup entry the persistence check lists, as it is now, "
                             "then exit. Asks to confirm. Can be given more than once.")
    parser.add_argument("--acknowledge-all", action="store_true",
                        help="Show the persistence check, then accept everything it lists. Asks "
                             "to confirm.")
    parser.add_argument("--yes", action="store_true",
                        help="Don't ask to confirm --allow, --allow-folder, --acknowledge or "
                             "--acknowledge-all (for scripts)")
    parser.add_argument("--protect", action="store_true",
                        help="With sudo: keep your config and your decisions (allowances, "
                             "acknowledged startup entries) where only root can change them, so "
                             "nothing running as you can. Shows your config and asks first, then exit")
    parser.add_argument("--protected", action="store_true",
                        help="With sudo, before --allow, --unallow, --allow-folder, --unallow-folder, "
                             "--persistence, --acknowledge or --acknowledge-all: change your protected "
                             "decisions (see --protect) instead of root's own")
    parser.add_argument("--unprotect", action="store_true",
                        help="With sudo: undo --protect, so your runs use your own config and "
                             "database again. Asks first, then exit")
    parser.add_argument("--suggest-fixes", action="store_true",
                        help="List files clamd could not read, grouped by directory, then exit (no full scan). "
                             "Scoped to any targets given.")
    args = parser.parse_args()
    if args.signature and not (args.allow_folder or args.unallow_folder):
        parser.error("--signature goes with --allow-folder or --unallow-folder")
    if args.unallow_folder and not args.signature:
        parser.error("--unallow-folder needs --signature NAME")
    if args.allow_folder and args.unallow_folder:
        parser.error("--allow-folder and --unallow-folder can't be used together")
    if args.protect and args.unprotect:
        parser.error("--protect and --unprotect can't be used together")
    if args.protected and not (args.allow or args.unallow or args.allow_folder or args.unallow_folder
                               or args.persistence or args.acknowledge or args.acknowledge_all):
        parser.error("--protected goes with --allow, --unallow, --allow-folder, --unallow-folder, "
                     "--persistence, --acknowledge or --acknowledge-all. To see what's allowed, "
                     "run ensign-scan --list-allowed as yourself.")
    return args


def setup_logging(config: Config) -> None:
    logsetup.setup(config)


def greet(config: Config) -> None:
    print()
    lines = logo.banner(get_console())   # None in a pipe, a narrow window, or without UTF-8
    if lines:
        for line in lines:
            print(line)
        print()
    print(f" Greetings, {HOME.name}!")
    print("-" * 71)
    print(" I, Ensign, will start scanning your system shortly…")
    print(f" Host:     {HOSTNAME}")
    print(f" Config:   {shown(config.source)}")
    print(f" Database: {shown(config.data_dir / 'system.db')}")
    print("-" * 71)


# Every run ends with a blank line before the shell prompt, as the scan's
# footer does. The footer prints its own; _end_gap() adds it for the rest.
_ended_with_gap = False


def _end_gap() -> None:
    if not _ended_with_gap:
        print()


def main() -> int:
    try:
        return _main()
    finally:
        _end_gap()


def _main() -> int:
    global _ended_with_gap
    # Everything Ensign creates (data folder, database and its -wal/-shm
    # files, logs, config, reports) is readable by its owner only: the
    # database maps every file on the machine, including where secrets
    # live. Only new files are affected; existing ones keep the permissions
    # they have, so a folder you opened up on purpose stays that way.
    os.umask(0o077)
    args = parse_args()
    # Absolute, normalized paths: the database, the excludes and the scoped
    # reports all work on absolute paths, so "cd ~ && ensign-scan Downloads"
    # must mean /home/you/Downloads -- not "Downloads", which would be
    # stored relative to wherever you stood and would slip past every exclude.
    args.targets = [os.path.abspath(t) for t in args.targets]
    args.allow = [os.path.abspath(p) for p in args.allow]
    args.unallow = [os.path.abspath(p) for p in args.unallow]
    args.clamav_report = [os.path.abspath(p) for p in args.clamav_report]
    # The audit stores entries with their folders resolved (/lib/x is
    # /usr/lib/x on a merged-/usr system); the file itself is not followed.
    args.acknowledge = [persistence.resolve_dirs(os.path.abspath(p)) for p in args.acknowledge]
    args.allow_folder = os.path.abspath(args.allow_folder) if args.allow_folder else None
    args.unallow_folder = os.path.abspath(args.unallow_folder) if args.unallow_folder else None
    # Before anything that writes (starter config, logs, database) or prints
    # personal details (the greeting): diagnostics must be read-only and clean.
    if args.diagnostics:
        builtin_print(diagnostics.report(args.config))
        return 0
    if args.protect or args.unprotect:
        return _run_protect(args)
    if AS_ROOT:
        # A protected user's runs stop on a decisions file made by an older
        # Ensign (they can't change it): any sudo run brings it up to date.
        upgraded = protect.upgrade_all()
        if upgraded:
            print(f"[ensign] Upgraded the protected decisions of {len(upgraded)} "
                  f"user{'s' if len(upgraded) != 1 else ''} for this version of Ensign.")
    if args.protected and not AS_ROOT:
        print("[bold red]✗[/bold red] --protected changes your protected decisions, which only root "
              "can write. Run it with sudo: sudo ensign-scan --protected ...")
        return 1
    # Protected mode (protect.py): before anything reads your own config.
    protected = None
    if not AS_ROOT:
        try:
            protected = protect.status()
        except protect.Unsafe as exc:
            print(f"[bold red]✗ Protected mode:[/bold red] {shown(str(exc))}")
            print("Nothing was scanned. Your own config isn't used instead: in protected mode it never is.")
            return 1
        if protected:
            refusal = _protected_refusal(args)
            if refusal:
                print(f"[bold red]✗[/bold red] {refusal}")
                return 1
            allowlist.show_protected_commands()
            persistence.show_protected_commands()
    # Before the starter config: it must never be written next to an old
    # config that's about to move into the new place.
    moved, not_moved = migrate.move_legacy_folders(args.config)
    if moved:
        print("[green]Moved Ensign's folders to their new names (ensign-scan, since 0.8.1):[/green]")
        for line in moved:
            print(shown(line))
        print("If a script or timer names an old path, update it.")
    try:
        if protected:
            config = dataclasses.replace(Config.load(protected.config), decisions_db=protected.decisions)
        else:
            if not args.config:
                ensure_default_config()
            config = Config.load(args.config)
    except ValueError as exc:   # a malformed config, TOML syntax errors included
        print(f"[bold red]✗ Config error:[/bold red] {shown(str(exc))}")
        print("Nothing was scanned. Fix the setting named above and run again.")
        return 1
    if protected:
        print(f"[ensign] Protected: your config and decisions are root's copies. Change the "
              f"config with: sudoedit {shown(str(protected.config))}")
    # Still on the pre-0.8.1 folders: say so before the run and again after
    # it, where it isn't scrolled away under the scan.
    notice = legacy_notice(config, not_moved)
    if notice:
        _print_legacy(notice)
    try:
        return _after_config(args, config)
    finally:
        if notice:
            _print_legacy(notice)
            _ended_with_gap = False


def _protected_refusal(args) -> str | None:
    """Why this run can't go ahead in protected mode, or None."""
    if args.config or os.environ.get("ENSIGN_CONFIG"):
        return ("You are protected, so your runs only use root's copy of your config: "
                "--config and $ENSIGN_CONFIG aren't used. If you didn't set ENSIGN_CONFIG "
                "yourself, find out what did (your shell's startup files, for a start).")
    if (args.allow or args.unallow or args.allow_folder or args.unallow_folder
            or args.acknowledge or args.acknowledge_all):
        return ("You are protected, so your allowances and acknowledged startup entries are "
                "root's, and your user can't change them. Change them with sudo and --protected, "
                "for example: sudo ensign-scan --protected --allow PATH. Nothing was changed.")
    return None


def _protected_writer(scanner: Scanner):
    """For sudo ... --protected: (engine on the user's protected decisions,
    with root's own records as the evidence; the log for acknowledgments),
    or None with the reason printed."""
    from ensign_scan.db import make_protected_writer
    try:
        uid = protect.target_uid()
    except protect.CantProtect as exc:
        print(f"[bold red]✗ {shown(str(exc))}[/bold red]")
        return None
    path = protect.decisions_path(uid)
    if not protect.is_protected(uid) or not path.is_file():
        print("[bold red]✗ You aren't protected,[/bold red] so there are no protected decisions to "
              "change. Without --protected, sudo changes root's own; as yourself, your own. "
              "To protect yours: sudo ensign-scan --protect")
        return None
    why = protect.trust.untrusted_reason(path)
    if why:
        print(f"[bold red]✗ Your protected decisions file isn't safe to use:[/bold red] {shown(why)}")
        return None
    allowlist.use_protected_decisions()
    persistence.show_protected_commands()
    print(f"[ensign] Changing your protected decisions ({shown(str(path))}). The evidence that a "
          f"file was flagged is root's own scan.")
    return (make_protected_writer(path, scanner.engine.url.database),
            protect.data_dir(uid) / "persistence_acknowledged.log")


def _run_protect(args) -> int:
    """sudo ensign-scan --protect / --unprotect (protect.py)."""
    from ensign_scan.config import EXAMPLE_CONFIG, _user_config_to_copy
    try:
        uid = protect.target_uid()
        if args.unprotect:
            if protect.unprotect(uid, _confirm(args.yes)):
                print("[green]✓ Unprotected.[/green] Your next run uses your own config and database.")
            return 0
        copied_from, text = _user_config_to_copy()
        found = protect.protect(uid, text if copied_from else EXAMPLE_CONFIG, copied_from,
                                _confirm(args.yes))
    except protect.CantProtect as exc:
        print(f"[bold red]✗ {shown(str(exc))}[/bold red]")
        return 1
    if found:
        print("[green]✓ Protected.[/green] Your own runs now use:")
        print(f"  config:    {shown(str(found.config))}")
        print(f"  decisions: {shown(str(found.decisions))} (empty)")
        print(f"Change the config with: sudoedit {shown(str(found.config))}")
        print("Your own ~/.config/ensign-scan/config.toml isn't read any more. "
              "Undo all this with: sudo ensign-scan --unprotect")
        print("Allow files and acknowledge startup entries with sudo and --protected, for example: "
              "sudo ensign-scan --protected --allow PATH. Your runs show what needs it, as before.")
    return 0


def _print_legacy(notice: str) -> None:
    # Line by line: shown() writes a newline out as "\\n".
    for line in notice.splitlines():
        print(f"[yellow]{shown(line)}[/yellow]")


def _after_config(args, config: Config) -> int:
    secrets.load_custom(config)
    explanations.load_custom(config)
    pkgdb.configure(config.package_verification)
    setup_logging(config)

    # The read-only reports never write to the database, so they don't need
    # the lock and can run alongside a scan. run() handles --purge-missing
    # and --rescan-errors first, so with either one also given, the run
    # writes and must take the lock like any other.
    writes = (args.purge_missing or args.rescan_errors or args.allow or args.unallow
              or args.allow_folder or args.unallow_folder or args.acknowledge or args.acknowledge_all
              or args.update_rules)
    readonly = (args.verify_packages or args.suggest_fixes or args.list_allowed or args.list_allowed_all
                or args.list_infected
                or args.clamav_report
                or args.persistence)
    if readonly and not writes:
        return run(args, config)

    lock = RunLock(config.data_dir / "ensign.lock")
    try:
        lock.acquire()
    except AlreadyRunning as busy:
        who = f"pid {busy.holder_pid}" if busy.holder_pid else "another process"
        print(f"[yellow]Ensign is already running ({who}). Not starting a second one.[/yellow]")
        print(f"  Lock: {shown(busy.path)}")
        return EXIT_BUSY
    except OSError as exc:   # e.g. ELOOP: the lock file is a symlink (runlock.py)
        print(f"[bold red]✗ Couldn't take the run lock:[/bold red] {shown(lock.path)}: "
              f"{shown(exc.strerror or str(exc))}")
        print("  If it's a symlink, something other than Ensign put it there. Nothing was scanned.")
        return 1
    try:
        return run(args, config)
    finally:
        lock.release()


def _confirm(assume_yes: bool):
    """How --allow, --allow-folder and --acknowledge ask to confirm: --yes
    skips it; without a terminal to ask on (a script, a pipe), it refuses rather than guessing."""
    def ask(prompt: str) -> bool:
        if assume_yes:
            return True
        if not sys.stdin.isatty():
            print("  No terminal to confirm on; add --yes to go ahead without asking.")
            return False
        try:
            return input(prompt).strip().lower() in ("y", "yes")
        except EOFError:
            return False
    return ask


def _print_rules_breakdown(state: dict) -> None:
    """What --update-rules did with ClamAV's body signatures (.ndb)."""
    counts = state.get("counts", {})
    print(f"  Read {state.get('signatures_read', 0)} body signatures (.ndb) in "
          f"{state.get('build_seconds', 0)}s:")
    print(f"    {state.get('covered_by_sweep', 0)} left to the slices, which find them anyway")
    print(f"    {sum(counts.values())} became YARA rules ({counts.get('any', 0)} for any file, "
          f"{counts.get('pe', 0)} Windows executables, {counts.get('elf', 0)} Linux executables)")
    skipped = state.get("skipped", {})
    if skipped:
        print(f"    {sum(skipped.values())} skipped, since they can't be translated exactly:")
        for why, n in sorted(skipped.items(), key=lambda kv: (-kv[1], kv[0])):
            print(f"      {n:>7}  {shown(why)}")
    versions = ", ".join(f"{k} {v}" for k, v in sorted(state.get("versions", {}).items()))
    if versions:
        print(f"  Signature databases: {shown(versions)}")


def _print_rules_status(status) -> None:
    if status.ok:
        print(f"[green]✓ {shown(status.message)}[/green]")
    elif not status.failed:
        print(f"[yellow]! {shown(status.message)}[/yellow]")
    else:
        print(f"[bold red]✗ {shown(status.message)}[/bold red]")


def clamd_is_safe(scanner: Scanner) -> bool:
    """Check clamd once before any file is sent to it. False (with the
    reason printed) if it runs as root, or as you -- Ensign then scans nothing."""
    try:
        scanner.prepare_clamd()
    except ClamdUnsafe as exc:
        print(f"[red]✗ {shown(str(exc))}[/red]")
        return False
    return True


def run_persistence(args: argparse.Namespace, engine, log_path: Path) -> int:
    """--persistence, --acknowledge, --acknowledge-all, against the
    baseline in `engine` (your own database, or with --protected your
    protected decisions)."""
    confirm = _confirm(args.yes)
    if args.acknowledge and not args.acknowledge_all:
        # No package lookups: acknowledging one named entry needs only its
        # state now, and the package check can take a while.
        audit = persistence.run_audit(engine, str(HOME), check_packages=False)
        pending = {e.path for e in audit.new} | {e.path for _, e in audit.changed} | {r.path for r in audit.removed}
        named = [p for p in args.acknowledge if p in pending]
        if named:
            print(f"Acknowledge {len(named)} startup entr{'y' if len(named) == 1 else 'ies'} as "
                  f"{'it is' if len(named) == 1 else 'they are'} now?")
            for path in named:
                print_unwrapped(f"  {shown(path)}")
            if not confirm("Acknowledge? [y/N] "):
                print("Nothing acknowledged.")
                return 0
        persistence.acknowledge(engine, audit, args.acknowledge, log_path)
        return 0
    backend = pkgdb.active()
    if backend.name != "none":
        print(f"Checking startup entries, and asking {backend.label} about new or changed ones "
              f"outside your home folder…")
    audit = persistence.run_audit(engine, str(HOME))
    persistence.report(audit)
    if args.acknowledge_all and audit.pending:
        print()
        if not confirm(f"Acknowledge all {audit.pending} listed above as they are now? [y/N] "):
            print("Nothing acknowledged.")
            return EXIT_PERSISTENCE_PENDING
        count = persistence.acknowledge_all(engine, audit, log_path)
        print(f"[green]✓ Acknowledged {count}.[/green] Log: {shown(log_path)}")
        unreadable = persistence.unreadable_pending(audit)
        if unreadable:
            print(f"[yellow]! {unreadable} couldn't be read, so they stay listed. Acknowledge them "
                  f"with sudo: sudo ensign-scan {'--protected ' if args.protected else ''}"
                  f"--acknowledge-all[/yellow]")
            return EXIT_PERSISTENCE_PENDING
        return 0
    return EXIT_PERSISTENCE_PENDING if audit.pending else 0


def run(args: argparse.Namespace, config: Config) -> int:
    greet(config)

    scanner = Scanner(config)
    decisions, log_path = scanner.engine, config.data_dir / "persistence_acknowledged.log"
    if args.protected:
        writer = _protected_writer(scanner)
        if writer is None:
            return 1
        decisions, log_path = writer
    if args.allow or args.unallow or args.allow_folder or args.unallow_folder:
        for path in args.unallow:
            allowlist.unallow(decisions, path)
        if args.unallow_folder:
            allowlist.unallow_folder(decisions, args.unallow_folder, args.signature)
        for path in args.allow:
            allowlist.allow(decisions, path, _confirm(args.yes))
        if args.allow_folder:
            allowlist.allow_folder(decisions, args.allow_folder, args.signature, _confirm(args.yes))
        return 0
    if args.list_allowed or args.list_allowed_all:
        allowlist.list_allowed(scanner.engine, expand=args.list_allowed_all)
        return 0
    if args.list_infected:
        list_infected(scanner.engine, paths=args.targets or None, files_per_threat=None)
        return 0
    if args.persistence or args.acknowledge or args.acknowledge_all:
        return run_persistence(args, decisions, log_path)
    if args.clamav_report:
        if not scanner.clamd.ping():
            print("[red]✗ clamd is not answering on its socket.[/red] The file is scanned again "
                  "before a report is written, so clamd has to be running.")
            print(f"  Socket: {shown(config.clamd_socket)}")
            print("  Start it with: sudo systemctl start clamav-daemon")
            return 1
        if not clamd_is_safe(scanner):
            return 1
        fpreport.make_reports(scanner, config, args.clamav_report)
        return 0
    if args.update_rules:
        print("Building YARA rules from ClamAV's signatures. This reads every signature "
              "database, so it can take a minute…")
        status = scanner.prepare_big_rules(by_hand=True)
        _print_rules_status(status)
        if status.rebuilt:
            _print_rules_breakdown(bigrules.read_state(config.data_dir))
        return 0 if status.loaded is not None else 1
    if args.purge_missing:
        scanner.purge_missing()
        return 0
    if args.rescan_errors:
        if not scanner.clamd.ping():
            print("[red]✗ clamd is not answering on its socket.[/red]")
            return 1
        if not clamd_is_safe(scanner):
            return 1
        scanner.rescan_errors()
        return 0
    if args.verify_packages:
        backend = pkgdb.active()
        if backend.name != "none":
            print(f"Checking every installed file against {backend.label}'s records. On a system "
                  f"with many packages this can take a while; Ctrl+C stops it.")
            try:
                result = backend.verify_all()
            except KeyboardInterrupt:
                # subprocess.run has already stopped the package manager.
                print(f"\n[yellow]Stopped. {backend.label} was only reading files; nothing was changed.[/yellow]")
                return 130
            package_report(scanner.engine, result, backend)
        else:
            print(f"[yellow]Package verification isn't available: {backend.reason}. Skipping.[/yellow]")
        return 0
    if args.suggest_fixes:
        suggest_fixes(scanner.engine, paths=args.targets or None)
        return 0
    auto = " (auto)" if config.max_workers <= 0 else ""
    workers = scanner.workers
    if config.max_workers <= 0 and scanner.clamd_max_threads is None:
        # The fallback, said out loud: a quiet 5 looked like a real answer.
        auto = " (auto; couldn't read clamd's MaxThreads, so a safe default)"
    print(f" Workers:  {workers}{auto}")
    if config.never_open_credentials:
        print("[yellow]! never_open_credentials is on: SSH keys in ~/.ssh, saved-password "
              "databases and gcloud's credential databases in their usual places aren't "
              "scanned when their header checks out. Anything running as you can write "
              "there.[/yellow]")
    scan = not args.no_scan
    hint = scanner.thread_hint() if scan else None  # --no-scan doesn't use clamd
    if hint:
        print(f"[dim]{hint}[/dim]")

    if scan and not scanner.clamd.ping():
        print("[red]✗ clamd is not answering on its socket.[/red]")
        print(f"  Socket: {shown(config.clamd_socket)}")
        print("  Start it with: sudo systemctl start clamav-daemon")
        return 1
    if scan:
        if not clamd_is_safe(scanner):
            return 1
        print("[green]✓ clamd is up.[/green]")
        if config.signature_max_age_days > 0:
            sig_age = scanner.clamd.signature_age_days()
            if sig_age is not None and sig_age > config.signature_max_age_days:
                print(f"[yellow]! Virus signatures are {sig_age} days old "
                      f"(threshold: {config.signature_max_age_days}). Run: sudo freshclam[/yellow]")
        if args.sweep or config.sweep_huge_files:
            # Before the scan, so a failed rule update is the first thing
            # you see, not something buried after hours of scanning.
            _print_rules_status(scanner.prepare_big_rules())
        print()

    # Before the scan: a file whose allowance is gone counts as infected
    # again, and so gets scanned again (allowlist.reconcile).
    regained = allowlist.reconcile(scanner.engine)
    findings.tidy(scanner.engine)
    if regained:
        print(f"[yellow]! {regained} file{'s' if regained != 1 else ''} recorded as allowed "
              f"{'have' if regained != 1 else 'has'} no allowance any more, so "
              f"{'they count' if regained != 1 else 'it counts'} as infected again.[/yellow]")

    targets = args.targets or config.scan_targets
    start = time.time()
    print("=== Starting Scan ===")
    unreadable: dict[str, str] = {}
    missing: set[str] = set()
    for target in targets:
        print(f"\nChecking [violet]{shown(target)}[/violet]:")
        stats = scanner.scan_tree(target, scan=scan)
        unreadable.update(stats.unreadable_dirs)
        missing |= stats.missing

    print(f"\nExecution time: {time.time() - start:.1f} seconds")

    if scan and not args.skip_rescans:
        print("\n=== Processing Rescans ===")
        scanner.rescan_infected()
        scanner.rescan_errors()
        scanner.rescan_stale()
    if scan and (args.sweep or config.sweep_huge_files):
        print("\n=== Sweeping Files Too Large for ClamAV ===")
        scanner.sweep_huge([str(t) for t in targets])

    summary = scan_summary(scanner.engine, paths=args.targets or None)
    if missing:
        print(f"Broken symlinks / vanished files skipped: {len(missing)}")
    error_summary(scanner.engine, paths=args.targets or None)
    incomplete_report(scanner.engine, paths=args.targets or None)
    unreadable_report(unreadable)
    integrity_report(scanner.integrity_changes)
    unsaved_infected = [u for u in scanner.unsaved if u.status == "infected"]
    evidence.refresh(scanner.engine)   # second opinions on what's flagged, for the report below
    infected = list_infected(scanner.engine, paths=args.targets or None,
                             more_elsewhere=bool(unsaved_infected))
    format_mismatch_report(scanner.engine, paths=args.targets or None)
    allowlist.new_in_allowed_folders(scanner.engine, paths=args.targets or None)
    allowlist.allowed_report(scanner.engine, paths=args.targets or None)
    # Results the database refused are reported (and alerted on) from memory,
    # so a failed save can never turn a detection into "nothing found".
    infected += unsaved_report(scanner.unsaved)
    if unsaved_infected:
        summary = {**summary, "infected": summary.get("infected", 0) + len({u.path for u in unsaved_infected})}
    suggest_fixes(scanner.engine, paths=args.targets or None)
    notify.send(summary, infected, config.infected_alert_seconds,
                only_when_gaming=config.infected_alert_only_while_gaming,
                interactive=sys.stdin.isatty(),
                state_path=config.data_dir / "alert_state.json")

    print("\n=== All Scans Finished ===")
    print("-" * 71)
    print(" All finished.")
    print(" Feel free to call upon me again.")
    print("     — Ensign")
    print()
    global _ended_with_gap
    _ended_with_gap = True
    # Non-zero when something needs attention, so a script or a scheduled
    # run can act on it: infected files (in the database or unsaved) first,
    # then results missing from the database. An infected file that has
    # since been deleted is still listed above, but no longer counts here.
    if any(os.path.lexists(os.fsencode(item["filepath"])) for item in infected):
        return EXIT_INFECTED
    return EXIT_UNSAVED if scanner.unsaved else 0


if __name__ == "__main__":
    raise SystemExit(main())
