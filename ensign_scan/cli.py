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
import os
import time
from builtins import print as builtin_print
from importlib.metadata import PackageNotFoundError, version as dist_version

from rich import print

from ensign_scan.config import HOME, HOSTNAME, Config, ensure_default_config, legacy_notice
from ensign_scan import (
    allowlist, bigrules, diagnostics, explanations, fpreport, logsetup, notify, persistence, pkgdb,
    secrets,
)
from ensign_scan.fsutil import print_unwrapped, shown
from ensign_scan.runlock import AlreadyRunning, RunLock
from ensign_scan.reports import (
    error_summary,
    incomplete_report,
    integrity_report,
    list_infected,
    package_report,
    scan_summary,
    suggest_fixes,
    unreadable_report,
    unsaved_report,
)
from ensign_scan.scanner import ClamdRunsAsRoot, Scanner

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
                        help="List the files you've allowed, then exit")
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
    return args


def setup_logging(config: Config) -> None:
    logsetup.setup(config)


def greet(config: Config) -> None:
    print()
    print(f" Greetings, {HOME.name}!")
    print("-" * 71)
    print(" I, Ensign, will start scanning your system shortly…")
    print(f" Host:     {HOSTNAME}")
    print(f" Config:   {shown(config.source)}")
    print(f" Database: {shown(config.data_dir / 'system.db')}")
    print("-" * 71)


def main() -> int:
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
    if not args.config:
        ensure_default_config()
    try:
        config = Config.load(args.config)
    except ValueError as exc:   # a malformed config, TOML syntax errors included
        print(f"[bold red]✗ Config error:[/bold red] {shown(str(exc))}")
        print("Nothing was scanned. Fix the setting named above and run again.")
        return 1
    # Still on the pre-0.8.1 folders: say so before the run and again after
    # it, where it isn't scrolled away under the scan.
    notice = legacy_notice(config)
    if notice:
        _print_legacy(notice)
    try:
        return _after_config(args, config)
    finally:
        if notice:
            _print_legacy(notice)


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
    readonly = (args.verify_packages or args.suggest_fixes or args.list_allowed or args.clamav_report
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
    reason printed) if it runs as root -- Ensign then scans nothing."""
    try:
        scanner.prepare_clamd()
    except ClamdRunsAsRoot as exc:
        print(f"[red]✗ {exc}[/red]")
        return False
    return True


def run_persistence(args: argparse.Namespace, config: Config, scanner: Scanner) -> int:
    """--persistence, --acknowledge, --acknowledge-all."""
    log_path = config.data_dir / "persistence_acknowledged.log"
    confirm = _confirm(args.yes)
    if args.acknowledge and not args.acknowledge_all:
        # No package lookups: acknowledging one named entry needs only its
        # state now, and the package check can take a while.
        audit = persistence.run_audit(scanner.engine, str(HOME), check_packages=False)
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
        persistence.acknowledge(scanner.engine, audit, args.acknowledge, log_path)
        return 0
    backend = pkgdb.active()
    if backend.name != "none":
        print(f"Checking startup entries, and asking {backend.label} about new or changed ones "
              f"outside your home folder…")
    audit = persistence.run_audit(scanner.engine, str(HOME))
    persistence.report(audit)
    if args.acknowledge_all and audit.pending:
        print()
        if not confirm(f"Acknowledge all {audit.pending} listed above as they are now? [y/N] "):
            print("Nothing acknowledged.")
            return EXIT_PERSISTENCE_PENDING
        count = persistence.acknowledge_all(scanner.engine, audit, log_path)
        print(f"[green]✓ Acknowledged {count}.[/green] Log: {shown(log_path)}")
        unreadable = persistence.unreadable_pending(audit)
        if unreadable:
            print(f"[yellow]! {unreadable} couldn't be read, so they stay listed. Acknowledge them "
                  f"with sudo: sudo ensign-scan --acknowledge-all[/yellow]")
            return EXIT_PERSISTENCE_PENDING
        return 0
    return EXIT_PERSISTENCE_PENDING if audit.pending else 0


def run(args: argparse.Namespace, config: Config) -> int:
    greet(config)

    scanner = Scanner(config)
    if args.allow or args.unallow or args.allow_folder or args.unallow_folder:
        for path in args.unallow:
            allowlist.unallow(scanner.engine, path)
        if args.unallow_folder:
            allowlist.unallow_folder(scanner.engine, args.unallow_folder, args.signature)
        for path in args.allow:
            allowlist.allow(scanner.engine, path, _confirm(args.yes))
        if args.allow_folder:
            allowlist.allow_folder(scanner.engine, args.allow_folder, args.signature, _confirm(args.yes))
        return 0
    if args.list_allowed:
        allowlist.list_allowed(scanner.engine)
        return 0
    if args.persistence or args.acknowledge or args.acknowledge_all:
        return run_persistence(args, config, scanner)
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
    infected = list_infected(scanner.engine, paths=args.targets or None,
                             more_elsewhere=bool(unsaved_infected))
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
    # Non-zero when something needs attention, so a script or a scheduled
    # run can act on it: infected files (in the database or unsaved) first,
    # then results missing from the database. An infected file that has
    # since been deleted is still listed above, but no longer counts here.
    if any(os.path.lexists(os.fsencode(item["filepath"])) for item in infected):
        return EXIT_INFECTED
    return EXIT_UNSAVED if scanner.unsaved else 0


if __name__ == "__main__":
    raise SystemExit(main())
