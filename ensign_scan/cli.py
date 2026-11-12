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

from ensign_scan.config import HOME, HOSTNAME, Config, ensure_default_config
from ensign_scan import allowlist, diagnostics, explanations, logsetup, notify, pkgdb, secrets
from ensign_scan.fsutil import shown
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
                        help="Config file (default: ~/.config/ensign/config.toml)")
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
                             "slices (as sweep_huge_files = true does for every scan)")
    parser.add_argument("--allow", metavar="PATH", action="append", default=[],
                        help="Mark a file ClamAV flagged as a false positive (this exact content and "
                             "signature only), then exit. Asks to confirm. Can be given more than once.")
    parser.add_argument("--unallow", metavar="PATH", action="append", default=[],
                        help="Undo --allow for a file, then exit")
    parser.add_argument("--list-allowed", action="store_true",
                        help="List the files you've allowed, then exit")
    parser.add_argument("--yes", action="store_true",
                        help="Don't ask to confirm --allow (for scripts)")
    parser.add_argument("--suggest-fixes", action="store_true",
                        help="List files clamd could not read, grouped by directory, then exit (no full scan). "
                             "Scoped to any targets given.")
    return parser.parse_args()


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
    # Before anything that writes (starter config, logs, database) or prints
    # personal details (the greeting): diagnostics must be read-only and clean.
    if args.diagnostics:
        builtin_print(diagnostics.report(args.config))
        return 0
    if not args.config:
        ensure_default_config()
    config = Config.load(args.config)
    secrets.load_custom(config)
    explanations.load_custom(config)
    pkgdb.configure(config.package_verification)
    setup_logging(config)

    # The read-only reports never write to the database, so they don't need
    # the lock and can run alongside a scan. run() handles --purge-missing
    # and --rescan-errors first, so with either one also given, the run
    # writes and must take the lock like any other.
    writes = args.purge_missing or args.rescan_errors or args.allow or args.unallow
    if (args.verify_packages or args.suggest_fixes or args.list_allowed) and not writes:
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
    """How --allow asks to confirm: --yes skips it; without a terminal to
    ask on (a script, a pipe), it refuses rather than guessing."""
    def ask(prompt: str) -> bool:
        if assume_yes:
            return True
        if not sys.stdin.isatty():
            print("  No terminal to confirm on; add --yes to allow without asking.")
            return False
        try:
            return input(prompt).strip().lower() in ("y", "yes")
        except EOFError:
            return False
    return ask


def clamd_is_safe(scanner: Scanner) -> bool:
    """Check clamd once before any file is sent to it. False (with the
    reason printed) if it runs as root -- Ensign then scans nothing."""
    try:
        scanner.prepare_clamd()
    except ClamdRunsAsRoot as exc:
        print(f"[red]✗ {exc}[/red]")
        return False
    return True


def run(args: argparse.Namespace, config: Config) -> int:
    greet(config)

    scanner = Scanner(config)
    if args.allow or args.unallow:
        for path in args.unallow:
            allowlist.unallow(scanner.engine, path)
        for path in args.allow:
            allowlist.allow(scanner.engine, path, _confirm(args.yes))
        return 0
    if args.list_allowed:
        allowlist.list_allowed(scanner.engine)
        return 0
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
    print(f" Workers:  {scanner.workers}{auto}")
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
