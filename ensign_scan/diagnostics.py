"""Privacy-safe diagnostics for bug reports (`ensign-scan --diagnostics`).

Prints what a maintainer needs to reproduce a problem -- versions, settings
and counts -- and nothing that identifies the user or their files. It
writes nothing: no starter config, no log files, no database. It only reads.

Two layers keep the output safe:

  1. By construction: every field is a version string, a number, a yes/no
     or a fixed category. Paths, filenames, hashes, threat names and the
     hostname are never collected in the first place -- only counted.
  2. As a safety net: before printing, _scrub() replaces the home
     directory, username and hostname anywhere they still appear (an
     unexpected error message, say). Layer 1 is the real protection;
     layer 2 catches what layer 1 didn't anticipate.
"""
from __future__ import annotations

import os
import platform
import re
import sqlite3
import sys
import tomllib
from importlib.metadata import PackageNotFoundError, distribution, version as dist_version
from pathlib import Path

from . import pkgdb
from .clamd import ClamdClient
from .config import DEFAULT_CONFIG_PATH, DEFAULT_DATA_DIR, HOME, HOSTNAME, Config

# Settings whose values are numbers or booleans -- safe to print as-is.
_SAFE_VALUE_SETTINGS = (
    "max_workers", "rescan_after_days", "rescan_after_signature_updates",
    "infected_alert_seconds", "infected_alert_only_while_gaming",
    "log_keep_days", "log_max_total_mb", "signature_max_age_days",
    "package_verification",
)

_DEFAULT_SOCKET = Config.clamd_socket  # the dataclass default


def _pkg_version(name: str) -> str:
    try:
        return dist_version(name)
    except PackageNotFoundError:
        return "not installed"


def _install_method() -> str:
    """How ensign-scan was installed, as a category -- never the path."""
    try:
        dist = distribution("ensign-scan")
    except PackageNotFoundError:
        return "running from source (not installed)"
    # PEP 610: pip records direct_url.json for installs from a local
    # directory, a git URL, or in editable mode -- not for PyPI installs.
    if dist.read_text("direct_url.json"):
        return "from source (local path or git)"
    if "pipx" in Path(sys.prefix).parts:
        return "pipx"
    if sys.prefix != sys.base_prefix:
        return "pip (virtual environment)"
    return "pip (system or user site)"


def _os_name() -> str:
    try:
        text = Path("/etc/os-release").read_text()
    except OSError:
        return "unknown"
    match = re.search(r'^PRETTY_NAME="?([^"\n]*)"?', text, re.MULTILINE)
    return match.group(1) if match else "unknown"


def _config_section(args_config: str | None) -> tuple[list[str], Config]:
    """Where the config came from and what it sets -- never its paths.

    Also returns the loaded Config (defaults if none could be loaded) so the
    other sections use the same one without loading it twice.
    """
    explicit = args_config or os.environ.get("ENSIGN_CONFIG")
    if args_config:
        origin = "--config flag"
    elif os.environ.get("ENSIGN_CONFIG"):
        origin = "$ENSIGN_CONFIG"
    else:
        origin = "default location"
    path = Path(explicit) if explicit else DEFAULT_CONFIG_PATH

    if not path.is_file():
        if explicit:
            return [f"  source:              {origin} (file not found)"], Config()
        return ["  source:              built-in defaults (no config file)"], Config()

    try:
        raw = tomllib.loads(path.read_text())
        config = Config.load(path)
    except Exception as exc:  # noqa: BLE001 -- a broken config is exactly what a bug report needs to show
        return [f"  source:              {origin} (could not be loaded: {type(exc).__name__})"], Config()

    hosts = raw.get("hosts", {})
    if not isinstance(hosts, dict):
        hosts = {}
    lines = [
        f"  source:              {origin}",
        f"  host sections:       {len(hosts)} (one matches this machine: "
        f"{'yes' if HOSTNAME in hosts else 'no'})",
    ]
    for name in _SAFE_VALUE_SETTINGS:
        lines.append(f"  {name + ':':<21}{getattr(config, name)}")
    lines += [
        f"  scan_targets:        {len(config.scan_targets)} entries",
        f"  excludes:            {len(config.excludes)} entries",
        f"  snapshot_roots:      {len(config.snapshot_roots)} entries",
        f"  clamd_socket:        {'default' if config.clamd_socket == _DEFAULT_SOCKET else 'custom'}",
        f"  data_dir:            {'default' if config.data_dir == DEFAULT_DATA_DIR else 'custom'}",
        f"  custom_secrets:      {sum(len(v) for v in config.custom_secrets.values() if isinstance(v, list))} entries",
        f"  custom_threats:      {len(config.custom_threats)} entries",
        f"  custom_pacman_reasons: {len(config.custom_pacman_reasons)} entries",
    ]
    return lines, config


def _packages_section(config: Config) -> list[str]:
    """Which package backend this run would use, and why if none."""
    backend = pkgdb.select(config.package_verification)
    if backend.name == "none":
        return ["  backend:             none", f"  reason:              {backend.reason}"]
    return [f"  backend:             {backend.name}"]


def _clamav_section(config: Config) -> list[str]:
    client = ClamdClient(config.clamd_socket, timeout=5.0)
    if not client.ping():
        return ["  clamd:               not answering on its socket"]
    try:
        # "ClamAV <engine>/<signature version>/<build date>" -- no local data.
        reply = client._command("VERSION")
    except OSError:
        reply = "unknown"
    age = client.signature_age_days()
    uid = client.daemon_uid()
    runs_as = "unknown" if uid is None else ("root (Ensign refuses to scan)" if uid == 0 else "unprivileged user")
    return [
        "  clamd:               answering",
        f"  version:             {reply}",
        f"  signature age:       {'unknown' if age is None else f'{age} days'}",
        f"  fd passing:          {'supported' if client.supports_fildes() else 'not supported (path scanning)'}",
        f"  clamd runs as:       {runs_as}",
    ]


def _database_section(config: Config) -> list[str]:
    """Counts by status, read through a read-only connection.

    The scanner's make_engine() creates tables and runs migrations, so it
    is deliberately not used here: diagnostics must never write.
    """
    db_path = Path(config.db_url.removeprefix("sqlite:///"))
    if not db_path.is_file():
        return ["  database:            not found (Ensign has not run yet)"]
    try:
        # resolve(): a relative data_dir is relative to the current directory,
        # same as for the scanner, but a file: URI must be absolute.
        conn = sqlite3.connect(f"{db_path.resolve().as_uri()}?mode=ro", uri=True, timeout=5)
        try:
            rows = conn.execute(
                "SELECT scan_status, COUNT(*) FROM files GROUP BY scan_status"
            ).fetchall()
            dirs = conn.execute("SELECT COUNT(*) FROM directories").fetchone()[0]
            last = conn.execute("SELECT MAX(last_scanned) FROM files").fetchone()[0]
        finally:
            conn.close()
    except sqlite3.Error as exc:
        return [f"  database:            could not be read ({type(exc).__name__})"]

    counts = dict(rows)
    lines = [
        f"  size:                {db_path.stat().st_size / 1_048_576:.1f} MB",
        f"  files tracked:       {sum(counts.values())}",
    ]
    for status in sorted(counts):
        lines.append(f"    {str(status) + ':':<19}{counts[status]}")
    lines += [
        f"  snapshot dirs:       {dirs}",
        f"  last scan (date):    {str(last)[:10] if last else 'never'}",
    ]
    return lines


def _scrub(text: str) -> str:
    """Safety net: replace home path, username and hostname if they slipped in.

    Longest first (the home path contains the username). Word boundaries
    keep a short username from mangling ordinary words, e.g. a user named
    "clam" must not turn "ClamAV" into "USERAV".

    "root" is skipped: it identifies no one, and replacing it would rewrite
    the "running as root" line itself. Any other username that is also a
    word in the output (say, "default") gets replaced there too -- that
    errs toward privacy, at the cost of a slightly garbled line.
    """
    home = str(HOME) if str(HOME) != "/" else ""  # "/" identifies no one either
    username = HOME.name if HOME.name != "root" else ""
    replacements = [(home, "/home/USER"), (username, "USER"), (HOSTNAME, "HOST")]
    for needle, placeholder in sorted(replacements, key=lambda r: -len(r[0])):
        if needle:
            text = re.sub(rf"(?<![\w.-]){re.escape(needle)}(?![\w.-])", placeholder, text)
    return text


def report(args_config: str | None) -> str:
    """Build the full diagnostics text."""
    config_lines, config = _config_section(args_config)
    lines = [
        "=== Ensign diagnostics ===",
        "(No paths, usernames, hostnames, file names or hashes are included.)",
        "",
        "Ensign",
        f"  ensign-scan:         {_pkg_version('ensign-scan')}",
        f"  install method:      {_install_method()}",
        f"  sqlalchemy:          {_pkg_version('sqlalchemy')}",
        f"  rich:                {_pkg_version('rich')}",
        "",
        "System",
        f"  python:              {platform.python_version()}",
        f"  os:                  {_os_name()}",
        f"  kernel:              {platform.release()}",
        f"  running as root:     {'yes' if os.geteuid() == 0 else 'no'}",
        "",
        "Config",
        *config_lines,
    ]
    lines += ["", "Packages", *_packages_section(config)]
    lines += ["", "ClamAV", *_clamav_section(config)]
    lines += ["", "Database", *_database_section(config)]
    return _scrub("\n".join(_align(line) for line in lines))


def _align(line: str) -> str:
    """Line up "  label: value" rows into one column, whatever the label length."""
    match = re.match(r"^(\s+)([^:]+):\s*(.*)$", line)
    if not match:
        return line
    indent, label, value = match.groups()
    return f"{indent}{(label + ':').ljust(36 - len(indent))}{value}"
