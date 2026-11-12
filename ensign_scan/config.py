"""Configuration for Ensign.

Design for multi-machine use:

  * The code contains NO machine-specific values. Everything lives in a
    TOML file, so any user on any box gets sane defaults out of the box.
  * Config search order: --config flag > $ENSIGN_CONFIG > 
    ~/.config/ensign/config.toml > built-in defaults.
  * Per-machine differences go in [hosts.<hostname>] sections of the
    SAME file, so you can sync one config across all your machines and
    each one picks up its own overrides.
  * "~" in the config file always means the *invoking* user's home,
    even under sudo (resolved via SUDO_USER + the passwd database, so
    it also works for homes outside /home).
"""
from __future__ import annotations

import os
import pwd
import socket
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .pkgdb import CHOICES as PACKAGE_VERIFICATION_CHOICES


# ----------------------------------------------------------------------
# Identity: who is really running this, and on which machine?
# ----------------------------------------------------------------------

def real_home() -> Path:
    """Home directory of the invoking user, even under sudo.

    Path.home() returns /root under sudo. SUDO_USER preserves the real
    account, and the passwd database gives its true home directory —
    no assumption that homes live under /home.
    """
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except KeyError:
            pass  # SUDO_USER set but unknown; fall through
    return Path.home()


HOME = real_home()
HOSTNAME = socket.gethostname()

DEFAULT_DATA_DIR = HOME / ".local" / "share" / "ensign"
DEFAULT_CONFIG_PATH = HOME / ".config" / "ensign" / "config.toml"

_DEFAULT_TARGETS = ("~/Downloads", "~/Documents", "~/Pictures", "~")


def _expand(value: str | Path) -> Path:
    """Expand ~ and environment variables relative to the invoking user."""
    text = os.path.expandvars(str(value))
    if text == "~":
        return HOME
    if text.startswith("~/"):
        return HOME / text[2:]
    return Path(text)


# ----------------------------------------------------------------------
# The config object
# ----------------------------------------------------------------------

# Allowed range for rescan_after_signature_updates in a config file.
# Below 7 is a full pass of a big machine every few days; above 31 leaves
# clean files unchecked for over a month. 0 (off) is always allowed.
SIGNATURE_RESCAN_MIN = 7
SIGNATURE_RESCAN_MAX = 31


@dataclass(frozen=True)
class Config:
    db_url: str = f"sqlite:///{DEFAULT_DATA_DIR / 'system.db'}"
    log_file: Path = DEFAULT_DATA_DIR / "error_logs.txt"
    clamd_socket: str = "/var/run/clamav/clamd.ctl"
    # 0 = auto: sized from clamd's MaxThreads and CPU count at startup.
    max_workers: int = 0
    # clamscan runs at once for files too large for clamd. 0 = auto: as many
    # as free memory allows (each loads its own copy of the signatures),
    # up to half the CPU cores. Always at least one.
    max_clamscans: int = 0
    rescan_after_days: int = 90
    # Rescan a clean file once the signature database has moved this many
    # versions past the one it was last scanned under. Usually about one
    # version per day, so this is roughly "days". A config file may set
    # SIGNATURE_RESCAN_MIN..SIGNATURE_RESCAN_MAX (clamped, with a warning),
    # or 0 to turn it off.
    rescan_after_signature_updates: int = 7
    # Seconds before the infected-files desktop alert closes itself, so it
    # doesn't sit over a game until dismissed. 0 = stays until dismissed.
    infected_alert_seconds: int = 60
    # Error logs are one file per run under <data_dir>/logs/. Delete runs
    # older than this many days (0 = never)...
    log_keep_days: int = 90
    # ...and, if the folder is still bigger than this many MB, the oldest
    # first (0 = no size limit). The size limit wins when the two disagree.
    log_max_total_mb: int = 2048
    # Apply infected_alert_seconds only while a Steam game is running;
    # otherwise the alert stays until dismissed.
    infected_alert_only_while_gaming: bool = True
    # Warn (not block) if the loaded virus-signature database is older
    # than this. Usually means freshclam has silently stopped running.
    signature_max_age_days: int = 3
    # Which package manager answers "which package owns this file, and is
    # it unmodified?": "auto" (from /etc/os-release), "off", or a backend
    # name. See ensign_scan/pkgdb.
    package_verification: str = "auto"
    snapshot_roots: tuple[str, ...] = ()
    # Path prefixes to skip entirely (high-churn temp/cache trees).
    excludes: tuple[str, ...] = ()
    scan_targets: tuple[Path, ...] = tuple(_expand(t) for t in _DEFAULT_TARGETS)

    # User-supplied additions to secrets.py's pattern lists and
    # explanations.py's curated lookup tables, from the [custom_secrets],
    # [custom_threats] and [custom_pacman_reasons] config sections.
    # Raw dicts, straight from TOML -- secrets.load_custom() and
    # explanations.load_custom() validate and apply them (additive-only).
    custom_secrets: dict = field(default_factory=dict)
    custom_threats: dict = field(default_factory=dict)
    custom_pacman_reasons: dict = field(default_factory=dict)

    # Where this config came from, for the startup banner. Not a setting.
    source: str = field(default="built-in defaults", compare=False)

    # -- loading ------------------------------------------------------

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Config":
        """Load config: explicit path > $ENSIGN_CONFIG > default location.

        An explicitly requested file that doesn't exist is an error; the
        default location merely falling back to defaults is not.
        """
        explicit = path or os.environ.get("ENSIGN_CONFIG")
        cfg_path = Path(explicit) if explicit else DEFAULT_CONFIG_PATH

        if not cfg_path.is_file():
            if explicit:
                raise FileNotFoundError(f"Config file not found: {cfg_path}")
            return cls()

        with open(cfg_path, "rb") as f:
            data = tomllib.load(f)

        # Per-machine overrides: [hosts.<hostname>] beats top level.
        # TOML allows any value type here, so check before trusting it.
        # A malformed section is an error, not a warning: skipping it would
        # run without this machine's excludes/scan_targets, and you'd think
        # the scan was doing what the file says.
        hosts = data.pop("hosts", {})
        if not isinstance(hosts, dict):
            raise ValueError(
                f"{cfg_path}: 'hosts' must be a table of [hosts.<hostname>] "
                f"sections, got {type(hosts).__name__}")
        host_overrides = hosts.get(HOSTNAME, {})
        if not isinstance(host_overrides, dict):
            raise ValueError(
                f"{cfg_path}: [hosts.{HOSTNAME}] must be a table of settings, "
                f"got {type(host_overrides).__name__}")
        merged = {**data, **host_overrides}
        return cls._from_dict(merged, source=str(cfg_path))

    @classmethod
    def _from_dict(cls, raw: dict, source: str) -> "Config":
        known = {
            "data_dir", "clamd_socket", "max_workers", "max_clamscans",
            "rescan_after_days", "rescan_after_signature_updates",
            "infected_alert_seconds", "infected_alert_only_while_gaming",
            "log_keep_days", "log_max_total_mb",
            "scan_targets", "snapshot_roots",
            "excludes", "signature_max_age_days", "package_verification",
            "custom_secrets", "custom_threats", "custom_pacman_reasons",
        }
        for key in raw.keys() - known:
            print(f"[ensign] Warning: unknown config key {key!r} ignored")

        data_dir = _expand(raw.get("data_dir", DEFAULT_DATA_DIR))
        kwargs: dict = {
            "db_url": f"sqlite:///{data_dir / 'system.db'}",
            "log_file": data_dir / "error_logs.txt",
            "source": source,
        }
        for key in ("clamd_socket", "max_workers", "max_clamscans", "rescan_after_days",
                    "rescan_after_signature_updates", "infected_alert_seconds",
                    "infected_alert_only_while_gaming", "log_keep_days",
                    "log_max_total_mb", "signature_max_age_days"):
            if key in raw:
                kwargs[key] = raw[key]
        if "scan_targets" in raw:
            kwargs["scan_targets"] = tuple(_expand(t) for t in raw["scan_targets"])
        if "snapshot_roots" in raw:
            kwargs["snapshot_roots"] = tuple(str(_expand(t)) for t in raw["snapshot_roots"])
        if "excludes" in raw:
            kwargs["excludes"] = tuple(str(_expand(t)).rstrip("/") for t in raw["excludes"])
        for key in ("custom_secrets", "custom_threats", "custom_pacman_reasons"):
            if key in raw:
                kwargs[key] = raw[key]
        if "package_verification" in raw:
            # A typo here must not quietly mean "off": fail loudly, like a
            # malformed hosts table.
            value = raw["package_verification"]
            if value not in PACKAGE_VERIFICATION_CHOICES:
                choices = ", ".join(f'"{c}"' for c in PACKAGE_VERIFICATION_CHOICES)
                raise ValueError(f"{source}: package_verification must be one of {choices}, got {value!r}")
            kwargs["package_verification"] = value
        n = kwargs.get("rescan_after_signature_updates")
        if isinstance(n, int) and n != 0:
            clamped = min(max(n, SIGNATURE_RESCAN_MIN), SIGNATURE_RESCAN_MAX)
            if clamped != n:
                print(f"[ensign] Warning: rescan_after_signature_updates = {n} is outside "
                      f"{SIGNATURE_RESCAN_MIN}-{SIGNATURE_RESCAN_MAX}; using {clamped}")
                kwargs["rescan_after_signature_updates"] = clamped
        return cls(**kwargs)

    @property
    def data_dir(self) -> Path:
        return self.log_file.parent

    @property
    def log_dir(self) -> Path:
        return self.data_dir / "logs"


# ----------------------------------------------------------------------
# First-run template
# ----------------------------------------------------------------------
# EXAMPLE_CONFIG must stay identical to config.example.toml at the repo
# root (config_test.py checks this). Edit the .toml, then copy it here.

EXAMPLE_CONFIG = """\
# Ensign configuration.
# Paths may use "~" (the invoking user's home, sudo-safe) and $VARS.
# Anything set under [hosts.<hostname>] overrides the values above it
# on that machine only — so this one file can be synced everywhere.

# Where the database and error log live.
# data_dir = "~/.local/share/ensign"

# Worker threads. 0 = auto (sized from clamd's MaxThreads and CPU count).
max_workers = 0

# Files larger than clamd scans go to clamscan, which loads its own copy of
# the signatures (about as much memory as clamd uses). How many may run at
# once: 0 = auto -- as many as free memory allows, keeping a reserve, up to
# half your CPU cores, checked again before each one starts. Always at
# least one. Raising MaxFileSize in clamd.conf (up to 2000M) avoids
# clamscan for most files, and is faster still.
max_clamscans = 0
rescan_after_days = 90

# Rescan an unchanged, previously-clean file once the virus-signature
# database has moved this many versions past the one it was last scanned
# under. The database moves about once a day, so this is roughly "days":
# 7 = every file is re-checked about weekly, 31 = about monthly. Allowed
# range 7-31 (anything else is clamped, with a warning); 0 turns it off.
# Each rescan is a full clamd pass over everything that is out of date,
# which on a large machine (millions of files) is a long one.
rescan_after_signature_updates = 7

# Seconds before the "infected files" desktop alert closes itself, so it
# doesn't sit on top of a game until you dismiss it. Longer than a normal
# alert on purpose. 0 = stays until you dismiss it. Other alerts are not
# affected.
infected_alert_seconds = 60

# true = for a scan you start yourself in a terminal, only auto-close that
# alert while a Steam game is running, so it stays on screen until you come
# back to it. false = always auto-close. (Steam open but idle does not count
# as gaming.) Runs with no terminal (a service or cron job) always auto-close,
# and each new infected alert replaces the previous one instead of stacking.
infected_alert_only_while_gaming = true

# Error logs: one file per run in <data_dir>/logs/, created only when a run
# has errors. Runs older than log_keep_days are deleted; if the folder is
# still over log_max_total_mb, the oldest go first (so the size limit wins).
# 0 turns either rule off. Within a run, an error that repeats is logged in
# full 20 times, then only counted, with a total at the end of the run.
log_keep_days = 90
log_max_total_mb = 2048

# Warn if the virus-signature database is older than this many days
# (usually means freshclam has silently stopped running). 0 disables.
signature_max_age_days = 3

# Which package manager Ensign asks "which package owns this file, and is
# it unmodified?" -- used by --verify-packages and the context line under
# infected files. "auto" picks it from /etc/os-release; "off" never asks
# one. Supported: "pacman" (Arch and derivatives), "dpkg" (Debian,
# Ubuntu and derivatives), "rpm" (Fedora, RHEL and rebuilds, openSUSE).
# On any other distribution "auto" means off; everything else still works.
package_verification = "auto"
clamd_socket = "/var/run/clamav/clamd.ctl"

scan_targets = [
    "~/Downloads",
    "~/Documents",
    "~/Pictures",
    "~",
]

# Directory trees whose contents never change in place (e.g. proton
# prefix snapshots). Unchanged subtrees under these are skipped by mtime.
snapshot_roots = []

# Trees to skip entirely. High-churn temp/cache directories mostly
# produce "file vanished mid-scan" errors and no security value.
# If you use snapper (or another btrfs snapshot tool) on a subvolume
# under your home directory, its .snapshots dir holds full copies of
# your whole home tree per snapshot -- left un-excluded, Ensign will
# walk every file once per snapshot, and the count balloons with each
# new snapshot snapper takes.
excludes = [
    "~/.cache",
    "~/.local/share/Trash",
    "~/.snapshots",
]

# --- Per-machine overrides (section name = `hostname` output) ---------
#
# [hosts.gaming-rig]
# max_workers = 8          # explicit override beats auto
# scan_targets = ["~/Downloads", "~/.local/share/Steam", "~"]
# snapshot_roots = [
#     "~/.local/share/Steam/steamapps/compatdata/<app_id>/pfx/dosdevices/z:/snapshots",
# ]
#
# [hosts.old-laptop]
# max_workers = 2

# --- Custom secrets-path patterns (ensign_scan/secrets.py) ------------------
# Additive only: these are ADDED to the built-in HIGH/MEDIUM pattern
# lists, never replace or override a built-in entry. See secrets.py's
# module docstring for what HIGH vs MEDIUM means.
#
# [custom_secrets]
# high_dirs = ["myvault"]                        # whole path component
# high_dir_paths = ["myapp/keys"]                # whole folder names, in order
# high_filenames = ["my_custom_key"]              # exact filename, any dir
# high_extensions = [".mysecret"]
# high_scoped_filenames = [["myapp", "config"]]   # [folder it sits directly in, filename]
# high_prefixes = [["mywallet_", "wallets"]]     # [prefix, folder name somewhere above it]
# medium_prefixes = [["myprefix_", "somedir"]]    # [prefix, required parent substring or ""]
# medium_extensions = [[".maybesecret", ""]]      # [extension, required parent substring or ""]

# --- Custom explanations (ensign_scan/explanations.py) -----------------------
# Additive only, same as above -- a name/reason that's already built in
# is left alone, not overridden.
#
# [custom_threats."Some.New.ThreatName"]
# description = "What this signature generally means."
# false_positive_note = "Optional: when it's commonly a false positive."
#
# [custom_pacman_reasons]
# "Some new mismatch type" = "What this pacman -Qkk reason means."
"""


def ensure_default_config() -> None:
    """Write the commented template on first run so users have something
    to edit instead of reading source code to learn the options."""
    if DEFAULT_CONFIG_PATH.exists():
        return
    DEFAULT_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    DEFAULT_CONFIG_PATH.write_text(EXAMPLE_CONFIG)
    print(f"[ensign] Wrote starter config to {DEFAULT_CONFIG_PATH}")
