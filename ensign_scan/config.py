"""Configuration for Ensign.

Design for multi-machine use:

  * The code contains NO machine-specific values. Everything lives in a
    TOML file, so any user on any box gets sane defaults out of the box.
  * Config search order: --config flag > $ENSIGN_CONFIG >
    ~/.config/ensign-scan/config.toml > built-in defaults. (Before 0.8.1
    the folders were named "ensign"; see legacy_notice().) As root, the
    default is /etc/ensign-scan/config.toml, and the data folder is
    /var/lib/ensign-scan: see ROOT_CONFIG_PATH and trust.py.
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
import stat
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from . import trust
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

# Your own config and data, in your home.
USER_DATA_DIR = HOME / ".local" / "share" / "ensign-scan"
USER_CONFIG_PATH = HOME / ".config" / "ensign-scan" / "config.toml"

# Root's (runs with sudo): its own config and data, which only root can
# change. Root never reads your config or writes into your folders -- see
# trust.py for why. On the first run as root, your config is copied here
# once (ensure_default_config); after that the two are independent.
ROOT_DATA_DIR = Path("/var/lib/ensign-scan")
ROOT_CONFIG_PATH = Path("/etc/ensign-scan/config.toml")

AS_ROOT = os.geteuid() == 0
DEFAULT_DATA_DIR = ROOT_DATA_DIR if AS_ROOT else USER_DATA_DIR
DEFAULT_CONFIG_PATH = ROOT_CONFIG_PATH if AS_ROOT else USER_CONFIG_PATH

# Before 0.8.1 the folders were named just "ensign": generic enough that some
# other program could pick the same name and share a folder with Ensign's
# database. They're renamed after the package and the command (ensign-scan).
# An install that already has the old folders keeps using them -- nothing is
# moved unless every safety check in migrate.py passes -- and while they're
# still in use, every run says why and how to move them (legacy_notice).
LEGACY_DATA_DIR = HOME / ".local" / "share" / "ensign"
LEGACY_CONFIG_PATH = HOME / ".config" / "ensign" / "config.toml"


def default_config_path() -> Path:
    """The config file to use when none is named: the new place, unless only
    the old one has a file. Root has no old place."""
    if AS_ROOT:
        return DEFAULT_CONFIG_PATH
    if not DEFAULT_CONFIG_PATH.exists() and LEGACY_CONFIG_PATH.is_file():
        return LEGACY_CONFIG_PATH
    return DEFAULT_CONFIG_PATH


def default_data_dir() -> Path:
    """The data folder to use when data_dir isn't set: the new place, unless
    only the old one exists. Root has no old place."""
    if AS_ROOT:
        return DEFAULT_DATA_DIR
    if not DEFAULT_DATA_DIR.exists() and LEGACY_DATA_DIR.is_dir():
        return LEGACY_DATA_DIR
    return DEFAULT_DATA_DIR

_DEFAULT_TARGETS = ("~/Downloads", "~/Documents", "~/Pictures", "~")


def _expand(value: str | Path) -> Path:
    """Expand ~ and environment variables relative to the invoking user."""
    text = os.path.expandvars(str(value))
    if text == "~":
        return HOME
    if text.startswith("~/"):
        return HOME / text[2:]
    return Path(text)


# Every setting a config file may hold (besides [hosts.<hostname>] sections).
KNOWN_SETTINGS = frozenset({
    "data_dir", "clamd_socket", "max_workers", "cpu_share", "max_clamscans",
    "clamscan_memory_percent", "sweep_huge_files",
    "resweep_after_signature_updates", "resweep_after_days",
    "rescan_after_days", "rescan_after_signature_updates",
    "infected_alert_seconds", "infected_alert_only_while_gaming",
    "never_open_credentials",
    "log_keep_days", "log_max_total_mb",
    "scan_targets", "snapshot_roots",
    "excludes", "signature_max_age_days", "package_verification",
    "custom_secrets", "custom_threats", "custom_pacman_reasons",
})


# ----------------------------------------------------------------------
# The config object
# ----------------------------------------------------------------------

# Settings that are true/false, and settings that are whole numbers. A value
# of the wrong type fails loudly: "no" in quotes is a non-empty string, which
# Python treats as true, so sweep_huge_files = "no" would quietly mean yes,
# and a quoted number crashed the run hours in, when it was first compared.
_BOOL_SETTINGS = ("sweep_huge_files", "infected_alert_only_while_gaming", "never_open_credentials")
_INT_SETTINGS = ("max_workers", "cpu_share", "max_clamscans", "clamscan_memory_percent",
                 "resweep_after_signature_updates", "resweep_after_days", "rescan_after_days",
                 "rescan_after_signature_updates", "infected_alert_seconds", "log_keep_days",
                 "log_max_total_mb", "signature_max_age_days")


def _require_root_only(what: str, place: Path) -> None:
    """As root, refuse a config file or data folder another user could change."""
    if not AS_ROOT:
        return
    why = trust.untrusted_reason(place)
    if why:
        raise ValueError(
            f"running as root, but the {what} {place} isn't safe to use: {why}. As root, "
            f"Ensign only uses a config and data folder no other user can change "
            f"(by default {ROOT_CONFIG_PATH} and {ROOT_DATA_DIR}).")


def _check_paths(raw: dict, source: str) -> None:
    """data_dir and the path lists must name absolute places. A relative
    data_dir put the database wherever Ensign was started from (a different
    one for a timer than for your shell), and a relative exclude or target
    never matched anything, with no warning."""
    if "data_dir" in raw:
        value = raw["data_dir"]
        if not isinstance(value, str):
            raise ValueError(f"{source}: data_dir must be a path in quotes, got {value!r}")
        if not _expand(value).is_absolute():
            raise ValueError(f'{source}: data_dir must start with / or ~/, got {value!r}')
    for key in ("scan_targets", "snapshot_roots", "excludes"):
        value = raw.get(key)
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            continue  # the type check after this one names that problem
        relative = [v for v in value if not _expand(v).is_absolute()]
        if relative:
            raise ValueError(f"{source}: every entry in {key} must start with / or ~/, "
                             f"got {relative[0]!r}")


def _check_types(values: dict, source: str) -> None:
    for key in _BOOL_SETTINGS:
        if key in values and not isinstance(values[key], bool):
            raise ValueError(f"{source}: {key} must be true or false (no quotes), "
                             f"got {values[key]!r}")
    for key in _INT_SETTINGS:
        value = values.get(key)
        if key in values and (isinstance(value, bool) or not isinstance(value, int)):
            hint = " (remove the quotes)" if isinstance(value, str) and value.strip().isdigit() else ""
            raise ValueError(f"{source}: {key} must be a whole number{hint}, got {value!r}")
    if "clamd_socket" in values and not isinstance(values["clamd_socket"], str):
        raise ValueError(f"{source}: clamd_socket must be a path in quotes, "
                         f"got {values['clamd_socket']!r}")


# Allowed range for rescan_after_signature_updates in a config file.
# Below 7 is a full pass of a big machine every few days; above 31 leaves
# clean files unchecked for over a month. 0 (off) is always allowed.
SIGNATURE_RESCAN_MIN = 7
SIGNATURE_RESCAN_MAX = 31
# Allowed range for resweep_after_signature_updates and resweep_after_days:
# a re-sweep reads every large file again, so not more often than weekly,
# and not less often than about every three months. 0 (off) is allowed.
RESWEEP_MIN = 7
RESWEEP_MAX = 90
CLAMSCAN_MEMORY_PERCENT_MIN = 5
CPU_SHARE_MIN = 10
CPU_SHARE_MAX = 100
CLAMSCAN_MEMORY_PERCENT_MAX = 75


@dataclass(frozen=True)
class Config:
    db_url: str = f"sqlite:///{DEFAULT_DATA_DIR / 'system.db'}"
    log_file: Path = DEFAULT_DATA_DIR / "error_logs.txt"
    clamd_socket: str = "/var/run/clamav/clamd.ctl"
    # 0 = auto: sized from clamd's MaxThreads and CPU count at startup.
    max_workers: int = 0
    # How much of the CPU a scan may use, in percent of its threads: the
    # workers and the clamscans together stay within it (one clamscan always
    # runs). 100 lets a scan have the whole machine. Clamped to
    # CPU_SHARE_MIN..CPU_SHARE_MAX, with a warning.
    cpu_share: int = 50
    # clamscan runs at once for files too large for clamd. 0 = auto: as many
    # as free memory allows (each loads its own copy of the signatures),
    # up to half the CPU cores. Always at least one.
    max_clamscans: int = 0
    # The most memory all of those clamscans together may use, as a percent
    # of total RAM -- however much happens to be free. One clamscan always
    # runs, even if it alone is over this. Clamped to
    # CLAMSCAN_MEMORY_PERCENT_MIN..CLAMSCAN_MEMORY_PERCENT_MAX, with a warning.
    clamscan_memory_percent: int = 25
    # Sweep files too large for ClamAV (over ~2 GiB) in overlapping slices
    # after the scan, plus the YARA pass for what slices miss: catches raw
    # byte patterns, but not what's inside compressed archives, so it never
    # marks a file clean. On by default; false turns it off (--sweep then
    # runs it for one scan).
    sweep_huge_files: bool = True
    # Sweep an unchanged, already-swept file again once the signatures have
    # moved this many versions on, or this many days have passed since its
    # last sweep, whichever comes first. Longer than for ordinary files: a
    # re-sweep reads every large file in full again. A config file may set
    # RESWEEP_MIN..RESWEEP_MAX (clamped, with a warning), or 0 to turn that
    # trigger off. A changed file is swept again on the next run regardless.
    resweep_after_signature_updates: int = 30
    resweep_after_days: int = 30
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
    # Opt-in: leave an application's own credential files unscanned when
    # their header confirms the format (secrets.never_open_reason). Off:
    # every file is scanned, credential files keeping no hash.
    never_open_credentials: bool = False
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

    # Protected mode (protect.py): root's decisions file, which the run reads
    # allowances and acknowledgments from instead of its own database. Set by
    # the run after loading root's copy of the config, never from a file: a
    # config can't name it (it isn't in KNOWN_SETTINGS).
    decisions_db: Path | None = None

    # -- loading ------------------------------------------------------

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Config":
        """Load config: explicit path > $ENSIGN_CONFIG > default location.

        An explicitly requested file that doesn't exist is an error; the
        default location merely falling back to defaults is not.
        """
        explicit = path or os.environ.get("ENSIGN_CONFIG")
        cfg_path = Path(explicit) if explicit else default_config_path()
        # As root, both the config file (before it's parsed) and the data
        # folder (before anything is written to it) must be root-only.
        # See trust.py for why.
        _require_root_only("config file", cfg_path)
        config = cls._load_file(cfg_path, explicit)
        _require_root_only("data_dir", config.data_dir)
        return config

    @classmethod
    def _load_file(cls, cfg_path: Path, explicit: str | Path | None) -> "Config":
        if not cfg_path.is_file():
            if explicit:
                raise FileNotFoundError(f"Config file not found: {cfg_path}")
            # Not cls(): its data folder is fixed at the new place, and an
            # install with only the old folder must keep finding its database.
            return cls._from_dict({}, source="built-in defaults")

        with open(cfg_path, "rb") as f:
            try:
                data = tomllib.load(f)
            except tomllib.TOMLDecodeError as exc:
                raise ValueError(f"{cfg_path}: not valid TOML: {exc}") from None

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
        for key in raw.keys() - KNOWN_SETTINGS:
            print(f"[ensign] Warning: unknown config key {key!r} ignored")

        _check_paths(raw, source)
        data_dir = _expand(raw["data_dir"]) if "data_dir" in raw else default_data_dir()
        kwargs: dict = {
            "db_url": f"sqlite:///{data_dir / 'system.db'}",
            "log_file": data_dir / "error_logs.txt",
            "source": source,
        }
        for key in ("clamd_socket", "max_workers", "cpu_share", "max_clamscans", "clamscan_memory_percent",
                    "rescan_after_days",
                    "rescan_after_signature_updates", "infected_alert_seconds",
                    "infected_alert_only_while_gaming", "never_open_credentials", "log_keep_days",
                    "log_max_total_mb", "signature_max_age_days", "sweep_huge_files",
                    "resweep_after_signature_updates", "resweep_after_days"):
            if key in raw:
                kwargs[key] = raw[key]
        _check_types(kwargs, source)
        for key in ("scan_targets", "snapshot_roots", "excludes"):
            value = raw.get(key)
            if value is not None and (not isinstance(value, list)
                                      or not all(isinstance(v, str) for v in value)):
                raise ValueError(f'{source}: {key} must be a list of paths in quotes, like '
                                 f'["~/Downloads"], got {value!r}')
        for key in ("custom_secrets", "custom_threats", "custom_pacman_reasons"):
            if key in raw and not isinstance(raw[key], dict):
                raise ValueError(f"{source}: {key} must be a table ([{key}] with entries under "
                                 f"it), got {raw[key]!r}")
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
        for key in ("resweep_after_signature_updates", "resweep_after_days"):
            n = kwargs.get(key)
            if isinstance(n, int) and not isinstance(n, bool) and n != 0:
                clamped = min(max(n, RESWEEP_MIN), RESWEEP_MAX)
                if clamped != n:
                    print(f"[ensign] Warning: {key} = {n} is outside {RESWEEP_MIN}-{RESWEEP_MAX}; "
                          f"using {clamped}")
                    kwargs[key] = clamped
        if "cpu_share" in kwargs:
            n = kwargs["cpu_share"]
            clamped = min(max(n, CPU_SHARE_MIN), CPU_SHARE_MAX)
            if clamped != n:
                print(f"[ensign] Warning: cpu_share = {n} is outside "
                      f"{CPU_SHARE_MIN}-{CPU_SHARE_MAX}; using {clamped}")
                kwargs["cpu_share"] = clamped
        if "clamscan_memory_percent" in kwargs:
            n = kwargs["clamscan_memory_percent"]
            clamped = min(max(n, CLAMSCAN_MEMORY_PERCENT_MIN), CLAMSCAN_MEMORY_PERCENT_MAX)
            if clamped != n:
                print(f"[ensign] Warning: clamscan_memory_percent = {n} is outside "
                      f"{CLAMSCAN_MEMORY_PERCENT_MIN}-{CLAMSCAN_MEMORY_PERCENT_MAX}; using {clamped}")
                kwargs["clamscan_memory_percent"] = clamped
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
# data_dir = "~/.local/share/ensign-scan"

# Worker threads. 0 = auto (sized from clamd's MaxThreads and CPU count).
max_workers = 0

# How much of your CPU a scan may use, in percent of its threads (10-100).
# The workers and any clamscans together stay within it, so you can keep
# using the machine. 100 = let a scan have the whole machine.
cpu_share = 50

# Files larger than clamd scans go to clamscan, which loads its own copy of
# the signatures (about as much memory as clamd uses). How many may run at
# once: 0 = auto -- as many as free memory and cpu_share allow, checked
# again before each one starts, up to 8. Always at least one. Raising MaxFileSize in clamd.conf (up to 2000M) avoids
# clamscan for most files, and is faster still.
max_clamscans = 0
# The most memory those clamscans may use together, as a percent of total
# RAM, however much happens to be free (5-75; one always runs).
clamscan_memory_percent = 25

# ClamAV can't scan files over about 2 GiB at all. true (the default) =
# after each scan, sweep such files in overlapping slices through clamd,
# then run the YARA pass for the signatures slices can miss: it finds
# malware bytes sitting in the raw file, but not inside compressed
# archives, so a swept file is never called clean. Each file is read once
# more when it is new or has changed, which on a big game library takes a
# while the first time. false = off (--sweep then runs it for one scan).
sweep_huge_files = true

# Sweep an unchanged file again once the signatures have moved this many
# versions on (about one a day), or this many days have passed since its
# last sweep, whichever comes first. Allowed range 7-90 (anything else is
# clamped, with a warning); 0 turns that trigger off.
resweep_after_signature_updates = 30
resweep_after_days = 30
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

# Credential files are scanned like everything else, and no hash of them is
# stored. true = leave some unscanned: only an application's own credential
# file in its usual place (SSH keys in ~/.ssh, a browser's saved-password
# database, gcloud's credential databases, /etc/krb5.keytab), owned by you,
# not executable, and starting with that format's header. Only those first
# bytes are read. Anything running as you can write to those places, so a
# file left unscanned there could be malware wearing the right header.
never_open_credentials = false

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
# prefix snapshots). Every folder under these is still checked, but the
# files in a folder nothing was added to, removed from or renamed in
# (same mtime and ctime as last run) aren't looked at again.
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
    if AS_ROOT:
        _ensure_root_config()
        return
    # An old-location config counts: a fresh template at the new place
    # would win over it and quietly drop every setting in it.
    if DEFAULT_CONFIG_PATH.exists() or LEGACY_CONFIG_PATH.exists():
        return
    DEFAULT_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    DEFAULT_CONFIG_PATH.write_text(EXAMPLE_CONFIG)
    print(f"[ensign] Wrote starter config to {DEFAULT_CONFIG_PATH}")


_MAX_COPIED_CONFIG = 1024 * 1024


def _ensure_root_config() -> None:
    """First run as root: copy the sudo user's config to root's place, once.

    After this the two are independent: editing your own config no longer
    changes what sudo runs do, so malware running as you can't either. Only
    a regular file the sudo user owns is copied, opened without following a
    symlink (a link to /etc/shadow would otherwise be copied as root). With
    nothing to copy, root gets the starter template.
    """
    if DEFAULT_CONFIG_PATH.exists() or DEFAULT_CONFIG_PATH.is_symlink():
        return
    _require_root_only("config file", DEFAULT_CONFIG_PATH)
    copied_from, text = _user_config_to_copy()
    DEFAULT_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(DEFAULT_CONFIG_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text if copied_from else EXAMPLE_CONFIG)
    if copied_from:
        print(f"[ensign] First run as root: copied your config {_tilde(copied_from)} to "
              f"{DEFAULT_CONFIG_PATH}.\n"
              f"[ensign] Runs with sudo use that copy from now on; changing your own config "
              f"no longer affects them. Check it, its excludes in particular: it holds "
              f"whatever your config said at this moment.")
    else:
        print(f"[ensign] Wrote starter config for runs as root to {DEFAULT_CONFIG_PATH}")


def _user_config_to_copy() -> tuple[Path | None, str]:
    """(path, text) of the sudo user's config, or (None, "") if there's none
    to copy safely."""
    try:
        uid = int(os.environ["SUDO_UID"])
    except (KeyError, ValueError):
        return None, ""   # root logged in directly: no user to copy from
    for path in (USER_CONFIG_PATH, LEGACY_CONFIG_PATH):
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        except OSError:
            continue   # missing, or a symlink (ELOOP)
        with os.fdopen(fd, "rb") as f:
            st = os.fstat(f.fileno())
            if not stat.S_ISREG(st.st_mode) or st.st_uid != uid or st.st_size > _MAX_COPIED_CONFIG:
                continue
            raw = f.read(_MAX_COPIED_CONFIG + 1)
        try:
            return path, raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
    return None, ""


def _tilde(path: Path) -> str:
    text = str(path)
    home = str(HOME)
    return "~" + text[len(home):] if text == home or text.startswith(home + "/") else text


def legacy_notice(config: "Config", not_moved: list[str] | tuple = ()) -> str | None:
    """How to move off the pre-0.8.1 folders, when this run uses one of them.

    Nothing when the old folders aren't in use, including when they're left
    over next to the new ones (the new ones win then). Printed at the start of
    a run and again at the end, where it isn't buried under the scan.
    """
    def same(a: Path, b: Path) -> bool:
        try:
            return a.exists() and a.resolve() == b.resolve()
        except OSError:
            return False

    old_config = config.source != "built-in defaults" and same(Path(config.source), LEGACY_CONFIG_PATH)
    old_data = same(config.data_dir, LEGACY_DATA_DIR)
    if not (old_config or old_data):
        return None

    lines = ["Ensign's folders are now named ensign-scan (they were ensign before 0.8.1), so",
             "they can't collide with another program's. This run still uses the old ones:"]
    lines_why = [f"  - {why}" for why in not_moved]
    if old_config:
        lines.append(f"  config: {_tilde(LEGACY_CONFIG_PATH.parent)}/")
    if old_data:
        lines.append(f"  data:   {_tilde(LEGACY_DATA_DIR)}/")
    if lines_why:
        lines += ["Ensign moves them itself when it safely can, but didn't this time because:", *lines_why]
    lines += ["To move them by hand, first make sure no Ensign run or scheduled scan is going, then:"]
    moves = ([(LEGACY_CONFIG_PATH.parent, DEFAULT_CONFIG_PATH.parent)] if old_config else []) + \
            ([(LEGACY_DATA_DIR, DEFAULT_DATA_DIR)] if old_data else [])
    for old, new in moves:
        if new.exists():
            # mv into an existing folder would nest the old one inside it.
            lines.append(f"  {_tilde(new)}/ already exists: move what you need from "
                         f"{_tilde(old)}/ into it by hand, then delete {_tilde(old)}/")
        else:
            lines.append(f"  mv {_tilde(old)} {_tilde(new)}")
    if old_data and "data_dir" in _set_in(config):
        lines.append(f'  and change data_dir in your config to "{_tilde(DEFAULT_DATA_DIR)}"')
    lines += ["If a script, timer or $ENSIGN_CONFIG names the old config path, update it too.",
              "Until then Ensign keeps using the old folders."]
    return "\n".join(lines)


def _set_in(config: "Config") -> dict:
    """The settings the config file itself sets (top level and this host's section)."""
    if config.source == "built-in defaults":
        return {}
    try:
        with open(config.source, "rb") as f:
            data = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return {}
    host = data.get("hosts", {})
    host = host.get(HOSTNAME, {}) if isinstance(host, dict) else {}
    return {**data, **(host if isinstance(host, dict) else {})}
