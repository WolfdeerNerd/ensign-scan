"""Path patterns suggesting a secrets/credentials store.

Design: three confidence tiers, not one flat list.

  HIGH   -- exact, canonical, tool-defined names (directories, fixed
            filenames, distinctive extensions). These essentially never
            collide with unrelated content by accident. Policy: anything
            financial or crypto (wallets, keystores) belongs here, not
            in MEDIUM, where the pattern is specific enough to allow it.
  MEDIUM -- naming conventions/prefixes that need directory context to
            be trustworthy (e.g. id_* only means something inside
            .ssh/; a bare .pem could be a certificate or a private key).
  (anything else is NOT flagged -- bare English words like "wallet",
  "secrets", "keystore" are deliberately excluded; they were the
  source of most false positives under the old substring-matching
  approach and add negligible real coverage.)

How it's used: skip_reason() decides, BEFORE a file is opened, whether
Ensign should leave its contents alone entirely -- no hash, no scan.
That uses HIGH only. Skipping is a coverage loss, so it is reserved for
names that are essentially never anything but credential material;
a MEDIUM match (a bare .pem, a custom-named id_* key) is still opened
and scanned. (MEDIUM currently has no other consumer; it is kept for
the planned folder-level aggregation.)

Why skip at all: a key, keyring, wallet or vault is what malware
*steals*, not where it hides, so scanning its contents finds almost
nothing -- and reading it, and storing its hash, is exposure for no
gain (a hash of a short secret, like a .netrc password, can be
brute-forced offline). Theft of these files is caught by watching who
opens them, not by reading them.

Two deliberate exceptions, so the skip can't become a hiding place:
  - Executables. Credential files are never executable; an executable
    in a secrets location is exactly what an attacker would plant
    there, so it is scanned like anything else.
  - INTEGRITY_WATCHED files (authorized_keys, ~/.ssh/config, ~/.ssh/rc).
    These hold no secrets but are classic persistence points: an added
    key or a ProxyCommand runs the attacker's code. They are hashed,
    scanned, and reported when they change.

Deliberately conservative: this is a deny-list, not a guarantee. It
will miss a secrets store whose name doesn't match anything here (a
custom password manager with an obscure directory name, for instance),
and that file will simply be scanned. That's an accepted, known gap --
see:

docs/Classified_Paths_Research.md

for how each entry was sourced.
"""
from __future__ import annotations

import os
from enum import Enum

# ----------------------------------------------------------------------
# HIGH confidence: exact, canonical, tool-defined names.
# ----------------------------------------------------------------------

# Directory names, matched as a whole path component (not substring).
# Some are multi-segment (checked as a path substring since they're
# specific enough not to need per-component matching).
#
# These eight lists (not tuples) are the single source of truth classify()
# reads from. load_custom() below is the only thing that appends to them
# after startup -- additive only, nothing else mutates these at runtime.
_HIGH_DIRS = [
    ".ssh", ".gnupg", ".aws", ".azure", ".docker", ".kube",
    ".password-store", "exodus.wallet",
]
_HIGH_DIR_PATHS = [  # multi-segment, checked as substrings
    ".gnupg/private-keys-v1.d", ".gnupg/openpgp-revocs.d",
    ".config/gcloud", ".electrum/wallets", ".ethereum/keystore",
    ".bitcoin", ".litecoin", ".dogecoin",
    "kwalletd", ".kde/share/apps/kwallet",  # KDE Wallet
]

# Filenames safe to treat as HIGH confidence regardless of parent dir --
# distinctive enough that directory context isn't needed.
_HIGH_FILENAMES = [
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ed25519_sk",
    "id_ecdsa_sk", "identity", "authorized_keys", "known_hosts",
    "pubring.kbx", "pubring.gpg", "secring.gpg", "trustdb.gpg",
    "trustedkeys.gpg", "trustedkeys.kbx",
    "wallet.dat", "default_wallet",
    "application_default_credentials.json", "credentials.db",
    "access_tokens.db", "adc.json", "accesstokens.json",
    "azureprofile.json", "msal_token_cache.bin",
    "seed.seco", "info.seco", "storage.seco",
    ".netrc", "_netrc", ".git-credentials", ".npmrc", ".pypirc",
    ".vault-token", ".pgpass", ".my.cnf", ".s3cfg", ".boto", ".gpg-id",
    "login data", "logins.json", "key4.db", "key3.db", "krb5.keytab",
]

# Filenames that are only HIGH confidence inside a specific parent dir
# (e.g. "config" is sensitive under .kube/, meaningless anywhere else).
# Each entry: (parent dir substring, filename).
_HIGH_SCOPED_FILENAMES = [
    (".aws", "credentials"),
    (".aws", "config"),
    (".kube", "config"),
    (".ssh", "config"),
    (".docker", "config.json"),
]

# Filename prefixes that are HIGH confidence, but only inside a parent dir.
# (prefix, required parent-dir substring) -- the parent is always required.
_HIGH_PREFIXES = [
    ("utc--", "keystore"),      # Ethereum keystore V3 (financial/crypto: HIGH)
]

# Distinctive extensions -- unique enough to a single ecosystem that
# they're safe as HIGH confidence without directory scoping.
_HIGH_EXTENSIONS = [
    ".kdbx", ".kdb",           # KeePass 2.x / 1.x
    ".opvault", ".1pux", ".1pif", ".agilekeychain",  # 1Password
    ".ppk",                    # PuTTY
    ".keytab",                 # Kerberos
    ".kwl",                    # KDE Wallet
]

# ----------------------------------------------------------------------
# MEDIUM confidence: conventions/prefixes that need directory context.
# ----------------------------------------------------------------------

# (prefix, required parent-dir substring or None if safe standalone)
_MEDIUM_PREFIXES = [
    ("id_", ".ssh"),            # custom-named SSH keys
    ("ssh_host_", "ssh"),       # host keys, usually /etc/ssh/
]

_MEDIUM_EXTENSIONS = [
    (".keys", None),    # Monero -- paired with *.address.txt, but the
                        # extension alone is distinctive enough
    (".gpg", (".gnupg", ".password-store")),
    (".asc", None), (".pgp", None),
    (".pem", None), (".key", None), (".p12", None), (".pfx", None),
    (".jks", None), (".keystore", None),
]


class Confidence(str, Enum):
    NONE = "none"
    MEDIUM = "medium"
    HIGH = "high"


def _parts(path: str) -> list[str]:
    return path.lower().replace("\\", "/").split("/")


def classify(path: str) -> Confidence:
    """Classify how confidently `path` looks like a secrets/credentials
    store. See module docstring for what each tier means and how the
    two call sites use different thresholds."""
    lower = path.lower().replace("\\", "/")
    parts = _parts(path)
    basename = parts[-1] if parts else ""

    # -- HIGH --
    if any(part == d for part in parts for d in _HIGH_DIRS):
        return Confidence.HIGH
    if any(d in lower for d in _HIGH_DIR_PATHS):
        return Confidence.HIGH
    if basename in _HIGH_FILENAMES:
        return Confidence.HIGH
    for parent, filename in _HIGH_SCOPED_FILENAMES:
        if basename == filename and parent in lower:
            return Confidence.HIGH
    for prefix, parent in _HIGH_PREFIXES:
        if basename.startswith(prefix) and parent in lower:
            return Confidence.HIGH
    if any(basename.endswith(ext) for ext in _HIGH_EXTENSIONS):
        return Confidence.HIGH

    # -- MEDIUM --
    for prefix, needs_parent in _MEDIUM_PREFIXES:
        if basename.startswith(prefix) and (needs_parent is None or needs_parent in lower):
            return Confidence.MEDIUM
    for ext, needs_parent in _MEDIUM_EXTENSIONS:
        if basename.endswith(ext):
            if needs_parent is None or (
                isinstance(needs_parent, tuple) and any(p in lower for p in needs_parent)
            ):
                return Confidence.MEDIUM

    return Confidence.NONE


def is_likely_secrets_path(path: str) -> bool:
    """HIGH or MEDIUM confidence."""
    return classify(path) != Confidence.NONE


def is_high_confidence_secrets_path(path: str) -> bool:
    """HIGH confidence only -- the tier skip_reason() acts on."""
    return classify(path) == Confidence.HIGH


# ----------------------------------------------------------------------
# Skip-before-open, and the persistence files that are never skipped.
# ----------------------------------------------------------------------

# Files directly inside a .ssh directory that hold no secrets but decide
# what runs: authorized_keys/authorized_keys2 (who may log in), config
# (ProxyCommand / LocalCommand run programs), rc (runs on every login).
INTEGRITY_WATCHED = ("authorized_keys", "authorized_keys2", "config", "rc")

SKIP_REASON = "Not scanned: path matches a credential pattern, contents never read"


def is_integrity_watched(path: str) -> bool:
    """True for an INTEGRITY_WATCHED file whose parent directory is .ssh."""
    parts = _parts(path)
    return len(parts) >= 2 and parts[-2] == ".ssh" and parts[-1] in INTEGRITY_WATCHED


def skip_reason(path: str, real_path: str, st_mode: int) -> str | None:
    """Why Ensign should not open this file at all, or None to scan it.

    Called before the file is opened, so it may only use the path, the
    symlink-resolved path, and stat() metadata -- never contents.
    `real_path` matters because symlinks are followed: a link named
    "notes.txt" pointing at ~/.ssh/id_ed25519 must be skipped too.
    """
    if is_integrity_watched(path) or is_integrity_watched(real_path):
        return None
    if st_mode & 0o111:
        return None  # credential files are never executable; scan it
    if classify(path) == Confidence.HIGH or classify(real_path) == Confidence.HIGH:
        return SKIP_REASON
    return None


def matching_reason(path: str) -> str | None:
    """Human-readable reason for a match, or None."""
    conf = classify(path)
    if conf == Confidence.NONE:
        return None
    basename = os.path.basename(path)
    return f"{conf.value}-confidence match on {basename!r}"


# ----------------------------------------------------------------------
# User-supplied extensions, from [custom_secrets] in config.toml.
# ----------------------------------------------------------------------

_CUSTOM_SECRETS_KNOWN_KEYS = {
    "high_dirs", "high_dir_paths", "high_filenames", "high_extensions",
    "high_scoped_filenames", "high_prefixes", "medium_prefixes", "medium_extensions",
}


def _as_pair(entry, allow_empty_second: bool, key: str, index: int) -> tuple[str, str | None] | None:
    """Validate a [value, parent] pair from TOML. `parent` of "" is
    treated as None (no required parent) when allow_empty_second is True
    -- scoped filenames always need a real parent, prefixes/extensions
    don't have to. Returns None (and warns) on anything malformed.

    The warning names WHERE the bad entry is (`key`, 1-based `index`),
    never what it contains. These entries describe where the user keeps
    secrets (e.g. ["mywallet_", "wallets"]); printing them would put that
    map into the terminal, and into the systemd journal when Ensign runs
    as a service, where other users in groups like wheel or adm can read it.
    """
    where = f"custom_secrets.{key} entry #{index}"
    if not (isinstance(entry, (list, tuple)) and len(entry) == 2):
        print(f"[ensign] Warning: {where} is malformed (expected a two-element list) -- ignored")
        return None
    value, parent = entry
    if not isinstance(value, str) or not value:
        print(f"[ensign] Warning: {where} is malformed (first element must be a non-empty string) -- ignored")
        return None
    if parent == "" and allow_empty_second:
        parent = None
    elif not isinstance(parent, str):
        print(f"[ensign] Warning: {where} is malformed (second element must be a string) -- ignored")
        return None
    return (value, parent)


def load_custom(config) -> None:
    """Merge config.custom_secrets into the module's pattern lists.

    Additive only: a value already present (by equality) is left alone,
    not duplicated. Malformed entries are warned about and skipped
    individually. Each custom entry picks ONE existing tier/shape to
    join -- there's no way from config to add a brand-new tier, a
    multi-value required-parent (medium_extensions' (".gpg", (".gnupg",
    ".password-store")) shape), or a tool-defined fixed extension
    outside high_extensions/medium_extensions.
    """
    raw = getattr(config, "custom_secrets", None) or {}
    for key in raw.keys() - _CUSTOM_SECRETS_KNOWN_KEYS:
        print(f"[ensign] Warning: unknown custom_secrets key {key!r} ignored")

    for value in raw.get("high_dirs", []):
        if isinstance(value, str) and value and value.lower() not in _HIGH_DIRS:
            _HIGH_DIRS.append(value.lower())
    for value in raw.get("high_dir_paths", []):
        if isinstance(value, str) and value and value.lower() not in _HIGH_DIR_PATHS:
            _HIGH_DIR_PATHS.append(value.lower())
    for value in raw.get("high_filenames", []):
        if isinstance(value, str) and value and value not in _HIGH_FILENAMES:
            _HIGH_FILENAMES.append(value.lower())
    for value in raw.get("high_extensions", []):
        if isinstance(value, str) and value and value not in _HIGH_EXTENSIONS:
            _HIGH_EXTENSIONS.append(value.lower())

    for index, entry in enumerate(raw.get("high_scoped_filenames", []), start=1):
        pair = _as_pair(entry, allow_empty_second=False, key="high_scoped_filenames", index=index)
        if pair:
            pair = (pair[0].lower(), pair[1].lower())
            if pair not in _HIGH_SCOPED_FILENAMES:
                _HIGH_SCOPED_FILENAMES.append(pair)
    for index, entry in enumerate(raw.get("high_prefixes", []), start=1):
        pair = _as_pair(entry, allow_empty_second=False, key="high_prefixes", index=index)
        if pair:
            pair = (pair[0].lower(), pair[1].lower())
            if pair not in _HIGH_PREFIXES:
                _HIGH_PREFIXES.append(pair)
    for index, entry in enumerate(raw.get("medium_prefixes", []), start=1):
        pair = _as_pair(entry, allow_empty_second=True, key="medium_prefixes", index=index)
        if pair:
            pair = (pair[0].lower(), pair[1].lower() if pair[1] else None)
            if pair not in _MEDIUM_PREFIXES:
                _MEDIUM_PREFIXES.append(pair)
    for index, entry in enumerate(raw.get("medium_extensions", []), start=1):
        pair = _as_pair(entry, allow_empty_second=True, key="medium_extensions", index=index)
        if pair:
            pair = (pair[0].lower(), pair[1].lower() if pair[1] else None)
            if pair not in _MEDIUM_EXTENSIONS:
                _MEDIUM_EXTENSIONS.append(pair)
