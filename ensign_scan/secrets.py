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

How it's used: every file is scanned, credential files included. A
name is something malware chooses, so a file was never safe to skip
for its name alone: until 0.8.5, a payload called invoice.kdbx or
wallet.dat anywhere on disk was never opened. What a
HIGH match changes now is what Ensign STORES: hash_not_stored() says to
keep no hash for the file, since a hash of a short secret (a .netrc
password, say) can be confirmed by guessing. Its path, verdict and
threat name are kept like any file's. A found infection does get its
hash stored: it is malware then, not a secret, and --allow needs it.
MEDIUM (a bare .pem, a custom-named id_* key) changes nothing yet; it
is kept for the planned folder-level aggregation.

skip_reason() is still the never-open decision where Ensign only
fingerprints a file without scanning it (the persistence audit).

INTEGRITY_WATCHED files (authorized_keys, ~/.ssh/config, ~/.ssh/rc) are
an exception: they hold no secrets but are classic persistence points
(an added key or a ProxyCommand runs the attacker's code), so their hash
is stored, and a change is reported.

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
from collections.abc import Callable
from enum import Enum

# ----------------------------------------------------------------------
# HIGH confidence: exact, canonical, tool-defined names.
# ----------------------------------------------------------------------

# Directory names, matched as a whole path component (not substring).
# Some are multi-segment: those must appear as whole components, in
# order (".gnupg/private-keys-v1.d"), never as a fragment of a name.
#
# These eight lists (not tuples) are the single source of truth classify()
# reads from. load_custom() below is the only thing that appends to them
# after startup -- additive only, nothing else mutates these at runtime.
_HIGH_DIRS = [
    ".ssh", ".gnupg", ".aws", ".azure", ".docker", ".kube",
    ".password-store", "exodus.wallet",
]
_HIGH_DIR_PATHS = [  # whole path components, in order (see _has_run)
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
# Each entry: (the folder the file sits directly in, filename).
_HIGH_SCOPED_FILENAMES = [
    (".aws", "credentials"),
    (".aws", "config"),
    (".kube", "config"),
    (".ssh", "config"),
    (".docker", "config.json"),
]

# Filename prefixes that are HIGH confidence, but only inside a parent dir.
# (prefix, a folder name somewhere above the file) -- the parent is always required.
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


def _has_run(parts: list[str], entry: str) -> bool:
    """True if `entry`'s components ("a/b") appear in `parts` consecutively,
    each as a WHOLE component.

    Not a substring test: a credential match now means the file is never
    scanned, so ".bitcoin" must not match ".bitcoin-notes", nor "kwalletd"
    a folder called "kwalletd-src", nor ".ssh" a ".sshfs-cache".
    """
    run = [c for c in entry.lower().split("/") if c]
    n = len(run)
    return n > 0 and any(parts[i:i + n] == run for i in range(len(parts) - n + 1))


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
    if any(_has_run(parts, d) for d in _HIGH_DIR_PATHS):
        return Confidence.HIGH
    if basename in _HIGH_FILENAMES:
        return Confidence.HIGH
    folders = parts[:-1]
    for parent, filename in _HIGH_SCOPED_FILENAMES:
        # The file sits directly in `parent` (".ssh/config", not any "config"
        # somewhere under a path that merely contains ".ssh").
        run = [c for c in parent.lower().split("/") if c]
        if basename == filename and run and folders[-len(run):] == run:
            return Confidence.HIGH
    for prefix, parent in _HIGH_PREFIXES:
        if basename.startswith(prefix) and _has_run(folders, parent):
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
    """HIGH confidence only -- the tier hash_not_stored() and skip_reason() act on."""
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


def hash_not_stored(path: str, real_path: str) -> bool:
    """True if a scanned file's hash must not be stored: its path, or the
    path a symlink to it resolves to, matches a HIGH credential pattern.
    INTEGRITY_WATCHED files keep theirs: it's what a change is checked
    against. (The caller keeps the hash of a file found infected.)"""
    if is_integrity_watched(path) or is_integrity_watched(real_path):
        return False
    return classify(path) == Confidence.HIGH or classify(real_path) == Confidence.HIGH


# ----------------------------------------------------------------------
# Does a credential-named file start the way that format always does?
# ----------------------------------------------------------------------
# A name is the file creator's choice, so a payload can borrow one (MITRE
# ATT&CK T1036.008, Masquerade File Type). For the formats below, the first
# bytes are fixed by the format and give nothing secret away, so a file
# named like one that doesn't start that way isn't one. Left out on
# purpose: plaintext formats with no fixed start (.netrc, .git-credentials,
# .npmrc, cloud config files), whose first bytes can be the secret itself;
# formats whose layout couldn't be confirmed from a primary source
# (wallet.dat, Electrum, KDE Wallet); and the bare name "identity", an
# everyday word. A matching start doesn't prove a file is harmless (a
# header can be copied): it only means the name isn't contradicted.
_SSH_KEY_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk"}
_SQLITE_NAMES = {"login data", "key4.db", "credentials.db", "access_tokens.db"}
_SQLITE_MAGIC = b"SQLite format 3\0"                 # sqlite.org/fileformat.html
_KDBX_MAGIC = bytes.fromhex("03d9a29a67fb4bb5")      # KeePass 2.x / KeePassXC (KDBX 2-4)
_KDB_MAGIC = bytes.fromhex("03d9a29a65fb4bb5")       # KeePass 1.x
HEADER_BYTES = 32  # enough for every check below


def _expected_format(name: str) -> tuple[str, Callable[[bytes], bool]] | None:
    """(what the name claims, check on the first bytes) for a name whose
    format has a fixed start, else None."""
    n = name.lower()
    if n.endswith(".kdbx"):
        return "a KeePass database", lambda h: h.startswith(_KDBX_MAGIC)
    if n.endswith(".kdb"):
        return "a KeePass 1 database", lambda h: h.startswith(_KDB_MAGIC)
    if n.endswith(".ppk"):
        return "a PuTTY key", lambda h: h.startswith(b"PuTTY-User-Key-File-")
    if n in _SSH_KEY_NAMES:
        # OpenSSH, and the older PEM and PKCS#8 forms, all open this way.
        return "an SSH private key", lambda h: h.startswith(b"-----BEGIN ")
    if n.endswith(".keytab"):
        # A version byte 5 then 2 (or the obsolete 1), big-endian (MIT krb5 docs).
        return "a Kerberos keytab", lambda h: h[:1] == b"\x05" and h[1:2] in (b"\x01", b"\x02")
    if n in _SQLITE_NAMES:
        return "an SQLite credential store", lambda h: h.startswith(_SQLITE_MAGIC)
    return None


def has_expected_format(path: str, real_path: str) -> bool:
    """True if format_mismatch() has anything to check for this file."""
    return any(_expected_format(os.path.basename(p)) for p in {path, real_path})


def format_mismatch(path: str, real_path: str, head: bytes) -> str | None:
    """Why the file isn't what its name says, or None. `head` is its first
    HEADER_BYTES bytes; an empty file isn't checked (it holds nothing)."""
    if not head:
        return None
    for p in dict.fromkeys((path, real_path)):   # each name once, the one seen first
        expected = _expected_format(os.path.basename(p))
        if expected and not expected[1](head):
            return f"named like {expected[0]} ({os.path.basename(p)}), but doesn't start like one"
    return None


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
