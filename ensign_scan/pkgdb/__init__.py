"""Package-manager backends: which package owns a file, and do installed
files still match what their packages put there. Read-only and local.

Which backend runs is chosen from /etc/os-release (the distribution's ID
and ID_LIKE), not from which commands happen to be installed: Arch's
repositories carry rpm-tools and the AUR has dpkg, so "use whatever
binary exists" could ask the wrong package manager and trust its answer.
The `package_verification` config setting can force a backend or turn
verification off.
"""
from __future__ import annotations

import os
import shlex
from pathlib import Path

from .base import Backend
from .dpkg import DpkgBackend
from .none import NoneBackend
from .pacman import PacmanBackend
from .rpm import RpmBackend

BACKENDS: dict[str, type[Backend]] = {
    "pacman": PacmanBackend,
    "dpkg": DpkgBackend,
    "rpm": RpmBackend,
}

# Values accepted by the `package_verification` config setting.
CHOICES = ("auto", "off", *BACKENDS)

# os-release ID / ID_LIKE value -> backend name. Derivatives name their
# parent in ID_LIKE (Manjaro: "arch", Mint: "ubuntu debian", Rocky:
# "rhel centos fedora", openSUSE: "suse opensuse"), so one entry covers a
# whole family.
_FAMILIES = {
    "arch": "pacman",
    "debian": "dpkg",
    "ubuntu": "dpkg",
    "fedora": "rpm",
    "rhel": "rpm",
    "centos": "rpm",
    "suse": "rpm",
    "opensuse": "rpm",
    "mageia": "rpm",
}

_OS_RELEASE_PATHS = (Path("/etc/os-release"), Path("/usr/lib/os-release"))


def read_os_release(paths=_OS_RELEASE_PATHS) -> dict[str, str]:
    """Parse os-release (KEY=value lines, values optionally quoted).
    /etc/os-release first, /usr/lib/os-release as the spec's fallback.
    Returns {} if neither can be read."""
    for path in paths:
        try:
            text = Path(path).read_text()
        except OSError:
            continue
        info: dict[str, str] = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            try:
                parts = shlex.split(value)
            except ValueError:  # unbalanced quote: keep the raw text
                parts = [value]
            info[key.strip()] = " ".join(parts)
        return info
    return {}


def detect(os_release: dict[str, str] | None = None) -> Backend:
    """Pick the backend for this distribution, or NoneBackend with a reason."""
    info = read_os_release() if os_release is None else os_release
    ids = [info.get("ID", "")] + info.get("ID_LIKE", "").split()
    for distro in ids:
        name = _FAMILIES.get(distro.lower())
        if name:
            backend = BACKENDS[name]()
            if backend.available():
                return backend
            return NoneBackend(f"{name} expected for this distribution, but it isn't available")
    if not info:
        return NoneBackend("couldn't identify the distribution (no readable os-release)")
    return NoneBackend("no supported package manager for this distribution yet")


def select(setting: str = "auto", os_release: dict[str, str] | None = None) -> Backend:
    """The backend for a `package_verification` value. Config validation
    has already rejected unknown values, so anything else is a bug."""
    if setting == "off":
        return NoneBackend('package_verification = "off"')
    if setting == "auto":
        return detect(os_release)
    backend = BACKENDS[setting]()
    if not backend.available():
        return NoneBackend(f'package_verification = "{setting}", but {setting} isn\'t available')
    return backend


_active: Backend | None = None


def configure(setting: str) -> Backend:
    """Choose the backend for this run. Called once at startup, like
    secrets.load_custom(), so reports don't need it passed through."""
    global _active
    _active = select(setting)
    return _active


def active() -> Backend:
    """The backend for this run (auto-detected if configure() wasn't called)."""
    global _active
    if _active is None:
        _active = select("auto")
    return _active


# ----------------------------------------------------------------------
# Where did these files come from?
# ----------------------------------------------------------------------

# Origin states, from most to least reassuring.
FROM_PACKAGE = "package"      # a package owns it, and it matches what the package installed
MODIFIED = "modified"         # a package owns it, and it differs from what the package installed
OWNED = "owned"               # a package owns it, but it couldn't be compared
UNOWNED = "unowned"           # the package manager says no package owns it
UNKNOWN = "unknown"           # no answer (no package manager, or an error)


def _same_file_key(path: str) -> str:
    """The path with its directories resolved, the file itself not (as the
    dpkg and rpm backends do), so /lib/x from a package record and
    /usr/lib/x found on disk compare equal on a merged-/usr system."""
    head, tail = os.path.split(path)
    return os.path.join(os.path.realpath(head or "/"), tail)


def origins(paths: list[str], backend: Backend | None = None) -> dict[str, tuple[str, str | None]]:
    """{path: (state, package name)} for each path; see the states above.

    One batched owner lookup, then one verify of just the owning packages.
    Only FROM_PACKAGE means "checked and unchanged". Anything the package
    manager couldn't confirm -- no answer, an error, a package removed in
    between, an output line the parser didn't understand -- comes out as
    OWNED or UNKNOWN instead, so a doubt never makes a file look verified.
    """
    backend = backend or active()
    result: dict[str, tuple[str, str | None]] = {p: (UNKNOWN, None) for p in paths}
    if not paths or backend.name == "none":
        return result
    owners = backend.owners(paths)
    packages = sorted({name for name in owners.values() if name})
    for path, name in owners.items():
        result[path] = (OWNED, name) if name else (UNOWNED, None)
    if not packages:
        return result
    check = backend.verify_packages(packages)
    if check is None or check.error or check.unparsed:
        return result  # couldn't verify cleanly: owned, not verified
    differs: dict[str, bool] = {}  # key -> True if any difference was really checked
    for m in check.mismatches:
        key = _same_file_key(m.filepath)
        differs[key] = differs.get(key, False) or not m.unverified
    for path, name in owners.items():
        if not name:
            continue
        key = _same_file_key(path)
        if key not in differs:
            result[path] = (FROM_PACKAGE, name)
        elif differs[key]:
            result[path] = (MODIFIED, name)
        # only unverified lines for it: stays OWNED
    return result
