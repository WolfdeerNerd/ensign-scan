"""Tests for package-manager backend selection (ensign_scan/pkgdb).
Run: python3 pkgdb_test.py

No real package manager is needed: availability is faked, and os-release
contents are passed in directly.

Optional live check against the real system:
    ENSIGN_EXPECT_BACKEND=pacman python3 pkgdb_test.py
detects from the machine's own /etc/os-release and asserts the result
("none" is a valid expectation too). CI sets it in each distro container.
"""
import os
import sys
import tempfile
import tomllib
from pathlib import Path

from ensign_scan import pkgdb, reports
from ensign_scan.config import Config
from ensign_scan.pkgdb.none import NoneBackend
from ensign_scan.pkgdb.pacman import PacmanBackend

# --- os-release parsing ----------------------------------------------------
with tempfile.TemporaryDirectory() as d:
    first, second = Path(d, "etc-os-release"), Path(d, "usr-os-release")
    second.write_text('ID=fallback\n')
    first.write_text(
        '# comment\n'
        'NAME="Arch Linux"\n'
        "ID_LIKE='debian ubuntu'\n"
        'ID=arch\n'
        '\n'
        'BROKEN="unbalanced\n'
    )
    info = pkgdb.read_os_release((first, second))
    assert info["NAME"] == "Arch Linux", "double quotes stripped"
    assert info["ID_LIKE"] == "debian ubuntu", "single quotes stripped, words kept"
    assert info["ID"] == "arch"
    assert "BROKEN" in info, "a bad quote doesn't drop the line or crash"

    # /etc/os-release missing -> /usr/lib/os-release is used, per the spec
    assert pkgdb.read_os_release((Path(d, "missing"), second)) == {"ID": "fallback"}
    # neither readable -> empty, not an exception
    assert pkgdb.read_os_release((Path(d, "missing"),)) == {}
print("os-release parsing tests passed ✓")

# --- detection ----------------------------------------------------------------
# Fake whether the pacman command exists, without touching the real system.
real_available = PacmanBackend.available


def pacman_present(flag: bool) -> None:
    PacmanBackend.available = lambda self: flag


pacman_present(True)
assert pkgdb.detect({"ID": "arch"}).name == "pacman"
assert pkgdb.detect({"ID": "endeavouros", "ID_LIKE": "arch"}).name == "pacman", \
    "derivatives are matched through ID_LIKE"
assert pkgdb.detect({"ID": "Arch"}).name == "pacman", "IDs compare case-insensitively"

# The point of using os-release: pacman installed on a Debian box (or
# rpm-tools on Arch) must NOT make Ensign trust that package manager.
debian = pkgdb.detect({"ID": "debian"})
assert debian.name == "none" and "no supported package manager" in debian.reason

unknown = pkgdb.detect({})
assert unknown.name == "none" and "os-release" in unknown.reason

pacman_present(False)
missing = pkgdb.detect({"ID": "arch"})
assert missing.name == "none" and "isn't available" in missing.reason, \
    "right distro but pacman missing is explained, not silently ignored"
print("detection tests passed ✓")

# --- select() -----------------------------------------------------------------
pacman_present(True)
off = pkgdb.select("off", {"ID": "arch"})
assert off.name == "none" and '"off"' in off.reason, "off wins even on Arch"
assert pkgdb.select("auto", {"ID": "arch"}).name == "pacman"
assert pkgdb.select("pacman", {"ID": "debian"}).name == "pacman", "a forced backend skips detection"
pacman_present(False)
forced = pkgdb.select("pacman", {"ID": "arch"})
assert forced.name == "none" and "isn't available" in forced.reason
print("select tests passed ✓")

# --- the none backend never claims "unowned" ----------------------------------
none = NoneBackend()
assert none.owner("/usr/bin/ls") == ("unknown", None), \
    "no package manager must never look like 'no package owns this'"
assert none.verify_all() is None and none.verify_command("x") is None
print("none backend tests passed ✓")

# --- configure() / active() -----------------------------------------------------
assert pkgdb.configure("off").name == "none"
assert pkgdb.active() is pkgdb._active, "configure() sets the backend reports use"
print("configure/active tests passed ✓")

# --- reports: the context line under infected files ---------------------------------


class FakeBackend(PacmanBackend):
    def __init__(self, answer):
        self.answer = answer

    def owner(self, path):
        return self.answer


with tempfile.NamedTemporaryFile() as f:
    pkgdb._active = FakeBackend(("owned", "coreutils 9.5-1"))
    line = reports._file_facts(f.name)
    assert "owned by package coreutils 9.5-1 (check it with: pacman -Qkk coreutils)" in line

    pkgdb._active = FakeBackend(("unowned", None))
    assert "not owned by any pacman package" in reports._file_facts(f.name), \
        "on Arch the wording is unchanged from before pkgdb"

    pkgdb._active = NoneBackend()
    line = reports._file_facts(f.name)
    assert "owned" not in line, "with no backend, ownership is simply not mentioned"
print("report context-line tests passed ✓")

PacmanBackend.available = real_available
pkgdb._active = None

# --- config: package_verification -----------------------------------------------
assert Config().package_verification == "auto"
for value, ok in (("auto", True), ("off", True), ("pacman", True), ("Pacman", False), ("yes", False), (True, False)):
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
        f.write(f"package_verification = {value!r}\n".replace("True", "true"))
    try:
        cfg = Config.load(f.name)
        assert ok, f"{value!r} should have been rejected"
        assert cfg.package_verification == value
    except ValueError as exc:
        assert not ok, f"{value!r} should have been accepted"
        assert "package_verification must be one of" in str(exc)
    finally:
        Path(f.name).unlink()
print("config validation tests passed ✓")

# --- CLI: --verify-pacman still works -------------------------------------------
from ensign_scan import cli  # noqa: E402

for flag in ("--verify-packages", "--verify-pacman"):
    sys.argv = ["ensign-scan", flag]
    assert cli.parse_args().verify_packages is True, f"{flag} sets verify_packages"
print("CLI alias tests passed ✓")

# --- packaging: every subpackage ships ------------------------------------------
# setuptools only installs the packages listed in pyproject.toml. A new
# subpackage that isn't listed works from a checkout but is missing from
# the PyPI install -- an ImportError only users would see.
root = Path(__file__).parent
listed = set(tomllib.loads((root / "pyproject.toml").read_text())["tool"]["setuptools"]["packages"])
found = {
    ".".join(p.parent.relative_to(root).parts)
    for p in (root / "ensign_scan").rglob("__init__.py")
}
assert found <= listed, f"packages missing from pyproject.toml: {sorted(found - listed)}"
print("packaging test passed ✓")

# --- live: detection on the real system ------------------------------------------
expected = os.environ.get("ENSIGN_EXPECT_BACKEND")
if expected:
    backend = pkgdb.detect()
    assert backend.name == expected, \
        f"expected backend {expected!r} here, detected {backend.name!r} ({getattr(backend, 'reason', '')})"
    if expected == "pacman":
        state, pkg = backend.owner("/usr/bin/pacman")
        assert state == "owned" and pkg.split()[0] == "pacman", (state, pkg)
        assert backend.verify_command("pacman") == "pacman -Qkk pacman"
    else:
        assert backend.owner("/usr/bin/ls") == ("unknown", None)
    print(f"live detection test passed ✓ ({backend.name})")
else:
    print("live detection test skipped (set ENSIGN_EXPECT_BACKEND to run it)")

print("All pkgdb tests passed ✓")
