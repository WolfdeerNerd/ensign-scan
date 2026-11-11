"""Tests for package-manager backend selection (ensign_scan/pkgdb).
Run: python3 tests/pkgdb_test.py

No real package manager is needed: availability is faked, and os-release
contents are passed in directly.

Optional live check against the real system:
    ENSIGN_EXPECT_BACKEND=pacman python3 tests/pkgdb_test.py
detects from the machine's own /etc/os-release and asserts the result
("none" is a valid expectation too). CI sets it in each distro container.
"""

import sys as _sys_path
from pathlib import Path as _Path

# Run against THIS checkout, never an installed copy of Ensign: the tests
# live in tests/, so without this "import ensign_scan" would find whatever
# is installed (or nothing) instead of the code next to them.
ROOT = _Path(__file__).resolve().parent.parent
_sys_path.path.insert(0, str(ROOT))
import contextlib
import io
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
# Fake which package-manager commands exist, without touching the real system.
from ensign_scan.pkgdb.dpkg import DpkgBackend  # noqa: E402
from ensign_scan.pkgdb.rpm import RpmBackend  # noqa: E402

real_available = {cls: cls.available for cls in (PacmanBackend, DpkgBackend, RpmBackend)}


def present(*names: str) -> None:
    """Pretend exactly these backends' commands are installed."""
    for cls in real_available:
        cls.available = (lambda flag: (lambda self: flag))(cls.name in names)


present("pacman", "dpkg", "rpm")  # everything installed: os-release alone must decide
for info, want in (
    ({"ID": "arch"}, "pacman"),
    ({"ID": "endeavouros", "ID_LIKE": "arch"}, "pacman"),
    ({"ID": "Arch"}, "pacman"),
    ({"ID": "debian"}, "dpkg"),
    ({"ID": "ubuntu", "ID_LIKE": "debian"}, "dpkg"),
    ({"ID": "linuxmint", "ID_LIKE": "ubuntu debian"}, "dpkg"),
    ({"ID": "fedora"}, "rpm"),
    ({"ID": "rocky", "ID_LIKE": "rhel centos fedora"}, "rpm"),
    ({"ID": "opensuse-tumbleweed", "ID_LIKE": "opensuse suse"}, "rpm"),
):
    got = pkgdb.detect(info).name
    assert got == want, f"{info} detected {got!r}, expected {want!r}"

# The point of using os-release: rpm-tools on Arch, or pacman on a Debian
# box, must NOT make Ensign trust that package manager.
assert pkgdb.detect({"ID": "arch"}).name == "pacman", "rpm/dpkg installed on Arch must not win"

unsupported = pkgdb.detect({"ID": "alpine"})
assert unsupported.name == "none" and "no supported package manager" in unsupported.reason

unknown = pkgdb.detect({})
assert unknown.name == "none" and "os-release" in unknown.reason

present("rpm")  # Debian with only rpm installed: still dpkg's distro, and dpkg is missing
missing = pkgdb.detect({"ID": "debian"})
assert missing.name == "none" and "dpkg" in missing.reason and "isn't available" in missing.reason, \
    "right distro but its package manager missing is explained, not swapped for another"
print("detection tests passed ✓")

# --- select() -----------------------------------------------------------------
present("pacman", "dpkg", "rpm")
off = pkgdb.select("off", {"ID": "arch"})
assert off.name == "none" and '"off"' in off.reason, "off wins even on Arch"
assert pkgdb.select("auto", {"ID": "arch"}).name == "pacman"
assert pkgdb.select("pacman", {"ID": "debian"}).name == "pacman", "a forced backend skips detection"
assert pkgdb.select("rpm", {"ID": "arch"}).name == "rpm"
present()
forced = pkgdb.select("dpkg", {"ID": "debian"})
assert forced.name == "none" and "isn't available" in forced.reason
assert set(pkgdb.CHOICES) == {"auto", "off", "pacman", "dpkg", "rpm"}
for cls, flag in real_available.items():
    cls.available = flag
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

pkgdb._active = None

# --- the dpkg/rpm verify format ----------------------------------------------------
# Every line below is real output, captured from dpkg 1.22 and rpm 4.18.
from ensign_scan.pkgdb import dpkg as dpkg_mod, rpm as rpm_mod, verifyfmt  # noqa: E402

line = verifyfmt.parse_line("??5??????   /usr/bin/tac")
assert line.path == "/usr/bin/tac" and line.reasons == ("Checksum mismatch",) and not line.is_config, line
line = verifyfmt.parse_line("??5?????? c /etc/adduser.conf")
assert line.is_config and line.reasons == ("Checksum mismatch",), "dpkg's '?' for unchecked tests is ignored"
line = verifyfmt.parse_line("?????????   /usr/bin/tac")
assert line.unreadable and line.reasons == ("Could not read file",), "'?' in the checksum column = never checked"
line = verifyfmt.parse_line("missing     /usr/share/doc/coreutils/AUTHORS")
assert line.missing and line.reasons == ("File missing",)
line = verifyfmt.parse_line("missing     /var/lib/polkit-1/localauthority (Permission denied)")
assert line.path == "/var/lib/polkit-1/localauthority" and line.unreadable and not line.missing, \
    "dpkg's '(Permission denied)' means not checked, not gone"
line = verifyfmt.parse_line("S.5....T.  c /etc/ens.conf")
assert line.is_config and line.reasons == ("Size mismatch", "Checksum mismatch", "Modification time mismatch")
line = verifyfmt.parse_line("SM5....T.    /usr/bin/enstool")
assert line.reasons == ("Size mismatch", "Mode mismatch", "Checksum mismatch", "Modification time mismatch")
line = verifyfmt.parse_line("....L....    /usr/bin/enslink")
assert line.reasons == ("Symlink path mismatch",)
line = verifyfmt.parse_line("S.?..UGT.    /etc/ens.secret")
assert line.unreadable and "Could not read file" in line.reasons and "Size mismatch" in line.reasons
line = verifyfmt.parse_line("missing   d /usr/share/doc/enstest/README")
assert line.missing and not line.is_config, "rpm's 'd' (doc) marker isn't a config file"
line = verifyfmt.parse_line("/usr/bin/with space/x  ")  # nonsense: not a verify line
assert line is None
assert verifyfmt.parse_line("..5......   /path with spaces/file").path == "/path with spaces/file"
# A bracketed ending is only an error message if it IS one: "(copy)" is part of a name
line = verifyfmt.parse_line("missing     /usr/share/doc/foo/notes (copy)")
assert line.path == "/usr/share/doc/foo/notes (copy)" and line.missing, line
line = verifyfmt.parse_line("missing     /x (b)/y (No such file or directory)")
assert line.path == "/x (b)/y" and line.missing, "a real error suffix is still stripped, brackets in the path kept"
assert not verifyfmt.is_candidate("dpkg: warning: something about /var/lib/dpkg")
assert not verifyfmt.is_candidate("error: file /x: No such file or directory")
assert verifyfmt.is_candidate("??5??????   /usr/bin/tac")
print("verify-format parser tests passed ✓")

# --- dpkg: path-exclude settings ---------------------------------------------------
with tempfile.TemporaryDirectory() as d:
    cfg_dir = Path(d, "dpkg.cfg.d"); cfg_dir.mkdir()
    # Ubuntu's real "excludes" file, abridged; plus the "option value" spelling
    (cfg_dir / "excludes").write_text(
        "# Drop all man pages\n"
        "path-exclude=/usr/share/man/*\n"
        "path-exclude=/usr/share/doc/*\n"
        "path-include=/usr/share/doc/*/copyright\n"
    )
    (cfg_dir / "zz-local").write_text("path-exclude /usr/share/locale/*/LC_MESSAGES/*.mo\n")
    filters = dpkg_mod.read_path_filters(Path(d, "dpkg.cfg"), cfg_dir)  # dpkg.cfg itself is absent
    assert [o for o, _ in filters] == ["path-exclude", "path-exclude", "path-include", "path-exclude"]
    ex = lambda p: dpkg_mod.is_excluded(p, filters)  # noqa: E731
    assert ex("/usr/share/man/man1/ls.1.gz"), "'*' crosses '/' in dpkg patterns"
    assert ex("/usr/share/doc/coreutils/README")
    assert not ex("/usr/share/doc/coreutils/copyright"), "a later path-include wins"
    assert ex("/usr/share/locale/de/LC_MESSAGES/coreutils.mo")
    assert not ex("/usr/bin/ls")
    assert dpkg_mod.read_path_filters(Path(d, "none"), Path(d, "nodir")) == [], "no config: nothing excluded"
    if os.geteuid() != 0:  # root can list anything, so this can only be checked as a normal user
        locked = Path(d, "locked.d"); locked.mkdir(); (locked / "x").write_text("path-exclude=/x\n")
        locked.chmod(0o000)
        try:
            assert dpkg_mod.read_path_filters(Path(d, "none"), locked) == [], "unreadable: no crash"
        finally:
            locked.chmod(0o700)
print("dpkg path-exclude tests passed ✓")

# --- dpkg: ownership lookups ---------------------------------------------------------
search_out = (
    "coreutils: /usr/bin/ls\n"
    "libc6:amd64: /usr/lib/x86_64-linux-gnu/libc.so.6\n"
    "pkg-a, pkg-b: /usr/share/shared\n"
    "diversion by libreadline8t64 from: /lib/x86_64-linux-gnu/libhistory.so.8.2\n"
    "diversion by libreadline8t64 to: /lib/x86_64-linux-gnu/libhistory.so.8.2.usr-is-merged\n"
)
assert dpkg_mod._parse_search(search_out) == {
    "/usr/bin/ls": "coreutils",
    "/usr/lib/x86_64-linux-gnu/libc.so.6": "libc6:amd64",  # the ":" in the name doesn't split it
    "/usr/share/shared": "pkg-a",
}, "diversion notes are not owners"


class FakeRun:
    """Stands in for subprocess.run: records calls, returns canned output."""
    def __init__(self, *results):
        self.results, self.calls = list(results), []

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        out, err, rc = self.results.pop(0)
        return type("R", (), {"stdout": out, "stderr": err, "returncode": rc})()


real_run = dpkg_mod.subprocess.run
real_mod_available = (dpkg_mod.available, rpm_mod.available)
present("dpkg", "rpm")
# owner() checks the MODULE-level available() (is the command on PATH?),
# not the backend class's, so fake that too -- otherwise these tests only
# pass on a machine that happens to have dpkg and rpm installed.
dpkg_mod.available = rpm_mod.available = lambda: True
try:
    # dpkg-query takes arguments as shell patterns: "/x/*" can match OTHER
    # files. Only an answer for exactly the path asked about counts -- and
    # since dpkg didn't say "nothing owns it" either, the answer is unknown.
    dpkg_mod.subprocess.run = FakeRun(("coreutils: /usr/bin/ls\n", "", 0))
    assert dpkg_mod.owner("/usr/bin/l*") == ("unknown", None), "a pattern match is neither owned nor unowned"

    fake = FakeRun(("coreutils: /usr/bin/ls\n", "", 0), ("9.4-3\n", "", 0))
    dpkg_mod.subprocess.run = fake
    assert dpkg_mod.owner("/usr/bin/ls") == ("owned", "coreutils 9.4-3")
    assert all(kw["env"]["LC_ALL"] == "C" for _, kw in fake.calls), "output parsed in the C locale"
    assert fake.calls[0][0][:3] == ["dpkg-query", "-S", "--"], "'--' so a path can't be read as an option"

    dpkg_mod.subprocess.run = FakeRun(("", "dpkg-query: no path found matching pattern /tmp/x\n", 1))
    assert dpkg_mod.owner("/tmp/x") == ("unowned", None)

    # A real failure exits non-zero too, and must not read as "nothing owns it"
    dpkg_mod.subprocess.run = FakeRun(("", "dpkg-query: error: parsing file '/var/lib/dpkg/status' "
                                           "near line 12: missing 'Package' field\n", 2))
    assert dpkg_mod.owner("/tmp/x") == ("unknown", None), "a damaged dpkg database is not 'unowned'"

    def boom(*a, **k):
        raise OSError("gone")
    dpkg_mod.subprocess.run = boom
    assert dpkg_mod.owner("/usr/bin/ls") == ("unknown", None), "a failure is never 'unowned'"

    # rpm (rpm_mod and dpkg_mod share the subprocess module)
    rpm_mod.subprocess.run = FakeRun(("coreutils 9.5-1.fc41\n", "", 0))
    assert rpm_mod.owner("/usr/bin/ls") == ("owned", "coreutils 9.5-1.fc41")
    rpm_mod.subprocess.run = FakeRun(("", "file /tmp/x is not owned by any package\n", 1))
    assert rpm_mod.owner("/tmp/x") == ("unowned", None)
    rpm_mod.subprocess.run = FakeRun(("", "error: rpmdb: BDB0113 Thread/process failed\n", 1))
    assert rpm_mod.owner("/tmp/x") == ("unknown", None)
finally:
    dpkg_mod.subprocess.run = real_run
    dpkg_mod.available, rpm_mod.available = real_mod_available
    for cls, flag in real_available.items():
        cls.available = flag
print("dpkg/rpm ownership tests passed ✓")

# --- dpkg/rpm results and the report ---------------------------------------------------
from ensign_scan.db import make_engine  # noqa: E402

dpkg_output = (
    "??5??????   /usr/bin/tac\n"
    "??5?????? c /etc/adduser.conf\n"
    "?????????   /etc/sudoers\n"
    "missing     /usr/share/doc/coreutils/AUTHORS\n"
    "missing     /usr/share/man/man1/ls.1.gz\n"
    "missing     /usr/lib/gone.so\n"
)
owners = {"/usr/bin/tac": "coreutils", "/etc/adduser.conf": "adduser", "/etc/sudoers": "sudo",
          "/usr/lib/gone.so": "libgone"}
result = dpkg_mod.parse_verify(dpkg_output, owners, [("path-exclude", "/usr/share/*")])
assert result.candidate_line_count == result.parsed_line_count == 6
assert sum(m.excluded for m in result.mismatches) == 2, "only the /usr/share 'missing' files are excluded"


def report(result, backend) -> str:
    with tempfile.TemporaryDirectory() as d:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            reports.package_report(make_engine(f"sqlite:///{d}/r.db"), result, backend)
        return " ".join(buf.getvalue().split())  # undo rich's line wrapping


out = report(result, DpkgBackend())
assert "=== DPKG FILE INTEGRITY (6 of 6 candidate lines parsed) ===" in out, out
assert "2 files differ from dpkg's records" in out, "tac (checksum) and gone.so (missing)"
assert "coreutils: /usr/bin/tac" in out and "libgone: /usr/lib/gone.so" in out
assert "1 file dpkg could not verify" in out and "/etc/sudoers" in out, \
    "an unreadable config file is 'not verified', never 'edited on purpose'"
assert "1 config (conffile) file locally modified" in out and "/etc/adduser.conf" in out
assert "2 files left out on purpose" in out
assert "pacman" not in out, "no pacman wording in a dpkg report"

rpm_output = "S.5....T.  c /etc/ens.conf\nSM5....T.    /usr/bin/enstool\nmissing   d /usr/share/doc/x\n"
result = rpm_mod.parse_verify(rpm_output, {"/etc/ens.conf": "enstest", "/usr/bin/enstool": "enstest"})
assert result.parsed_line_count == 3 and len(result.mismatches) == 3 + 4 + 1, "one entry per failed test"
out = report(result, RpmBackend())
assert "=== RPM FILE INTEGRITY (3 of 3 candidate lines parsed) ===" in out
assert "(unknown package): /usr/share/doc/x" in out, "no owner found is shown, not hidden"
assert "Checksum mismatch" in out and "Mode mismatch" in out
assert "1 config file locally modified" in out

garbled = dpkg_mod.parse_verify("?? weird line /usr/bin/x\n", {}, [])
out = report(garbled, DpkgBackend())
assert "parser may need updating" in out and "'dpkg --verify'" in out, out
assert "?? weird line /usr/bin/x" in out, "the line that didn't parse is shown as printed"

# Some lines parse, some don't: the ones that don't must not vanish quietly
partly = dpkg_mod.parse_verify("??5??????   /usr/bin/tac\n?? odd /usr/bin/y\n", {"/usr/bin/tac": "coreutils"}, [])
assert partly.parsed_line_count == 1 and partly.candidate_line_count == 2 and partly.unparsed == ("?? odd /usr/bin/y",)
out = report(partly, DpkgBackend())
assert "(1 of 2 candidate lines parsed)" in out
assert "1 line from dpkg couldn't be read by Ensign and is not in this report" in out, out
assert "?? odd /usr/bin/y" in out and "coreutils: /usr/bin/tac" in out, "shown, and the rest still reported"

# pacman: a path with spaces parses (cmake really ships these), and the report
# would flag anything that still didn't
from ensign_scan.pkgdb.pacman import PacmanVerifyResult, _MISMATCH_RE  # noqa: E402
m = _MISMATCH_RE.match("warning: cmake: /usr/share/cmake/Help/generator/Borland Makefiles.rst (Size mismatch)")
assert m and m["path"] == "/usr/share/cmake/Help/generator/Borland Makefiles.rst" and m["reason"] == "Size mismatch"
m = _MISMATCH_RE.match("backup file: foo: /etc/foo bar.conf (Modification time mismatch)")
assert m and m["kind"] == "backup file" and m["path"] == "/etc/foo bar.conf"
m = _MISMATCH_RE.match("warning: x: /a (b)/c (Size mismatch)")
assert m and m["path"] == "/a (b)/c" and m["reason"] == "Size mismatch", "only the LAST bracket is the reason"
out = report(PacmanVerifyResult(mismatches=[], candidate_line_count=3, unparsed=("odd (1)", "odd (2)", "odd (3)")),
             PacmanBackend())
assert "parser may need updating" in out and "odd (1)" in out
print("unparsed-line tests passed ✓")
print("dpkg/rpm report tests passed ✓")

# --- config: package_verification -----------------------------------------------
assert Config().package_verification == "auto"
for value, ok in (("auto", True), ("off", True), ("pacman", True), ("dpkg", True), ("rpm", True), ("Pacman", False), ("yes", False), (True, False)):
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

# --- --verify-packages: no time limit, and Ctrl+C stops it cleanly ------------------
import inspect  # noqa: E402

from ensign_scan.pkgdb import pacman as pacman_mod  # noqa: E402
for mod in (pacman_mod, dpkg_mod, rpm_mod):
    default = inspect.signature(mod.verify_all).parameters["timeout"].default
    assert default is None, f"{mod.__name__}.verify_all has a default time limit ({default})"


class InterruptedBackend(PacmanBackend):
    def verify_all(self):
        raise KeyboardInterrupt


with tempfile.TemporaryDirectory() as d:
    cfg = Path(d, "config.toml")
    cfg.write_text(f'data_dir = "{d}/data"\n')
    real_configure = cli.pkgdb.configure
    cli.pkgdb.configure = lambda setting: setattr(pkgdb, "_active", InterruptedBackend())
    sys.argv = ["ensign-scan", "--verify-packages", "--config", str(cfg)]
    try:
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            code = cli.main()
    finally:
        cli.pkgdb.configure = real_configure
        pkgdb._active = None
    out = " ".join(buf.getvalue().split())
    assert code == 130, code
    assert "Ctrl+C stops it" in out and "nothing was changed" in out, out
print("--verify-packages interrupt tests passed ✓")

# --- packaging: every subpackage ships ------------------------------------------
# setuptools only installs the packages listed in pyproject.toml. A new
# subpackage that isn't listed works from a checkout but is missing from
# the PyPI install -- an ImportError only users would see.
root = ROOT
listed = set(tomllib.loads((root / "pyproject.toml").read_text())["tool"]["setuptools"]["packages"])
found = {
    ".".join(p.parent.relative_to(root).parts)
    for p in (root / "ensign_scan").rglob("__init__.py")
}
assert found <= listed, f"packages missing from pyproject.toml: {sorted(found - listed)}"
print("packaging test passed ✓")

# --- live: the real package manager ----------------------------------------------------
# ENSIGN_EXPECT_BACKEND names what detection must pick on this machine
# ("none" is a valid answer). For a real backend, everything is then
# checked against the real package manager: ownership, and every line
# of a full verify run parsing. Optional:
#   ENSIGN_SKIP_FULL_VERIFY=1         ownership checks only (for machines
#                                     with so many packages that a full
#                                     verify outlasts its timeout)
#   ENSIGN_EXPECT_VERIFY_FINDINGS=1   the verify run must find something
#                                     (CI plants changes so the parser is
#                                     tested on real findings, not on "clean")
KNOWN_FILE = {"pacman": "/usr/bin/pacman", "dpkg": "/usr/bin/dpkg", "rpm": "/usr/bin/rpm"}
expected = os.environ.get("ENSIGN_EXPECT_BACKEND")
if expected:
    backend = pkgdb.detect()
    assert backend.name == expected, \
        f"expected backend {expected!r} here, detected {backend.name!r} ({getattr(backend, 'reason', '')})"
    if expected == "none":
        assert backend.owner("/usr/bin/ls") == ("unknown", None)
    else:
        known = KNOWN_FILE[expected]
        state, pkg = backend.owner(known)
        assert state == "owned" and pkg.split()[0] == expected, (known, state, pkg)
        # /bin is a symlink to /usr/bin on all three families now
        if os.path.islink("/bin"):
            assert backend.owner("/bin/ls")[0] == "owned", backend.owner("/bin/ls")
        with tempfile.NamedTemporaryFile() as f:
            assert backend.owner(f.name) == ("unowned", None), "a fresh temp file belongs to no package"
        assert backend.owner("/usr/bin/ensign-no-such-file")[0] in ("unowned", "unknown")

    if expected != "none" and os.environ.get("ENSIGN_SKIP_FULL_VERIFY") == "1":
        print("  full verify skipped (ENSIGN_SKIP_FULL_VERIFY=1)")
    elif expected != "none":
        result = backend.verify_all()
        assert result is not None and result.error is None, result and result.error
        parsed = getattr(result, "parsed_line_count", 0) or len(result.mismatches)
        assert result.candidate_line_count == parsed, (
            f"{result.candidate_line_count - parsed} finding-shaped lines didn't parse; "
            f"run '{backend.verify_all_command}' and compare against the parser"
        )
        out = report(result, backend)
        assert f"{expected.upper()} FILE INTEGRITY" in out and "parser may need updating" not in out
        if os.environ.get("ENSIGN_EXPECT_VERIFY_FINDINGS") == "1":
            assert parsed > 0, "CI planted changes, but the verify run found none"
            assert any(m.excluded for m in result.mismatches) or expected != "dpkg", \
                "the planted path-exclude file wasn't recognised"
        print(f"  {parsed} verify lines parsed, {sum(m.excluded for m in result.mismatches)} excluded")
    print(f"live detection test passed ✓ ({backend.name})")
else:
    print("live detection test skipped (set ENSIGN_EXPECT_BACKEND to run it)")

print("All pkgdb tests passed ✓")
