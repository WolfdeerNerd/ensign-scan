"""End-to-end test of the INSTALLED ensign-scan command.

Skipped unless ENSIGN_CLI points at an installed `ensign-scan` executable.
CI builds the wheel, installs it into a clean virtual environment and
points ENSIGN_CLI there, so this tests the package users get from PyPI,
not this checkout. It never imports ensign_scan itself, for the same
reason: everything goes through the command, in a separate process.

    ENSIGN_CLI=/path/to/venv/bin/ensign-scan python3 tests/cli_live_test.py

Optional:
  ENSIGN_TEST_CLAMD_SOCKET  a real clamd. Adds the scanning tests (EICAR
                            found, change detection, purge, run lock).
                            CI starts one with .github/scripts/start-test-clamd.sh;
                            your own clamd works too.
  ENSIGN_EXPECT_VERSION     the version --version must report (CI's
                            release job passes the tag, minus the "v").
                            Default: the version in pyproject.toml.

Run under sudo as well, it checks the sudo behaviour: "~" must still mean
the invoking user's home, not /root.
"""
from __future__ import annotations

import fcntl
import os
import pwd
import re
import socket
import sqlite3
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

CLI = os.environ.get("ENSIGN_CLI")
SOCKET = os.environ.get("ENSIGN_TEST_CLAMD_SOCKET")
ROOT = Path(__file__).resolve().parent.parent  # the repo root (this file is in tests/)

if not CLI:
    print("installed-CLI test skipped (set ENSIGN_CLI to run it)")
    sys.exit(0)

CLI = str(Path(CLI).resolve())
assert os.access(CLI, os.X_OK), f"ENSIGN_CLI is not an executable: {CLI}"
_ANSI = re.compile(r"\x1b\[[0-9;]*m")

# The EICAR test string, in two halves so this file never contains it whole.
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR" + b"-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

AS_ROOT = os.geteuid() == 0
SUDO_USER = os.environ.get("SUDO_USER") if AS_ROOT else None


def run(*args: str, expect: int = 0, cwd: Path) -> str:
    """Run the installed command; return its output with colour codes removed."""
    result = subprocess.run([CLI, *args], cwd=cwd, capture_output=True, text=True, timeout=300,
                            env={**os.environ, "NO_COLOR": "1", "TERM": "dumb"})
    out = _ANSI.sub("", result.stdout + result.stderr)
    assert result.returncode == expect, \
        f"ensign-scan {' '.join(args)} exited {result.returncode}, expected {expect}:\n{out}"
    return out


def rows(db: Path) -> dict[str, tuple]:
    """filepath -> (scan_status, threat_name, last_scanned), read with plain sqlite3."""
    with sqlite3.connect(db) as con:
        # A name that isn't valid UTF-8 is stored as its bytes (a BLOB):
        # decode it the way Python names such files, so keys compare equal.
        return {(p.decode("utf-8", "surrogateescape") if isinstance(p, bytes) else p): (s, t, ls)
                for p, s, t, ls in
                con.execute("SELECT filepath, scan_status, threat_name, last_scanned FROM files")}


with tempfile.TemporaryDirectory(prefix="ensign_cli_") as tmp:
    tmp = Path(tmp)
    work = tmp / "cwd"        # run from here, so nothing from the checkout is importable
    tree = tmp / "tree"
    data = tmp / "data"
    for d in (work, tree / "sub" / "deeper"):
        d.mkdir(parents=True)
    clean = tree / "clean.txt"
    clean.write_text("nothing to see here\n")
    infected = tree / "sub" / "eicar.com"
    infected.write_bytes(EICAR)
    private = tree / "sub" / "deeper" / "private.txt"
    private.write_text("owner-only file\n")
    private.chmod(0o600)  # clamd can't open this by path; Ensign passes it an open handle

    config = tmp / "config.toml"
    config.write_text(
        f'data_dir = "{data}"\n'
        f'clamd_socket = "{SOCKET or tmp / "no-clamd.ctl"}"\n'
        "signature_max_age_days = 0\n"
        "max_workers = 2\n"
        f'scan_targets = ["{tree}"]\n'
    )
    db = data / "system.db"

    # --- the installed package, not the checkout ---------------------------------
    python = Path(CLI).parent / "python"
    if python.exists():
        where = subprocess.run([str(python), "-I", "-c", "import ensign_scan; print(ensign_scan.__file__)"],
                               cwd=work, capture_output=True, text=True, check=True).stdout.strip()
        assert not where.startswith(str(ROOT) + os.sep), \
            f"ENSIGN_CLI imports the checkout ({where}), not an installed package"
        # Every module must import from the installed copy. A subpackage left
        # out of pyproject.toml's package list only fails here, not from a checkout.
        subprocess.run([str(python), "-I", "-c",
                        "import importlib, pkgutil, ensign_scan\n"
                        "for m in pkgutil.walk_packages(ensign_scan.__path__, 'ensign_scan.'):\n"
                        "    importlib.import_module(m.name)"],
                       cwd=work, check=True)
    print("installed-package import test passed ✓")

    # --- --version ---------------------------------------------------------------
    expected = os.environ.get("ENSIGN_EXPECT_VERSION") or \
        tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    out = run("--version", cwd=work).strip()
    assert out == f"ensign-scan {expected}", f"--version said {out!r}, expected {expected!r}"
    print("--version test passed ✓")

    # --- --diagnostics: read-only and private ---------------------------------------
    out = run("--diagnostics", "--config", str(config), cwd=work)
    assert "=== Ensign diagnostics ===" in out
    assert str(tmp) not in out, "diagnostics leaked a path"
    # "root" isn't private, and diagnostics names it on purpose ("running as root")
    for private_word in {pwd.getpwuid(os.getuid()).pw_name, SUDO_USER, socket.gethostname()} - {None, "root"}:
        assert not re.search(rf"\b{re.escape(private_word)}\b", out), \
            f"diagnostics leaked {private_word!r}"
    assert not data.exists(), "--diagnostics must not create the data directory"
    if AS_ROOT:
        assert re.search(r"running as root:\s+yes", out)
    if SOCKET:
        assert re.search(r"clamd:\s+answering", out), out
        assert re.search(r"fd passing:\s+supported", out), out
        assert re.search(r"clamd runs as:\s+unprivileged user", out), out
    print("--diagnostics test passed ✓")

    # --- sudo: "~" is still the invoking user's home ------------------------------------
    if SUDO_USER:
        home = pwd.getpwnam(SUDO_USER).pw_dir
        if python.exists():
            got = subprocess.run([str(python), "-I", "-c", "from ensign_scan.config import HOME; print(HOME)"],
                                 cwd=work, capture_output=True, text=True, check=True).stdout.strip()
            assert got == home, f"under sudo, HOME resolved to {got!r}, expected {home!r}"
        print("sudo home-resolution test passed ✓")

    if not SOCKET:
        # No clamd: hash and record only, which still exercises the installed
        # scanner, database and reports end to end.
        out = run("--no-scan", "--config", str(config), str(tree), cwd=work)
        assert "All finished" in out, out
        recorded = rows(db)
        assert {str(clean), str(infected), str(private)} <= recorded.keys(), recorded
        infected.unlink()
        run("--purge-missing", "--config", str(config), cwd=work)
        assert str(infected) not in rows(db), "--purge-missing kept a deleted file"
        print("no-clamd run test passed ✓")
        print("\nAll installed-CLI tests passed ✓ (scanning tests skipped: set ENSIGN_TEST_CLAMD_SOCKET)")
        sys.exit(0)

    # --- a real scan -----------------------------------------------------------------------
    # Exit code 3: the run finished and infected files are present.
    out = run("--config", str(config), str(tree), expect=3, cwd=work)
    assert "All finished" in out, out
    first = rows(db)
    assert first[str(infected)][0] == "infected", f"EICAR not found: {first[str(infected)]}"
    assert "eicar" in (first[str(infected)][1] or "").lower(), first[str(infected)]
    assert first[str(clean)][0] == "clean", first[str(clean)]
    assert first[str(private)][0] == "clean", \
        f"owner-only file should scan through the passed handle: {first[str(private)]}"
    print("real scan test passed ✓")

    # --- unchanged files are not rescanned -------------------------------------------------
    # Still 3: an infection found on an earlier run and still there counts too.
    run("--config", str(config), str(tree), expect=3, cwd=work)
    second = rows(db)
    assert second[str(clean)][2] == first[str(clean)][2], "an unchanged clean file was rescanned"
    assert second[str(infected)][0] == "infected"
    print("unchanged-file test passed ✓")

    # --- a changed file is rescanned ----------------------------------------------------------
    clean.write_bytes(EICAR)
    run("--config", str(config), str(tree), expect=3, cwd=work)
    assert rows(db)[str(clean)][0] == "infected", "a file that changed into EICAR wasn't rescanned"
    print("change-detection test passed ✓")

    # --- read-only reports -----------------------------------------------------------------------
    run("--suggest-fixes", "--config", str(config), cwd=work)
    run("--rescan-errors", "--config", str(config), cwd=work)
    print("read-only report test passed ✓")

    # --- --purge-missing --------------------------------------------------------------------------
    infected.unlink()
    run("--purge-missing", "--config", str(config), cwd=work)
    after = rows(db)
    assert str(infected) not in after and str(clean) in after, "--purge-missing removed the wrong rows"
    print("--purge-missing test passed ✓")

    # --- only one run at a time ---------------------------------------------------------------
    with open(data / "ensign.lock", "a+") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        out = run("--config", str(config), str(tree), expect=75, cwd=work)
        assert "already running" in out, out
        # read-only reports don't take the lock, so they still work
        run("--suggest-fixes", "--config", str(config), cwd=work)
    print("run-lock test passed ✓")

    # --- a name that isn't valid UTF-8 is scanned, saved and reported ------------------
    odd_tree = tmp / "odd"
    odd_tree.mkdir()
    odd = os.fsdecode(os.path.join(os.fsencode(odd_tree), b"eicar-caf\xe9.com"))
    with open(os.fsencode(odd), "wb") as fh:
        fh.write(EICAR)
    out = run("--config", str(config), str(odd_tree), expect=3, cwd=work)
    flat = " ".join(out.split())
    assert "INFECTED FILES" in flat and "eicar-caf\\xe9.com" in flat, \
        "listed with its byte as \\xe9, so it can be found"
    assert "SCANNED BUT NOT SAVED" not in flat, out
    first = rows(db)[odd]
    assert first[0] == "infected", first
    run("--config", str(config), str(odd_tree), expect=3, cwd=work)
    assert rows(db)[odd][0] == "infected", "still tracked on the next run"
    # and once the infected file is gone, a clean tree exits 0 again
    os.remove(os.fsencode(odd))
    with open(os.path.join(os.fsencode(odd_tree), b"fine.txt"), "wb") as fh:
        fh.write(b"nothing to see")
    run("--config", str(config), str(odd_tree), expect=0, cwd=work)
    print("undecodable-filename test passed ✓")

print("\nAll installed-CLI tests passed ✓")
