"""The persistence audit (--persistence, --acknowledge, --acknowledge-all).

Runs on a fake root folder and a fake home, so nothing on this machine is
read. Checked here:

  * the first run lists everything as new; --acknowledge-all sets the
    baseline, and the next run reports nothing;
  * new entries, changed content, changed permissions, a retargeted
    symlink and a deleted entry are each reported as such;
  * --acknowledge PATH accepts one entry and no other, and says so for a
    path the audit doesn't check;
  * a FIFO where a startup file should be is reported, without hanging;
  * a credential-looking file is never opened (its size and times stand in,
    ctime included, so setting mtime back doesn't hide an edit);
  * a folder that can't be read is "couldn't check", and the entries
    acknowledged inside it are not reported as gone;
  * a file that can be listed but not read (a root-only cron job without
    sudo) is still reported when it is new, or when its permissions or
    owner changed; it can't be acknowledged without reading it;
  * a symlinked folder is an entry, not walked into, and a folder reached
    under two names is read once;
  * every acknowledgment is written to the log;
  * entries a package installed that still match it are counted, not
    listed; a modified or unowned one is listed with a note;
  * pkgdb.origins() never calls a file verified when the package manager
    couldn't confirm it;
  * pacman's and dpkg's batched owner lookups parse and escape correctly;
  * main.py --persistence exits 4 while something is pending, 0 when not.

    python3 tests/persistence_test.py
"""
from __future__ import annotations

import sys as _sys_path
from pathlib import Path as _Path

# Run against THIS checkout, never an installed copy of Ensign.
ROOT = _Path(__file__).resolve().parent.parent
_sys_path.path.insert(0, str(ROOT))

import contextlib  # noqa: E402
import io  # noqa: E402
import os  # noqa: E402
import tempfile  # noqa: E402
import threading  # noqa: E402
from pathlib import Path  # noqa: E402

from sqlalchemy.orm import Session  # noqa: E402

from ensign_scan import persistence, pkgdb  # noqa: E402
from ensign_scan.db import make_engine  # noqa: E402
from ensign_scan.models import PersistenceEntry  # noqa: E402
from ensign_scan.pkgdb import dpkg, pacman  # noqa: E402
from ensign_scan.pkgdb.base import Backend, FileMismatch, VerifyResult  # noqa: E402

pkgdb.configure("off")


def quiet(fn, *args, **kwargs):
    """(result, output with line breaks folded into spaces)."""
    with contextlib.redirect_stdout(io.StringIO()) as buf:
        result = fn(*args, **kwargs)
    return result, " ".join(buf.getvalue().split())


def write(path: Path, text: str, mode: int = 0o644) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(mode)
    return path


with tempfile.TemporaryDirectory() as d:
    root, home = Path(d, "root"), Path(d, "home")
    data = Path(d, "data")
    data.mkdir()
    log = data / "persistence_acknowledged.log"
    engine = make_engine(f"sqlite:///{data}/system.db")

    unit = write(root / "etc/systemd/system/backup.service", "[Service]\nExecStart=/usr/bin/true\n")
    wants = root / "etc/systemd/system/multi-user.target.wants"
    wants.mkdir(parents=True)
    os.symlink("/etc/systemd/system/backup.service", wants / "backup.service")
    write(root / "usr/lib/systemd/system/sshd.service", "[Service]\nExecStart=/usr/bin/sshd\n")
    # /lib -> usr/lib, as on a merged-/usr system: read once, as /usr/lib
    os.symlink("usr/lib", root / "lib")
    bashrc = write(home / ".bashrc", "alias ll='ls -l'\n")
    profile_d = write(root / "etc/profile.d/locale.sh", "export LANG=C\n").parent
    hook = write(root / "etc/pacman.d/hooks/clean.hook", "[Action]\nExec=/usr/bin/true\n")
    cron = write(root / "etc/cron.d/backup", "0 3 * * * root /usr/bin/true\n")
    # A symlinked folder inside an audited one: an entry, never walked into.
    elsewhere = write(Path(d, "elsewhere/evil.service"), "[Service]\nExecStart=/tmp/x\n").parent
    os.symlink(elsewhere, root / "etc/systemd/system/linked.d")
    # Looks like a credential: never opened.
    wallet = write(home / ".config/environment.d/wallet.dat", "not really a wallet")

    def audit(check_packages=False):
        return persistence.run_audit(engine, str(home), str(root), check_packages=check_packages)

    # --- first run: everything is new --------------------------------------------------------------
    first = audit()
    paths = {e.path for e in first.new}
    assert str(unit) in paths and str(bashrc) in paths and str(hook) in paths and str(cron) in paths
    assert str(root / "usr/lib/systemd/system/sshd.service") in paths
    assert not any("/lib/systemd" in p and "/usr/lib/" not in p for p in paths), paths  # read once
    assert str(root / "etc/systemd/system/linked.d") in paths, "symlinked folder is an entry"
    assert not any(p.startswith(str(elsewhere)) or p.endswith("linked.d/evil.service") for p in paths)
    link = first.new[[e.path for e in first.new].index(str(wants / "backup.service"))]
    assert link.kind == "symlink" and link.digest == "/etc/systemd/system/backup.service", link
    w = first.new[[e.path for e in first.new].index(str(wallet))]
    assert w.digest.startswith("metadata "), w
    _, out = quiet(persistence.report, first)
    assert "Nothing has been acknowledged yet" in out and "NEW SINCE YOU LAST ACKNOWLEDGED" in out, out
    assert "--acknowledge-all" in out
    print("persistence first run test passed ✓")

    # --- acknowledge-all, then nothing is pending ----------------------------------------------------
    n, _ = quiet(persistence.acknowledge_all, engine, first, log)
    assert n == len(first.new) and n > 0
    again = audit()
    assert again.pending == 0 and again.acknowledged == n, (again.new, again.changed, again.removed)
    _, out = quiet(persistence.report, again)
    assert "Nothing new, changed or gone" in out, out
    lines = log.read_text().splitlines()
    assert len(lines) == n and all(line.split("\t")[1] == "acknowledged" for line in lines)
    assert any(line.split("\t")[2] == str(unit) and line.split("\t")[6] == "0644" for line in lines)

    # A credential-looking entry is never opened, so its size and times
    # stand in for its contents. Edit it to the same size and set its mtime
    # back (touch -d): its ctime still moves, and gives the edit away.
    before = wallet.stat()
    wallet.write_text("NOT really a wallet")              # same length
    os.utime(wallet, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert wallet.stat().st_size == before.st_size and wallet.stat().st_mtime_ns == before.st_mtime_ns
    edited = audit()
    assert [e.path for _, e in edited.changed] == [str(wallet)], (edited.new, edited.changed)
    quiet(persistence.acknowledge_all, engine, edited, log)
    print("persistence acknowledge-all test passed ✓")

    # --- every kind of change ------------------------------------------------------------------------
    unit.write_text("[Service]\nExecStart=/tmp/.hidden/miner\n")          # content
    hook.chmod(0o666)                                                      # permissions
    os.unlink(wants / "backup.service")                                    # retargeted symlink
    os.symlink("/tmp/evil.service", wants / "backup.service")
    cron.unlink()                                                          # gone
    write(home / ".config/autostart/updater.desktop", "[Desktop Entry]\nExec=/tmp/u\n")  # new
    write(root / "etc/ld.so.preload", "/tmp/libhook.so\n")                 # new, and alarming
    result = audit()
    changed = {e.path: persistence._differences(row, e) for row, e in result.changed}
    assert changed[str(unit)] == "content changed", changed
    assert changed[str(hook)] == "permissions 0644 → 0666", changed
    assert changed[str(wants / "backup.service")].startswith("now points to /tmp/evil.service"), changed
    assert {r.path for r in result.removed} == {str(cron)}
    assert {e.path for e in result.new} == {str(home / ".config/autostart/updater.desktop"),
                                            str(root / "etc/ld.so.preload")}
    _, out = quiet(persistence.report, result)
    assert "CHANGED SINCE YOU ACKNOWLEDGED THEM (3)" in out and "GONE SINCE YOU ACKNOWLEDGED THEM (1)" in out
    assert "ld.so.preload: Libraries loaded into every program" in out, out
    assert out.index("ld.so.preload") < out.index("desktop autostart"), "preload listed first"
    print("persistence change detection test passed ✓")

    # --- an entry named through a symlinked folder is the same entry --------------------------------
    alias = Path(d, "home-alias")
    os.symlink(home, alias)
    assert persistence.resolve_dirs(str(alias / ".bashrc")) == str(bashrc)
    assert persistence.resolve_dirs(str(root / "lib/systemd/system/sshd.service")) == \
        str(root / "usr/lib/systemd/system/sshd.service")

    # --- acknowledge one entry -----------------------------------------------------------------------
    n, out = quiet(persistence.acknowledge, engine, result, [str(unit)], log)
    assert n == 1 and "Acknowledged" in out, out
    n, out = quiet(persistence.acknowledge, engine, audit(), [str(unit), str(root / "etc/hostname")], log)
    assert n == 0 and "Already acknowledged" in out and "Not a startup entry" in out, out
    left = audit()
    assert str(unit) not in {e.path for _, e in left.changed} and left.pending == result.pending - 1
    n, out = quiet(persistence.acknowledge, engine, left, [str(cron)], log)   # a gone entry
    assert n == 1 and "Gone, and forgotten" in out, out
    with Session(engine) as session:
        assert session.query(PersistenceEntry).filter(PersistenceEntry.path == str(cron)).count() == 0
    assert log.read_text().splitlines()[-1].split("\t")[1:3] == ["gone", str(cron)]
    quiet(persistence.acknowledge_all, engine, audit(), log)
    assert audit().pending == 0
    print("persistence acknowledge test passed ✓")

    # --- a FIFO where a startup file should be: reported, no hang ------------------------------------
    bashrc.unlink()
    os.mkfifo(bashrc)
    box: list = []
    t = threading.Thread(target=lambda: box.append(audit()), daemon=True)
    t.start()
    t.join(20)
    assert box, "the audit hung on a FIFO"
    fifo = {e.path: e for _, e in box[0].changed}[str(bashrc)]
    assert fifo.kind == "fifo", fifo
    _, out = quiet(persistence.report, box[0])
    assert "was a file, now a fifo" in out, out
    bashrc.unlink()
    bashrc.write_text("alias ll='ls -l'\n")
    bashrc.chmod(0o644)
    print("persistence FIFO test passed ✓")

    # --- a folder that can't be read -------------------------------------------------------------------
    if os.geteuid() != 0:   # root reads everything, so this can't be set up as root
        profile_d.chmod(0)
        try:
            blocked = audit()
            assert str(profile_d) in blocked.unchecked, blocked.unchecked
            assert not any(r.path.startswith(str(profile_d)) for r in blocked.removed), blocked.removed
            _, out = quiet(persistence.report, blocked)
            assert "COULDN'T CHECK" in out, out
            inside = str(profile_d / "locale.sh")       # acknowledged, but unreadable now
            n, out = quiet(persistence.acknowledge, engine, blocked, [inside], log)
            assert n == 0 and "Couldn't read it" in out and "unchanged" not in out, out
        finally:
            profile_d.chmod(0o755)
        # A file that can be listed but not read: new, it is still NEW.
        hidden = write(root / "etc/cron.d/hidden", "* * * * * root /tmp/x\n", 0o000)
        try:
            seen = audit()
            entry = {e.path: e for e in seen.new}.get(str(hidden))
            assert entry is not None and not entry.readable, (seen.new, seen.unchecked)
            assert seen.pending >= 1 and persistence.unreadable_pending(seen) == 1
            _, out = quiet(persistence.report, seen)
            assert "couldn't read it; run with sudo" in out and "Nothing new" not in out, out
            n, out = quiet(persistence.acknowledge, engine, seen, [str(hidden)], log)
            assert n == 0 and "with sudo it can be" in out, out
            quiet(persistence.acknowledge_all, engine, seen, log)
            assert str(hidden) in {e.path for e in audit().new}, "acknowledge-all can't take it either"
        finally:
            hidden.unlink()
        # An acknowledged file made unreadable: its permissions changed, so CHANGED.
        hook.chmod(0o000)
        try:
            seen = audit()
            changed = {e.path: persistence._differences(row, e) for row, e in seen.changed}
            assert changed.get(str(hook)) == "permissions 0666 → 0000", (changed, seen.unchecked)
        finally:
            hook.chmod(0o666)
        assert audit().pending == 0
        print("persistence unreadable folder test passed ✓")
    else:
        print("persistence unreadable folder test skipped (running as root)")

    # --- package-owned entries: counted when verified, listed otherwise -------------------------------
    write(root / "usr/lib/systemd/system/a.service", "a")
    write(root / "usr/lib/systemd/system/b.service", "b")
    write(root / "usr/lib/systemd/system/c.service", "c")
    real_origins = pkgdb.origins
    pkgdb.origins = lambda paths, backend=None: {   # noqa: E731
        p: ((pkgdb.FROM_PACKAGE, "pkg-a") if p.endswith(("a.service", "b.service"))
            else (pkgdb.MODIFIED, "pkg-c") if p.endswith("c.service")
            else (pkgdb.UNOWNED, None)) for p in paths}
    try:
        owned = audit(check_packages=True)
        _, out = quiet(persistence.report, owned)
    finally:
        pkgdb.origins = real_origins
    assert "2 in " + str(root / "usr/lib/systemd/system") + " came from packages" in out, out
    assert "a.service" not in out and "b.service" not in out, out
    assert "c.service (differs from what pkg-c installed)" in out, out
    assert str(home / ".bashrc") not in owned.origins, "home-folder entries are never looked up"
    print("persistence package grouping test passed ✓")


# --- pkgdb.origins: a doubt never counts as verified -------------------------------------------------
class FakeBackend(Backend):
    name = label = "fake"

    def __init__(self, result):
        self.result = result

    def owners(self, paths):
        return {p: (None if "stray" in p else "pkg") for p in paths if "unknown" not in p}

    def verify_packages(self, packages):
        return self.result


paths = ["/usr/lib/x/same", "/usr/lib/x/edited", "/usr/lib/x/unreadable", "/usr/lib/x/stray",
         "/usr/lib/x/unknown"]
clean = VerifyResult([FileMismatch("pkg", "/usr/lib/x/edited", "Checksum mismatch"),
                      FileMismatch("pkg", "/usr/lib/x/unreadable", "Permission denied", unverified=True)], 2)
got = {p: s for p, (s, _) in pkgdb.origins(paths, FakeBackend(clean)).items()}
assert got == {"/usr/lib/x/same": pkgdb.FROM_PACKAGE, "/usr/lib/x/edited": pkgdb.MODIFIED,
               "/usr/lib/x/unreadable": pkgdb.OWNED, "/usr/lib/x/stray": pkgdb.UNOWNED,
               "/usr/lib/x/unknown": pkgdb.UNKNOWN}, got
for doubtful in (None, VerifyResult([], 0, error="timed out"), VerifyResult([], 1, unparsed=("??",))):
    got = {p: s for p, (s, _) in pkgdb.origins(paths, FakeBackend(doubtful)).items()}
    assert pkgdb.FROM_PACKAGE not in got.values(), (doubtful, got)
print("pkgdb.origins test passed ✓")

# --- batched owner lookups --------------------------------------------------------------------------
asked = ["/usr/lib/systemd/system/sshd.service", "/etc/systemd/system/x.service",
         "/usr/share/doc/Borland Makefiles.rst", "/never/printed"]
found = pacman.parse_owners(
    "/usr/lib/systemd/system/sshd.service is owned by openssh 9.9p1-1\n"
    "/usr/share/doc/Borland Makefiles.rst is owned by cmake 3.31.0-1\n"
    "/somewhere/else is owned by other 1-1\n",
    "error: No package owns /etc/systemd/system/x.service\n", asked)
assert found == {"/usr/lib/systemd/system/sshd.service": "openssh",
                 "/usr/share/doc/Borland Makefiles.rst": "cmake",
                 "/etc/systemd/system/x.service": None}, found
assert dpkg._glob_escape(r"/a/system-systemd\x2dsetup.slice") == r"/a/system-systemd\\x2dsetup.slice"
assert dpkg._glob_escape("/a/[b]*?") == r"/a/\[b\]\*\?"
print("pkgdb owner lookup parsing test passed ✓")

# --- the exit code, end to end through main.py ---------------------------------------------------
# This one audits the real system's locations (only the home folder is
# fake), with package lookups off so it stays quick.
import subprocess  # noqa: E402

with tempfile.TemporaryDirectory() as d:
    cfg = Path(d, "c.toml")
    cfg.write_text(f'data_dir = "{d}"\npackage_verification = "off"\n')
    env = dict(os.environ, HOME=d)

    def run(*args):
        # stdin from /dev/null: run from a terminal, the child would
        # otherwise inherit it and wait at the confirm question, unseen.
        return subprocess.run([_sys_path.executable, str(ROOT / "main.py"), "--config", str(cfg), *args],
                              capture_output=True, text=True, env=env, timeout=600, cwd=ROOT,
                              stdin=subprocess.DEVNULL)

    write(Path(d, ".bashrc"), "alias ll='ls -l'\n")
    first = run("--persistence")
    assert first.returncode == 4, (first.returncode, first.stdout[-500:], first.stderr[-500:])
    declined = run("--acknowledge-all")          # no terminal to ask on, no --yes: declined
    assert declined.returncode == 4, (declined.returncode, declined.stdout[-300:])
    done = run("--acknowledge-all", "--yes")
    assert done.returncode == 0, (done.returncode, done.stdout[-500:])
    clean = run("--persistence")
    assert clean.returncode == 0, (clean.returncode, clean.stdout[-1500:])
    write(Path(d, ".config/autostart/new.desktop"), "[Desktop Entry]\nExec=/bin/true\n")
    again = run("--persistence")
    assert again.returncode == 4 and "new.desktop" in again.stdout, (again.returncode, again.stdout[-500:])
print("persistence exit code test passed ✓")
