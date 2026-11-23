"""Protected mode: your config and decisions kept where only root can write.

Checked here:

  * acl.py: a named-user entry is added, replaced and removed without
    touching the rest, and the mode's group bits follow the mask;
  * db.make_engine(decisions=...): a run reads allowances, folder allowances
    and acknowledged startup entries from root's decisions file, ignores the
    same tables in its own database, and can't write any of them -- through
    the scanner, the allow commands and the persistence audit alike;
  * protected runs refuse --config, $ENSIGN_CONFIG and the commands that
    change decisions;
  * as root: --protect creates root's copies (0711 above, 0700 + search for
    the user, 0600 + read for the user), the user's runs then find and use
    them, nobody else can read them, and the run stops -- never falling back
    to the user's own config -- when an ACL is lost, a file is replaced or
    made writable by others, or the decisions file is missing; a config with
    an error is refused before anything is created; --unprotect removes it all.

The first parts run as anyone. The root part is skipped (with a note)
otherwise. It works in a folder of its own, never in /etc or /var/lib:

    python3 tests/protect_test.py
    sudo python3 tests/protect_test.py
"""
from __future__ import annotations

import sys as _sys_path
from pathlib import Path as _Path

# Run against THIS checkout, never an installed copy of Ensign.
ROOT = _Path(__file__).resolve().parent.parent
_sys_path.path.insert(0, str(ROOT))

import argparse  # noqa: E402
import contextlib  # noqa: E402
import hashlib  # noqa: E402
import io  # noqa: E402
import os  # noqa: E402
import shutil  # noqa: E402
import sqlite3  # noqa: E402
import stat  # noqa: E402
import tempfile  # noqa: E402
from pathlib import Path  # noqa: E402

from sqlalchemy.orm import Session  # noqa: E402

from ensign_scan import acl, allowlist, cli, persistence, protect  # noqa: E402
from ensign_scan.clamd import ScanOutcome  # noqa: E402
from ensign_scan.config import Config  # noqa: E402
from ensign_scan.models import FileRecord, ScanStatus  # noqa: E402
from ensign_scan.scanner import Scanner  # noqa: E402

OTHER_UID = 65534   # "nobody": stands in for the user being protected


class FakeClamd:
    """Flags content containing EVIL as Test.Evil."""
    def daemon_uid(self):
        return 990   # not your uid: Ensign refuses a clamd running as you

    def supports_fildes(self):
        return True

    def signature_version(self):
        return 27000

    def max_threads(self):
        return 4

    def scan_fd(self, fd, label=""):
        if b"EVIL" in os.pread(fd, 1 << 20, 0):
            return ScanOutcome(ScanStatus.INFECTED, f"{label}: Test.Evil FOUND", "Test.Evil")
        return ScanOutcome(ScanStatus.CLEAN, f"{label}: OK")


def quiet(fn, *args, **kwargs):
    with contextlib.redirect_stdout(io.StringIO()) as buf:
        result = fn(*args, **kwargs)
    return result, " ".join(buf.getvalue().split())


def acl_supported(folder: Path) -> bool:
    probe = folder / "acl-probe"
    probe.write_bytes(b"")
    try:
        acl.grant(str(probe), os.geteuid() + 1, acl.READ)
        return True
    except acl.ACLUnsupported:
        return False
    finally:
        probe.unlink()


tmp = Path(tempfile.mkdtemp(prefix="ensign_protect_"))
os.chmod(tmp, 0o711)

# ----------------------------------------------------------------------
# 1. acl.py
# ----------------------------------------------------------------------
if not acl_supported(tmp):
    print(f"acl.py test skipped: the filesystem under {tmp} doesn't support ACLs")
    has_acls = False
else:
    has_acls = True
    f = tmp / "acl-file"
    f.write_bytes(b"x")
    os.chmod(f, 0o600)
    acl.grant(str(f), 4242, acl.READ)
    assert acl.named_users(str(f)) == {4242: acl.READ}
    assert stat.S_IMODE(f.stat().st_mode) == 0o640, "group bits show the mask (r)"
    acl.grant(str(f), 4243, acl.READ | acl.EXECUTE)
    assert acl.named_users(str(f)) == {4242: acl.READ, 4243: acl.READ | acl.EXECUTE}
    assert stat.S_IMODE(f.stat().st_mode) == 0o650, "the mask grows with the entries"
    acl.grant(str(f), 4242, acl.EXECUTE)
    assert acl.user_perm(str(f), 4242) == acl.EXECUTE, "granting again replaces, never adds"
    acl.revoke(str(f), 4243)
    acl.revoke(str(f), 4242)
    assert acl.named_users(str(f)) == {}
    assert stat.S_IMODE(f.stat().st_mode) == 0o600, "no entries left: back to the plain mode"
    try:
        acl.grant(str(f), 4242, 2)
        raise AssertionError("acl.grant must never give write")
    except ValueError:
        pass
    print("acl.py test passed ✓")

# ----------------------------------------------------------------------
# 2. Reading root's decisions instead of your own
# ----------------------------------------------------------------------
decisions = tmp / "decisions.db"
protect._create_decisions(decisions)
conn = sqlite3.connect(decisions)
assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "delete", \
    "rollback journal: reading it must never write a -shm file into root's folder"
conn.close()

tree = tmp / "tree"
tree.mkdir()
(tree / "asset.dat").write_bytes(b"game data with EVIL-looking bytes")
(tree / "forged.dat").write_bytes(b"malware EVIL, allowed in your own database")
digest = hashlib.sha256((tree / "asset.dat").read_bytes()).hexdigest()
forged_digest = hashlib.sha256((tree / "forged.dat").read_bytes()).hexdigest()

# Your own database, unprotected, with an allowance for the "malware".
data = tmp / "data"
data.mkdir()
plain = Config(db_url=f"sqlite:///{data}/system.db", log_file=data / "e.txt", max_workers=2)
engine = Scanner(plain, clamd=FakeClamd()).engine
with engine.begin() as c:
    c.exec_driver_sql("INSERT INTO allowances (file_hash, threat_name, filepath, allowed_at) "
                      "VALUES (?, 'Test.Evil', ?, '2026-11-23 10:00:00')", (forged_digest, str(tree / "forged.dat")))
    c.exec_driver_sql("INSERT INTO persistence_entries (path, category, kind, digest, acknowledged_at) "
                      "VALUES ('/home/user/.bashrc', 'shell', 'file', 'forged', '2026-11-23 10:00:00')")
engine.dispose()

# Root's decisions: the real false positive only.
with sqlite3.connect(decisions) as c:
    c.execute("INSERT INTO allowances (file_hash, threat_name, filepath, allowed_at) "
              "VALUES (?, 'Test.Evil', ?, '2026-11-23 10:00:00')", (digest, str(tree / "asset.dat")))
    c.execute("INSERT INTO allowed_folders (folder, threat_name, allowed_at, last_allowed_at) "
              "VALUES (?, 'Test.Evil', '2026-11-23 10:00:00', '2026-11-23 10:00:00')", (str(tree),))
c.close()

protected = Config(db_url=plain.db_url, log_file=plain.log_file, max_workers=2, decisions_db=decisions)
scanner = Scanner(protected, clamd=FakeClamd())
assert allowlist.allowed_pairs(scanner.engine) == {(digest, "Test.Evil")}, \
    "only root's allowance counts; the one in your own database is ignored"
quiet(scanner.scan_tree, tree)
with Session(scanner.engine) as s:
    got = {Path(r.filepath).name: r.scan_status for r in s.query(FileRecord)}
assert got == {"asset.dat": ScanStatus.ALLOWED.value, "forged.dat": ScanStatus.INFECTED.value}, got
_, out = quiet(allowlist.list_allowed, scanner.engine, expand=True)
assert "FOLDERS YOU ALLOWED (1)" in out, "root's folder allowance is read too"
assert "asset.dat" in out and "1 file here is infected now and not allowed" in out, out
assert out.count("forged.dat") == 0, out

audit = persistence.run_audit(scanner.engine, str(tmp), check_packages=False)
with Session(scanner.engine) as s:
    from ensign_scan.models import PersistenceEntry
    assert s.query(PersistenceEntry).count() == 0, "your own acknowledgments are ignored"

# Nothing can write a decision through a protected run's engine.
for attempt in (lambda: allowlist.allow(scanner.engine, str(tree / "forged.dat"), lambda p: True),
                lambda: allowlist.unallow(scanner.engine, str(tree / "asset.dat")),
                lambda: persistence.acknowledge_all(scanner.engine, audit, tmp / "ack.log")):
    try:
        quiet(attempt)
        changed = allowlist.allowed_pairs(scanner.engine) != {(digest, "Test.Evil")}
        raise AssertionError(f"a protected run wrote a decision (changed={changed})")
    except Exception as exc:   # noqa: BLE001 -- any refusal will do, as long as nothing changed
        if isinstance(exc, AssertionError):
            raise
        assert "view" in str(exc) or "readonly" in str(exc), exc
with sqlite3.connect(decisions) as c:
    assert c.execute("SELECT count(*) FROM allowances").fetchone()[0] == 1
    assert c.execute("SELECT count(*) FROM persistence_entries").fetchone()[0] == 0
c.close()
assert sorted(p.name for p in tmp.iterdir() if p.name.startswith("decisions")) == ["decisions.db"], \
    "reading root's file left nothing next to it"
scanner.engine.dispose()
print("protected reads test passed ✓")

# ----------------------------------------------------------------------
# 3. What a protected run refuses
# ----------------------------------------------------------------------
def ns(**kw):
    base = dict(config=None, allow=[], unallow=[], allow_folder=None, unallow_folder=None,
                acknowledge=[], acknowledge_all=False)
    return argparse.Namespace(**{**base, **kw})


saved = os.environ.pop("ENSIGN_CONFIG", None)
assert cli._protected_refusal(ns()) is None, "a plain run goes ahead"
for kw in ({"config": "/tmp/x.toml"}, {"allow": ["/x"]}, {"unallow": ["/x"]}, {"allow_folder": "/x"},
           {"unallow_folder": "/x"}, {"acknowledge": ["/x"]}, {"acknowledge_all": True}):
    assert cli._protected_refusal(ns(**kw)), f"refused: {kw}"
os.environ["ENSIGN_CONFIG"] = "/tmp/x.toml"
assert "ENSIGN_CONFIG" in cli._protected_refusal(ns())
os.environ.pop("ENSIGN_CONFIG")
if saved is not None:
    os.environ["ENSIGN_CONFIG"] = saved
print("protected refusals test passed ✓")

# ----------------------------------------------------------------------
# 4. As root: --protect, the user's view, failing closed, --unprotect
# ----------------------------------------------------------------------
if os.geteuid() != 0:
    print("root part skipped: run with sudo to check --protect and --unprotect")
elif not has_acls:
    print("root part skipped: no ACL support here")
else:
    import pwd
    # Never /etc or /var/lib: a folder of this test's own, set up like them.
    protect.CONFIG_ROOT = tmp / "etc"
    protect.DATA_ROOT = tmp / "var-lib"
    uid = OTHER_UID
    gid = pwd.getpwuid(uid).pw_gid

    def as_user(fn):
        """Run fn() as the protected user, in a child process; returns
        (ok, message)."""
        r, w = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(r)
            try:
                os.setgroups([])
                os.setgid(gid)
                os.setuid(uid)
                os.write(w, str(fn()).encode()[:4000])
                os._exit(0)
            except BaseException as exc:   # noqa: BLE001
                os.write(w, f"{type(exc).__name__}: {exc}".encode()[:4000])
                os._exit(1)
        os.close(w)
        with os.fdopen(r, "rb") as f:
            message = f.read().decode()
        return os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]) == 0, message

    yes = lambda prompt: True  # noqa: E731
    assert as_user(protect.status) == (True, "None"), "not protected yet"

    # A config with an error is refused, and leaves nothing behind.
    try:
        quiet(protect.protect, uid, "max_workers = 'many'\n", None, yes)
        raise AssertionError("a config with an error must be refused")
    except protect.CantProtect as exc:
        assert "error" in str(exc)
    assert not protect.is_protected(uid), "nothing is left after a refused --protect"

    # Declining changes nothing.
    assert quiet(protect.protect, uid, "", None, lambda p: False)[0] is None
    assert not protect.is_protected(uid)

    config_text = 'excludes = ["/srv/cache"]\n'
    found, out = quiet(protect.protect, uid, config_text, Path("/home/u/.config/ensign-scan/config.toml"), yes)
    assert found and "/srv/cache" in out, "the config is shown before anything is protected"
    for folder in (protect.CONFIG_ROOT, protect.CONFIG_ROOT / "users",
                   protect.DATA_ROOT, protect.DATA_ROOT / "users"):
        assert stat.S_IMODE(folder.stat().st_mode) == 0o711, f"{folder}: passable, not listable"
    for folder in (protect.config_dir(uid), protect.data_dir(uid)):
        assert folder.stat().st_uid == 0 and acl.named_users(str(folder)) == {uid: acl.EXECUTE}
    for f in (found.config, found.decisions):
        st = f.stat()
        assert st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o640, oct(st.st_mode)
        assert acl.named_users(str(f)) == {uid: acl.READ}
    assert found.config.read_text() == config_text
    try:
        quiet(protect.protect, uid, config_text, None, yes)
        raise AssertionError("--protect twice must say it's already done")
    except protect.CantProtect as exc:
        assert "already" in str(exc)

    # The user sees it, can load it, and can't change either file.
    ok, message = as_user(lambda: protect.status())
    assert ok and "Protected(" in message, message
    ok, message = as_user(lambda: Config.load(found.config).excludes)
    assert ok and "/srv/cache" in message, message
    for path in (found.config, found.decisions):
        ok, message = as_user(lambda p=path: open(p, "ab"))
        assert not ok and "Permission" in message, f"the user can't write {path}"

    # Another account sees nothing (nobody's group is the only other id at hand:
    # check the files' plain "other" bits, which is what any other account gets).
    for f in (found.config, found.decisions):
        assert f.stat().st_mode & 0o007 == 0

    # Failing closed: each of these stops the user's run, never "not protected".
    def expect_unsafe(why: str):
        ok, message = as_user(protect.status)
        assert not ok and message.startswith("Unsafe:"), f"{why}: {message}"

    acl.revoke(str(protect.config_dir(uid)), uid)
    expect_unsafe("lost ACL on the folder")
    acl.grant(str(protect.config_dir(uid)), uid, acl.EXECUTE)

    os.chmod(found.config, 0o660)   # the mask now lets the group write
    expect_unsafe("config writable by the group")
    acl.grant(str(found.config), uid, acl.READ)

    os.rename(found.decisions, found.decisions.with_suffix(".away"))
    expect_unsafe("decisions file missing")
    os.rename(found.decisions.with_suffix(".away"), found.decisions)

    saved_config = found.config.read_bytes()
    found.config.unlink()
    os.symlink("/etc/hostname", found.config)
    expect_unsafe("config replaced by a symlink")
    found.config.unlink()
    found.config.write_bytes(saved_config)
    os.chmod(found.config, 0o600)
    acl.grant(str(found.config), uid, acl.READ)

    os.chown(found.config, uid, -1)
    expect_unsafe("config owned by the user")
    os.chown(found.config, 0, -1)
    acl.grant(str(found.config), uid, acl.READ)
    assert as_user(protect.status)[0], "back to normal"

    # --unprotect: declined changes nothing, then everything goes.
    assert not quiet(protect.unprotect, uid, lambda p: False)[0]
    assert protect.is_protected(uid)
    assert quiet(protect.unprotect, uid, yes)[0]
    assert not protect.is_protected(uid)
    assert as_user(protect.status) == (True, "None"), "unprotected: the user's own config again"
    assert not quiet(protect.unprotect, uid, yes)[0], "nothing to undo"
    print("--protect / --unprotect test passed ✓")

shutil.rmtree(tmp, ignore_errors=True)
print("All protected-mode tests passed ✓")
