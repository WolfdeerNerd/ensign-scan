"""ensign-scan --uninstall (uninstall.py).

As an ordinary user: everything Ensign made for you goes, after typing
"uninstall"; what isn't only Ensign's stays; your decisions can be saved
first; a run that's going stops it; anything else cancels.

As root (with SUDO_UID set to an ordinary account, as sudo does): root's
folders go too, and your files are deleted as you, never as root. Skipped
when not root.

Never touches your real files: every home and root folder is a temporary
one.

    python3 tests/uninstall_test.py
    sudo python3 tests/uninstall_test.py   # the root part
"""
from __future__ import annotations

import sys as _sys_path
from pathlib import Path as _Path

# Run against THIS checkout, never an installed copy of Ensign.
ROOT = _Path(__file__).resolve().parent.parent
_sys_path.path.insert(0, str(ROOT))

import json  # noqa: E402
import os  # noqa: E402
import pwd  # noqa: E402
import shutil  # noqa: E402
import tempfile  # noqa: E402
from pathlib import Path  # noqa: E402

from sqlalchemy.orm import Session  # noqa: E402

from ensign_scan import protect, uninstall  # noqa: E402
from ensign_scan.db import make_engine  # noqa: E402
from ensign_scan.models import Allowance, utcnow  # noqa: E402
from ensign_scan.runlock import RunLock  # noqa: E402


def make_home(home: Path) -> None:
    """An Ensign install's files, and a few that aren't Ensign's."""
    (home / ".config" / "ensign-scan").mkdir(parents=True)
    (home / ".config" / "ensign-scan" / "config.toml").write_text('data_dir = "~/elsewhere"\n')
    data = home / ".local" / "share" / "ensign-scan"
    data.mkdir(parents=True)
    (data / "logs").mkdir()
    (data / "logs" / "run.log").write_text("log\n")
    engine = make_engine(f"sqlite:///{data / 'system.db'}")
    with Session(engine) as session:
        session.add(Allowance(file_hash="ab" * 32, threat_name="Test.Evil", engine="clamav",
                              filepath="/home/user/game.dll", allowed_at=utcnow()))
        session.commit()
    engine.dispose()
    elsewhere = home / "elsewhere"   # a data_dir that holds your own things too
    elsewhere.mkdir()
    (elsewhere / "error_logs.txt").write_text("Ensign's\n")
    (elsewhere / "mine.txt").write_text("not Ensign's\n")
    legacy = home / ".config" / "ensign"   # the old name, but another program's here
    legacy.mkdir()
    (legacy / "notes.txt").write_text("another program\n")
    units = home / ".config" / "systemd" / "user"
    units.mkdir(parents=True)
    (units / "scan.service").write_text("[Service]\nExecStart=/usr/bin/ensign-scan\n")


def run(answer: str, export: bool):
    lines: list[str] = []
    code = uninstall.run(confirm_word=lambda prompt: answer, ask_yes_no=lambda prompt: export,
                         out=lambda text="": lines.append(str(text)))
    return code, "\n".join(lines)


# --- as you (as root, root's folders would be planned too) ------------------------------------
if os.geteuid() != 0:
    real_home = os.environ.get("HOME")
    with tempfile.TemporaryDirectory() as d:
        home = Path(d)
        os.environ["HOME"] = str(home)
        try:
            make_home(home)
            data = home / ".local" / "share" / "ensign-scan"

            # Without a terminal, and with the default prompt: refused.
            lines: list[str] = []
            if not _sys_path.stdin.isatty():
                assert uninstall.run(out=lines.append) == 1 and "no terminal" in lines[0], lines

            # Anything but the word: nothing changes.
            code, text = run("yes", export=False)
            assert code == 0 and "Nothing was changed" in text, text
            assert data.exists()
            assert "scan.service" in text, "a unit that runs Ensign is pointed out"
            assert "notes.txt" not in text and "left alone" in text, text

            # A run that's going: refused before asking.
            lock = RunLock(data / "ensign.lock")
            lock.acquire()
            try:
                code, text = run(uninstall.CONFIRM_WORD, export=False)
            finally:
                lock.release()
            assert code == 1 and "run is going" in text and data.exists(), text

            code, text = run(uninstall.CONFIRM_WORD, export=True)
            assert code == 0, text
            assert not (home / ".config" / "ensign-scan").exists() and not data.exists()
            assert not (home / "elsewhere" / "error_logs.txt").exists()
            assert (home / "elsewhere" / "mine.txt").exists(), "only Ensign's files in a shared folder"
            assert (home / ".config" / "ensign" / "notes.txt").exists(), "another program's folder stays"
            assert (home / ".config" / "systemd" / "user" / "scan.service").exists(), "yours to remove"
            saved = list(home.glob("ensign-scan-decisions-*.json"))
            assert len(saved) == 1, saved
            assert oct(saved[0].stat().st_mode & 0o777) == "0o600"
            body = json.loads(saved[0].read_text())
            rows = next(iter(body["databases"].values()))["allowances"]
            assert rows[0]["threat_name"] == "Test.Evil" and rows[0]["engine"] == "clamav", rows
            assert "To remove the program itself" in text and "ClamAV is left installed" in text, text
            print("uninstall as you test passed ✓")
        finally:
            if real_home is not None:
                os.environ["HOME"] = real_home

# --- with sudo -----------------------------------------------------------------------------------
if os.geteuid() != 0:
    print("\nAll uninstall tests passed ✓ (the root part is skipped: run with sudo for it)")
    _sys_path.exit(0)

ordinary = next((p for p in pwd.getpwall() if p.pw_uid >= 1000 and p.pw_uid < 60000), None)
if ordinary is None:
    print("\nAll uninstall tests passed ✓ (the root part is skipped: no ordinary account)")
    _sys_path.exit(0)

with tempfile.TemporaryDirectory() as d:
    base = Path(d)
    os.chmod(base, 0o755)
    home = base / "home"
    home.mkdir()
    make_home(home)
    for root, dirs, files in os.walk(home):
        for name in dirs + files + [""]:
            os.lchown(os.path.join(root, name), ordinary.pw_uid, ordinary.pw_gid)
    # A file in your folder that only root could delete: deleted as you, it
    # can't be, which shows the deleting really is done as you.
    trap = home / ".local" / "share" / "ensign-scan" / "logs"
    os.chown(trap, 0, 0)
    os.chmod(trap, 0o755)

    config_root, data_root = base / "etc-ensign-scan", base / "var-lib-ensign-scan"
    config_root.mkdir()
    (config_root / "config.toml").write_text("")
    data_root.mkdir()
    (data_root / "users" / str(ordinary.pw_uid)).mkdir(parents=True)
    real_roots = (protect.CONFIG_ROOT, protect.DATA_ROOT)
    protect.CONFIG_ROOT, protect.DATA_ROOT = config_root, data_root
    real_getpwuid = uninstall.pwd.getpwuid

    def fake_getpwuid(uid):
        found = real_getpwuid(uid)
        if uid != ordinary.pw_uid:
            return found
        return pwd.struct_passwd((found.pw_name, found.pw_passwd, found.pw_uid, found.pw_gid,
                                  found.pw_gecos, str(home), found.pw_shell))
    uninstall.pwd.getpwuid = fake_getpwuid
    os.environ["SUDO_UID"] = str(ordinary.pw_uid)
    try:
        code, text = run(uninstall.CONFIRM_WORD, export=False)
    finally:
        del os.environ["SUDO_UID"]
        uninstall.pwd.getpwuid = real_getpwuid
        protect.CONFIG_ROOT, protect.DATA_ROOT = real_roots
    assert not config_root.exists() and not data_root.exists(), text
    assert not (home / ".config" / "ensign-scan").exists(), text
    assert (home / ".local" / "share" / "ensign-scan" / "logs").exists(), \
        "a file only root can delete was deleted: your files must be deleted as you"
    assert code == 1 and "couldn't be deleted" in text, text
    assert (home / "elsewhere" / "mine.txt").exists()
    shutil.rmtree(home, ignore_errors=True)
    print("uninstall with sudo test passed ✓")

print("\nAll uninstall tests passed ✓")
