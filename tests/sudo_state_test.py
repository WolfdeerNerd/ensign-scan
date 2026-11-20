"""Runs as root never read or write in a folder another user can change.

The bug: under sudo, Ensign read the invoking user's config and wrote into
the user's data folder. Anything running as that user could then plant a
symlink there (root truncated or overwrote whatever it pointed to), or edit
the config (adding its own folder to `excludes` hides it from the root scan).

Checked here:

  * the run lock refuses a symlink instead of truncating its target;
  * new data folders and databases are created owner-only (700 / 600), and
    an existing folder's permissions are left as they are;
  * as root: trust.untrusted_reason() accepts root-only paths and refuses
    anything another user owns or can write to, including through a symlink
    and above a name that doesn't exist yet in a shared folder like /tmp;
  * as root: a run pointed at a user-owned data folder with a planted lock
    symlink refuses to start, and the symlink's target is untouched;
  * as root: the first run copies the user's config once, owner-only, and
    never follows a symlink while doing it; later runs leave the copy alone;
  * as root: the pre-0.8.1 folder move (the user's folders) is skipped.

The first two parts run as anyone. The rest need root and are skipped
(with a note) otherwise:

    python3 tests/sudo_state_test.py
    sudo python3 tests/sudo_state_test.py
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
import shutil  # noqa: E402
import stat  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402
import tempfile  # noqa: E402
from pathlib import Path  # noqa: E402

from ensign_scan import config as cfg  # noqa: E402
from ensign_scan import migrate, trust  # noqa: E402
from ensign_scan.runlock import RunLock  # noqa: E402

OTHER_UID = 65534   # "nobody": stands in for the user whose account is compromised
tmp = Path(tempfile.mkdtemp(prefix="ensign_sudo_state_"))


def mode(p: Path) -> int:
    return stat.S_IMODE(p.lstat().st_mode)


def run_ensign(config_file: Path, tree: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(ROOT / "main.py"), "--no-scan",
                           "--config", str(config_file), str(tree)],
                          capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL,
                          env={**os.environ, "NO_COLOR": "1", "TERM": "dumb"})


def write_config(path: Path, data_dir: Path) -> None:
    path.write_text(f'data_dir = "{data_dir}"\nclamd_socket = "{tmp / "no-clamd.ctl"}"\n'
                    "signature_max_age_days = 0\n")


try:
    # ------------------------------------------------------------------
    # 1. The run lock never follows a symlink
    # ------------------------------------------------------------------
    victim = tmp / "victim.txt"
    victim.write_text("IMPORTANT\n")
    (tmp / "lockdir").mkdir()
    (tmp / "lockdir" / "ensign.lock").symlink_to(victim)
    try:
        RunLock(tmp / "lockdir" / "ensign.lock").acquire()
        raise AssertionError("a symlinked lock file was opened")
    except OSError:
        pass
    assert victim.read_text() == "IMPORTANT\n", "the lock truncated the symlink's target"
    print("lock symlink test passed ✓")

    # ------------------------------------------------------------------
    # 2. New files are owner-only; existing permissions are left alone
    # ------------------------------------------------------------------
    tree = tmp / "tree"
    tree.mkdir()
    (tree / "a.txt").write_text("hello\n")
    fresh = tmp / "fresh-data"
    write_config(tmp / "fresh.toml", fresh)
    result = run_ensign(tmp / "fresh.toml", tree)
    assert result.returncode == 0, result.stdout + result.stderr
    assert mode(fresh) == 0o700, f"new data folder is {mode(fresh):o}, expected 700"
    for name in ("system.db", "ensign.lock"):
        assert mode(fresh / name) == 0o600, f"new {name} is {mode(fresh / name):o}, expected 600"

    opened = tmp / "opened-data"   # a folder someone opened up on purpose
    opened.mkdir()
    opened.chmod(0o755)
    write_config(tmp / "opened.toml", opened)
    result = run_ensign(tmp / "opened.toml", tree)
    assert result.returncode == 0, result.stdout + result.stderr
    assert mode(opened) == 0o755, "an existing folder's permissions were changed"
    print("owner-only permissions test passed ✓")

    if os.geteuid() != 0:
        print("root-only parts skipped: run under sudo to check them")
        raise SystemExit(0)

    # ------------------------------------------------------------------
    # 3. trust.untrusted_reason()
    # ------------------------------------------------------------------
    safe = tmp / "safe"            # root-owned, 700, inside root's 700 tmp dir
    safe.mkdir(mode=0o700)
    assert trust.untrusted_reason(safe) is None
    assert trust.untrusted_reason(safe / "not-yet" / "deeper") is None, \
        "a missing name inside a root-only folder is fine: only root can create it"

    users = tmp / "users"          # a folder the other user owns
    users.mkdir()
    os.chown(users, OTHER_UID, OTHER_UID)
    assert "owned by uid" in (trust.untrusted_reason(users) or "")
    assert trust.untrusted_reason(users / "system.db"), "a file in another user's folder"

    loose = tmp / "loose"          # root-owned, but anyone may write to it
    loose.mkdir()
    loose.chmod(0o777)
    assert "changed by other users" in (trust.untrusted_reason(loose / "x") or "")

    link = safe / "link-to-users"  # root's symlink to the user's folder: the target is checked
    link.symlink_to(users)
    assert trust.untrusted_reason(link / "system.db"), "followed a symlink into a user's folder"

    planted = safe / "planted"     # a symlink the other user owns, even to somewhere safe
    planted.symlink_to(safe)
    os.lchown(planted, OTHER_UID, OTHER_UID)
    assert "symlink owned by uid" in (trust.untrusted_reason(planted) or "")

    sticky = tmp / "sticky"        # like /tmp: 1777
    sticky.mkdir()
    sticky.chmod(0o1777)
    (sticky / "roots").mkdir(mode=0o700)
    assert trust.untrusted_reason(sticky / "roots") is None, \
        "a root-owned folder inside a sticky one is safe: others can't rename or remove it"
    assert "could create it first" in (trust.untrusted_reason(sticky / "missing") or ""), \
        "a missing name in a sticky folder can be claimed by anyone"
    assert "shared" in (trust.untrusted_reason(sticky) or ""), "a shared folder as the place itself"
    # A path Ensign can't check is refused with a reason, never a traceback.
    # (A traceback still meant no run, but read as a crash, not a refusal.)
    a_file = safe / "a-file"
    a_file.write_text("")
    assert "couldn't check" in (trust.untrusted_reason(a_file / "below-a-file") or ""), \
        "a path through a regular file"
    assert "couldn't check" in (trust.untrusted_reason(safe / ("x" * 300)) or ""), "a name too long"
    print("trust check test passed ✓")

    # ------------------------------------------------------------------
    # 4. The original attack: root refuses the user's data folder
    # ------------------------------------------------------------------
    shadow = safe / "shadow"       # stands in for /etc/shadow
    shadow.write_text("root:secret\n")
    shadow.chmod(0o600)
    attack = tmp / "attacked-data"
    attack.mkdir()
    (attack / "ensign.lock").symlink_to(shadow)
    os.lchown(attack / "ensign.lock", OTHER_UID, OTHER_UID)
    os.chown(attack, OTHER_UID, OTHER_UID)
    write_config(tmp / "attack.toml", attack)
    result = run_ensign(tmp / "attack.toml", tree)
    out = result.stdout + result.stderr
    assert result.returncode == 1, f"a root run used another user's data folder:\n{out}"
    assert "isn't safe to use" in out, out
    assert shadow.read_text() == "root:secret\n", "the planted symlink's target was changed"
    assert sorted(p.name for p in attack.iterdir()) == ["ensign.lock"], \
        "something was written to the refused folder"

    users_cfg = users / "config.toml"   # the user's config, read by root
    write_config(users_cfg, safe / "data")
    os.chown(users_cfg, OTHER_UID, OTHER_UID)
    try:
        cfg.Config.load(users_cfg)
        raise AssertionError("root loaded a config another user can edit")
    except ValueError as exc:
        assert "isn't safe to use" in str(exc), exc
    print("root refuses user-owned config and data test passed ✓")

    # ------------------------------------------------------------------
    # 5. First run as root: the user's config is copied once
    # ------------------------------------------------------------------
    saved = {k: getattr(cfg, k) for k in ("DEFAULT_CONFIG_PATH", "USER_CONFIG_PATH", "LEGACY_CONFIG_PATH")}
    saved_uid = os.environ.get("SUDO_UID")
    try:
        home = tmp / "home"
        (home / ".config" / "ensign-scan").mkdir(parents=True)
        cfg.USER_CONFIG_PATH = home / ".config" / "ensign-scan" / "config.toml"
        cfg.LEGACY_CONFIG_PATH = home / ".config" / "ensign" / "config.toml"
        os.environ["SUDO_UID"] = str(OTHER_UID)

        def first_run(etc: Path) -> str:
            cfg.DEFAULT_CONFIG_PATH = etc / "config.toml"
            with contextlib.redirect_stdout(io.StringIO()) as buf:
                cfg.ensure_default_config()
            return buf.getvalue()

        cfg.USER_CONFIG_PATH.write_text('excludes = ["/home/user/.cache"]\n')
        os.chown(cfg.USER_CONFIG_PATH, OTHER_UID, OTHER_UID)
        etc = safe / "etc1"
        out = first_run(etc)
        root_cfg = etc / "config.toml"
        assert root_cfg.read_text() == cfg.USER_CONFIG_PATH.read_text(), "the user's config wasn't copied"
        assert "copied your config" in out, out
        assert root_cfg.stat().st_uid == 0 and mode(root_cfg) == 0o600, \
            f"root's copy is uid {root_cfg.stat().st_uid}, mode {mode(root_cfg):o}"
        cfg.USER_CONFIG_PATH.write_text('excludes = ["/"]\n')    # malware edits the user's config later
        first_run(etc)
        assert root_cfg.read_text() == 'excludes = ["/home/user/.cache"]\n', \
            "a later run copied the user's config again"

        cfg.USER_CONFIG_PATH.unlink()                             # the user's config is a symlink
        cfg.USER_CONFIG_PATH.symlink_to(shadow)
        os.lchown(cfg.USER_CONFIG_PATH, OTHER_UID, OTHER_UID)
        etc = safe / "etc2"
        first_run(etc)
        text = (etc / "config.toml").read_text()
        assert "root:secret" not in text, "followed a symlink while copying the user's config"
        assert text == cfg.EXAMPLE_CONFIG, "expected the starter template instead"

        cfg.USER_CONFIG_PATH.unlink()                             # a file the sudo user doesn't own
        cfg.USER_CONFIG_PATH.write_text('excludes = ["/"]\n')     # (root's here)
        etc = safe / "etc3"
        first_run(etc)
        assert (etc / "config.toml").read_text() == cfg.EXAMPLE_CONFIG, \
            "copied a config the sudo user doesn't own"
    finally:
        for k, v in saved.items():
            setattr(cfg, k, v)
        if saved_uid is None:
            os.environ.pop("SUDO_UID", None)
        else:
            os.environ["SUDO_UID"] = saved_uid
    print("copy-once config test passed ✓")

    # ------------------------------------------------------------------
    # 6. Root never moves the user's pre-0.8.1 folders
    # ------------------------------------------------------------------
    saved = {k: getattr(cfg, k) for k in ("DEFAULT_CONFIG_PATH", "DEFAULT_DATA_DIR",
                                          "LEGACY_CONFIG_PATH", "LEGACY_DATA_DIR")}
    try:
        old = tmp / "oldhome"   # the user's pre-0.8.1 folders, which would be moved
        (old / ".config" / "ensign").mkdir(parents=True)
        (old / ".local" / "share" / "ensign").mkdir(parents=True)
        (old / ".config" / "ensign" / "config.toml").write_text("max_workers = 0\n")
        (old / ".local" / "share" / "ensign" / "system.db").write_bytes(b"")
        cfg.LEGACY_CONFIG_PATH = old / ".config" / "ensign" / "config.toml"
        cfg.LEGACY_DATA_DIR = old / ".local" / "share" / "ensign"
        cfg.DEFAULT_CONFIG_PATH = old / ".config" / "ensign-scan" / "config.toml"
        cfg.DEFAULT_DATA_DIR = old / ".local" / "share" / "ensign-scan"
        with contextlib.redirect_stdout(io.StringIO()):
            result = migrate.move_legacy_folders(None)
        assert result == ([], []), f"root ran the legacy folder move: {result}"
        assert cfg.LEGACY_CONFIG_PATH.is_file() and cfg.LEGACY_DATA_DIR.is_dir(), \
            "root moved the user's old folders"
    finally:
        for k, v in saved.items():
            setattr(cfg, k, v)
    print("legacy move skipped as root test passed ✓")

    print("All sudo state tests passed ✓")
finally:
    shutil.rmtree(tmp, ignore_errors=True)
