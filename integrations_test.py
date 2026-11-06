"""Tests for the pacman integrity parser and notification message logic.

Both are pure functions with no clamd/DB dependency, so these run fast
and standalone. Run: python3 integrations_test.py
"""
from ensign_scan.pacman import PacmanMismatch, PacmanVerifyResult, _MISMATCH_RE
from ensign_scan.reports import pacman_report
from ensign_scan.notify import build_message
from ensign_scan import explanations, secrets
from ensign_scan.secrets import Confidence
from ensign_scan.clamd import is_permission_error, is_size_limit_error

# --- secrets.py: tiered confidence matching --------------------------

# HIGH confidence: exact/canonical names, matched regardless of caller.
assert secrets.classify("/home/user/.local/share/kwalletd/kdewallet.kwl") == Confidence.HIGH
assert secrets.classify("/home/user/.bitcoin/wallet.dat") == Confidence.HIGH, \
    "should match on canonical directory name"
assert secrets.classify("/home/user/.netrc") == Confidence.HIGH, \
    "canonical dotfile in $HOME should match on filename alone"
assert secrets.classify("/home/user/.ssh/id_rsa") == Confidence.HIGH
assert secrets.classify("/home/user/.aws/credentials") == Confidence.HIGH, \
    "scoped filename (credentials) inside its expected parent dir (.aws)"

# Scoped filenames must NOT match outside their expected parent -- this
# is the whole point of scoping them instead of matching bare "credentials"
# or "config" anywhere.
assert secrets.classify("/home/user/Documents/credentials") == Confidence.NONE, \
    "'credentials' outside .aws/ must not match -- that's the false-positive risk being avoided"
assert secrets.classify("/home/user/projects/myapp/config") == Confidence.NONE, \
    "'config' outside .ssh//.kube//.docker/ must not match"

# MEDIUM confidence: conventions that need directory context.
# Anything financial or crypto is HIGH (decided Oct 7): the .ethereum/keystore
# directory is HIGH, and the UTC-- prefix rule is HIGH too, so a keystore
# kept anywhere else (e.g. a custom geth --datadir) is also caught.
assert secrets.classify("/data/chain/keystore/UTC--2024-01-01T00-00-00.000Z--abc123") == Confidence.HIGH
assert secrets.classify("/home/user/.ethereum/keystore/UTC--2024-01-01T00-00-00.000Z--abc123") == Confidence.HIGH
assert secrets.classify("/home/user/random/UTC--fake") == Confidence.NONE, \
    "UTC-- prefix outside a keystore/ dir must not match -- context is required"
assert secrets.classify("/home/user/notes/mykey.pem") == Confidence.MEDIUM

# NONE: the old substring-bleed false positives must be gone.
assert secrets.classify("/home/user/Documents/notes.txt") == Confidence.NONE
assert secrets.classify("/home/user/projects/no-secrets-here/readme.md") == Confidence.NONE, \
    "generic word 'secrets' embedded in an unrelated name must not match"
assert secrets.classify("/home/user/projects/android-keystore-docs/notes.md") == Confidence.NONE, \
    "generic word 'keystore' embedded in an unrelated name must not match"
assert secrets.classify("/home/user/MyWalletApp/screenshots/img.png") == Confidence.NONE, \
    "generic word 'wallet' embedded in an unrelated name must not match"

# The two call-site thresholds behave differently, as designed.
assert secrets.is_likely_secrets_path("/home/user/notes/mykey.pem"), \
    "suggest_fixes() uses the wider threshold (HIGH or MEDIUM)"
assert not secrets.is_high_confidence_secrets_path("/home/user/notes/mykey.pem"), \
    "scanner.py's reclassification uses the narrower threshold (HIGH only)"
assert secrets.is_high_confidence_secrets_path("/home/user/.ssh/id_rsa")

assert secrets.matching_reason("/home/user/Documents/notes.txt") is None
assert secrets.matching_reason("/home/user/.ssh/id_rsa") is not None

# --- clamd.py: permission vs size-limit error detection ---------------

assert is_permission_error("/x: Access denied. ERROR")
assert is_permission_error("/x: File path check failure: Permission denied. ERROR")
assert not is_permission_error("/x: size limit exceeded. ERROR")
assert not is_size_limit_error("/x: Access denied. ERROR")
assert is_size_limit_error("/x: size limit exceeded. ERROR")

# --- pacman.py: line-format parsing ---------------------------------
# Real -Qkk wording wasn't verified against a live pacman install (no
# Arch system available while building this) -- these check the regex
# handles the plausible shapes, and that a total non-match is visible
# as "0 parsed" rather than silently looking like a clean system.

cases = [
    ("coreutils: /usr/bin/ls (Size mismatch)",
     (None, "coreutils", "/usr/bin/ls", "Size mismatch")),
    ("openssh: /etc/ssh/sshd_config (Modification time mismatch)",
     (None, "openssh", "/etc/ssh/sshd_config", "Modification time mismatch")),
    ("warning: linux: /boot/vmlinuz-linux (UID mismatch)",
     ("warning", "linux", "/boot/vmlinuz-linux", "UID mismatch")),
    ("backup file: filesystem: /etc/fstab (SHA256 checksum mismatch)",
     ("backup file", "filesystem", "/etc/fstab", "SHA256 checksum mismatch")),
]
for line, expected in cases:
    m = _MISMATCH_RE.match(line)
    assert m is not None, f"should match: {line!r}"
    assert m.groups() == expected, f"{line!r} -> {m.groups()} != {expected}"

assert _MISMATCH_RE.match("not a mismatch line") is None
assert _MISMATCH_RE.match("") is None
assert _MISMATCH_RE.match("coreutils: 444 total files, 0 altered files") is None, \
    "per-package summary lines must never be mistaken for a mismatch"

# --- pacman_report(): the four branches -------------------------------
import tempfile
from pathlib import Path
from ensign_scan.config import Config
from ensign_scan.scanner import Scanner

tmp = Path(tempfile.mkdtemp())
cfg = Config(db_url=f"sqlite:///{tmp / 't.db'}", log_file=tmp / "e.log", clamd_socket="/nonexistent")
s = Scanner(cfg)

import io, contextlib

def captured(*args):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        pacman_report(*args)
    return buf.getvalue()

assert "not installed" in captured(s.engine, None)
# The bug that caused real confusion: a subprocess failure (timeout,
# permission issue) must NOT print the same "not installed" message as
# pacman genuinely being absent -- these are different problems with
# different fixes, and collapsing them into one message is misleading.
out = captured(s.engine, PacmanVerifyResult(mismatches=[], candidate_line_count=0, error="pacman -Qkk did not finish within 600s."))
assert "not installed" not in out, "a ran-but-failed result must not look like 'not installed'"
assert "verification failed" in out and "600s" in out
assert "No mismatches" in captured(s.engine, PacmanVerifyResult(mismatches=[], candidate_line_count=0))
out = captured(s.engine, PacmanVerifyResult(
    mismatches=[PacmanMismatch("coreutils", "/usr/bin/ls", "Size mismatch")], candidate_line_count=1,
))
assert "/usr/bin/ls" in out and "not tracked by Ensign" in out
out = captured(s.engine, PacmanVerifyResult(mismatches=[], candidate_line_count=5))
assert "may need updating" in out, "0-parsed-but-nonzero-lines should surface a parser warning, not look clean"

# --- notify.py: message building --------------------------------------

empty_summary = {"total": 0, "clean": 0, "infected": 0, "error": 0, "pending": 0}
title, body, urgency = build_message(empty_summary, [])
assert urgency == "normal"
assert "Infected: 0" in body

infected_summary = {"total": 2, "clean": 0, "infected": 1, "error": 1, "pending": 0}
infected_list = [{"filepath": "/home/user/nasty.exe", "threat": "Test.Virus", "scanned": None}]
title, body, urgency = build_message(infected_summary, infected_list)
assert urgency == "critical", "any infection should escalate urgency"
assert "nasty.exe" in body
assert "1 infected" in title

error_only_summary = {"total": 5, "clean": 4, "infected": 0, "error": 1, "pending": 0}
title, body, urgency = build_message(error_only_summary, [])
assert urgency == "normal", "errors alone should not escalate to critical"
assert "1 error" in title

# many infections -> body should truncate the name list, not dump them all
many_infected = [{"filepath": f"/tmp/bad{i}.exe", "threat": "X", "scanned": None} for i in range(10)]
_, body, _ = build_message({"total": 10, "clean": 0, "infected": 10, "error": 0, "pending": 0}, many_infected)
assert "+7 more" in body, body

# --- notify.py: send() and the auto-close timer ----------------------
import os as _os, stat as _stat, tempfile as _tf, time as _time
from ensign_scan import notify as _notify

_bin = Path(_tf.mkdtemp(prefix="ensign_notify_"))
_ns_log, _gd_log = _bin / "notify-send.log", _bin / "gdbus.log"
(_bin / "notify-send").write_text(
    f'#!/bin/sh\necho "$@" >> {_ns_log}\ncase " $* " in *" -p "*) echo 42;; esac\n')
(_bin / "gdbus").write_text(f'#!/bin/sh\necho "$@" >> {_gd_log}\n')
for _name in ("notify-send", "gdbus"):
    (_bin / _name).chmod((_bin / _name).stat().st_mode | _stat.S_IEXEC)
_old_path = _os.environ["PATH"]
_os.environ["PATH"] = f"{_bin}:{_old_path}"


def _wait_for(path, seconds=5.0):
    end = _time.time() + seconds
    while _time.time() < end:
        if path.exists() and path.read_text().strip():
            return path.read_text()
        _time.sleep(0.05)
    return ""


try:
    # critical + timeout: asks for the id, then a detached helper closes it
    assert _notify.send(infected_summary, infected_list, infected_timeout_s=1)
    assert " -p " in " " + _ns_log.read_text() + " ", "must request the notification id"
    _closed = _wait_for(_gd_log)
    assert "CloseNotification" in _closed and "uint32 42" in _closed, _closed
    assert "org.freedesktop.Notifications" in _closed

    # timeout 0 = old behavior: no id requested, nothing scheduled
    _ns_log.unlink(); _gd_log.unlink()
    assert _notify.send(infected_summary, infected_list, infected_timeout_s=0)
    assert " -p" not in _ns_log.read_text()
    _time.sleep(1.5)
    assert not _gd_log.exists(), "no timer when the timeout is 0"

    # non-critical alerts are never auto-closed, whatever the timeout
    _ns_log.unlink()
    assert _notify.send(empty_summary, [], infected_timeout_s=1)
    assert " -p" not in _ns_log.read_text()
    _time.sleep(1.5)
    assert not _gd_log.exists(), "normal alerts must not get a close timer"

    # notify-send that doesn't print an id (older libnotify): no crash, no timer
    (_bin / "notify-send").write_text(f'#!/bin/sh\necho "$@" >> {_ns_log}\n')
    assert _notify.send(infected_summary, infected_list, infected_timeout_s=1)
    _time.sleep(1.5)
    assert not _gd_log.exists(), "unreadable id: leave the notification alone"

    # only_when_gaming: timer applies only while a Steam game is running
    (_bin / "notify-send").write_text(
        f'#!/bin/sh\necho "$@" >> {_ns_log}\ncase " $* " in *" -p "*) echo 42;; esac\n')
    _real_steam = _notify.game_running
    try:
        _notify.game_running = lambda: False
        _ns_log.unlink(missing_ok=True); _gd_log.unlink(missing_ok=True)
        assert _notify.send(infected_summary, infected_list, infected_timeout_s=1, only_when_gaming=True)
        assert " -p" not in _ns_log.read_text(), "no game: no id requested, stays until dismissed"
        _time.sleep(1.5)
        assert not _gd_log.exists(), "no game: nothing scheduled"

        _notify.game_running = lambda: True
        _ns_log.unlink(); _gd_log.unlink(missing_ok=True)
        assert _notify.send(infected_summary, infected_list, infected_timeout_s=1, only_when_gaming=True)
        assert "CloseNotification" in _wait_for(_gd_log), "game running: timer applies"

        _notify.game_running = lambda: False          # flag off: timer regardless of a game
        _ns_log.unlink(); _gd_log.unlink()
        assert _notify.send(infected_summary, infected_list, infected_timeout_s=1, only_when_gaming=False)
        assert "CloseNotification" in _wait_for(_gd_log), "flag off: always timed"

        # service/cron run (no terminal): always timed, even with no game and only_when_gaming
        _notify.game_running = lambda: False
        _ns_log.unlink(); _gd_log.unlink()
        assert _notify.send(infected_summary, infected_list, infected_timeout_s=1,
                            only_when_gaming=True, interactive=False)
        assert "CloseNotification" in _wait_for(_gd_log), "non-interactive: always timed"

        # --- replace instead of stack -----------------------------------
        import json as _json
        _st = _bin / "alert_state.json"

        def _fresh():
            for _p in (_ns_log, _gd_log, _st):
                _p.unlink(missing_ok=True)

        # first alert: asks for the id, nothing to replace, saves state
        _fresh()
        assert _notify.send(infected_summary, infected_list, infected_timeout_s=0, state_path=_st)
        _first = _ns_log.read_text()
        assert " -p " in " " + _first + " " and "-r" not in _first.split(), _first
        _saved = _json.loads(_st.read_text())
        assert _saved["id"] == 42 and _saved["boot_id"] == _notify._boot_id()

        # second alert, same boot: replaces id 42
        _ns_log.unlink()
        assert _notify.send(infected_summary, infected_list, infected_timeout_s=0, state_path=_st)
        assert "-r 42" in _ns_log.read_text(), _ns_log.read_text()

        # id saved during another boot is not trusted
        _st.write_text(_json.dumps({"id": 42, "boot_id": "some-other-boot", "close_pid": None}))
        _ns_log.unlink()
        assert _notify.send(infected_summary, infected_list, infected_timeout_s=0, state_path=_st)
        assert "-r" not in _ns_log.read_text().split(), "stale boot: do not replace"

        # a normal (non-critical) alert neither replaces nor records anything
        _fresh()
        assert _notify.send(empty_summary, [], infected_timeout_s=1, state_path=_st)
        assert not _st.exists() and " -p" not in _ns_log.read_text()

        # replacing cancels the old alert's pending close timer, so it can't
        # close the new alert early (same id)
        _fresh()
        assert _notify.send(infected_summary, infected_list, infected_timeout_s=2, state_path=_st)
        _old_pid = _json.loads(_st.read_text())["close_pid"]
        assert isinstance(_old_pid, int)
        assert _notify.send(infected_summary, infected_list, infected_timeout_s=0, state_path=_st)
        assert _json.loads(_st.read_text())["close_pid"] is None
        _time.sleep(3)
        assert not _gd_log.exists(), "old timer was cancelled; the new sticky alert stays"

        # older libnotify without -r: retried without it, alert still shown
        _fresh()
        _st.write_text(_json.dumps({"id": 42, "boot_id": _notify._boot_id(), "close_pid": None}))
        (_bin / "notify-send").write_text(
            f'#!/bin/sh\ncase " $* " in *" -r "*) exit 2;; esac\n'
            f'echo "$@" >> {_ns_log}\ncase " $* " in *" -p "*) echo 43;; esac\n')
        assert _notify.send(infected_summary, infected_list, infected_timeout_s=0, state_path=_st)
        assert "-r" not in _ns_log.read_text().split()
        assert _json.loads(_st.read_text())["id"] == 43
    finally:
        _notify.game_running = _real_steam

    # game_running() itself: matches Steam's per-game `reaper SteamLaunch` helper only
    (_bin / "pgrep").write_text('#!/bin/sh\n[ "$*" = "-f reaper SteamLaunch AppId=" ] && exit 0\nexit 1\n')
    (_bin / "pgrep").chmod((_bin / "pgrep").stat().st_mode | _stat.S_IEXEC)
    assert _notify.game_running() is True
    (_bin / "pgrep").write_text('#!/bin/sh\nexit 1\n')
    assert _notify.game_running() is False
    _os.environ["PATH"] = str(_bin)  # no pgrep on PATH at all
    (_bin / "pgrep").unlink()
    assert _notify.game_running() is False, "pgrep missing: assume not running"
finally:
    _os.environ["PATH"] = _old_path
print("notify.send auto-close test passed ✓")

print("All pacman/notify/secrets tests passed ✓")

# --- real-world data regression test ---------------------------------
# [unchanged -- see previous version]
_REAL_DUMP = """\
aide: /etc/aide.conf
7zip: 17 total files, 0 altered files
aide: 22 total files, 1 altered file
backup file: filesystem: /etc/fstab (Modification time mismatch)
backup file: filesystem: /etc/fstab (Size mismatch)
backup file: filesystem: /etc/fstab (SHA256 checksum mismatch)
backup file: filesystem: /etc/group (Modification time mismatch)
backup file: filesystem: /etc/passwd (SHA256 checksum mismatch)
backup file: glibc: /etc/locale.gen (Modification time mismatch)
backup file: grub: /etc/default/grub (Modification time mismatch)
backup file: pacman: /etc/pacman.conf (SHA256 checksum mismatch)
backup file: ufw: /etc/ufw/user6.rules (SHA256 checksum mismatch)
warning: filesystem: /etc/crypttab (failed to calculate SHA256 checksum)
warning: filesystem: /root (Permissions mismatch)
warning: intel-ucode: /boot/intel-ucode.img (Permissions mismatch)
warning: java-runtime-common: /usr/lib/jvm/default (Symlink path mismatch)
warning: libutempter: /usr/lib/utempter/utempter (GID mismatch)
warning: modemmanager: /usr/share/ModemManager/connection.available.d/99-log-event (failed to calculate SHA256 checksum)
warning: rkhunter: /etc/rkhunter.conf (failed to calculate SHA256 checksum)
warning: systemd: /var/log/journal (GID mismatch)
filesystem: 127 total files, 7 altered files
rkhunter: 58 total files, 39 altered files
"""

_mismatches = []
_candidates = 0
for _line in _REAL_DUMP.splitlines():
    _line = _line.strip()
    if not _line or "(" not in _line:
        continue
    _candidates += 1
    _m = _MISMATCH_RE.match(_line)
    assert _m, f"real-world line failed to parse: {_line!r}"
    _mismatches.append(PacmanMismatch(_m.group("pkg"), _m.group("path"), _m.group("reason"),
                                       is_backup=(_m.group("kind") == "backup file")))

assert _candidates == len(_mismatches) == 17, \
    "every parenthetical line in real pacman output should parse -- zero silent drops"
_backups = [m for m in _mismatches if m.is_backup]
_warnings = [m for m in _mismatches if not m.is_backup]
assert len(_backups) == 9, len(_backups)
assert len(_warnings) == 8, len(_warnings)

_result = PacmanVerifyResult(mismatches=_mismatches, candidate_line_count=_candidates)
_out = captured(s.engine, _result)
assert "backup/config file" in _out and "not a concern" in _out
assert "differ from pacman's records" in _out
assert _out.index("differ from pacman's records") < _out.index("backup/config file"), \
    "real anomalies should print before the expected/benign backup-file section"

print("Real-world pacman dump regression test passed ✓")

# --- report scoping: the "targeted scan showed unrelated errors" bug -----
from ensign_scan.models import FileRecord as _FR2, ScanStatus as _SS2, utcnow as _utcnow
from ensign_scan.reports import scan_summary, error_summary, list_infected
from sqlalchemy.orm import Session

_tmp2 = Path(tempfile.mkdtemp())
_cfg2 = Config(db_url=f"sqlite:///{_tmp2 / 't.db'}", log_file=_tmp2 / "e.log", clamd_socket="/nonexistent")
_s2 = Scanner(_cfg2)

with Session(_s2.engine) as session:
    session.add(_FR2(filepath="/home/user/Downloads/bad.txt", filename="bad.txt", file_hash="x",
                      scan_status=_SS2.ERROR.value, scan_result="/home/user/Downloads/bad.txt: Access denied. ERROR",
                      last_scanned=_utcnow()))
    session.add(_FR2(filepath="/home/user/Steam/other.txt", filename="other.txt", file_hash="x",
                      scan_status=_SS2.ERROR.value, scan_result="/home/user/Steam/other.txt: Access denied. ERROR",
                      last_scanned=_utcnow()))
    session.add(_FR2(filepath="/home/user/Steam/nasty.exe", filename="nasty.exe", file_hash="x",
                      scan_status=_SS2.INFECTED.value, threat_name="Test.Virus", scan_result="FOUND",
                      last_scanned=_utcnow()))
    session.commit()

def _cap(fn, *a, **kw):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn(*a, **kw)
    return buf.getvalue()

_scoped_err = _cap(error_summary, _s2.engine, paths=["/home/user/Downloads"])
_scoped_inf = _cap(list_infected, _s2.engine, paths=["/home/user/Downloads"])
_scoped_sum = _cap(scan_summary, _s2.engine, paths=["/home/user/Downloads"])

assert "Steam" not in _scoped_err, "a scoped report must not leak errors from outside its scope"
assert "No infected files found" in _scoped_inf, "a scoped report must not leak infections from outside its scope"
assert "Total files:     1" in _scoped_sum

_full_err = _cap(error_summary, _s2.engine)
assert "Steam" in _full_err, "an unscoped report must still show everything (no regression)"

print("Report scoping regression test passed ✓")

# --- explanations.py: built-ins + additive custom loading --------------

assert explanations.explain_threat(None) is None
assert explanations.explain_threat("NotARealThreatName") is None
assert explanations.explain_pacman_reason("Not a real reason") is None

_builtin = explanations.explain_threat("SVGDynamicFunction")
assert _builtin is not None and "heuristic" in _builtin.description.lower()
assert _builtin.false_positive_note is not None

assert "File size differs" in explanations.explain_pacman_reason("Size mismatch")

_cfg_custom = Config(
    custom_threats={
        "Win.Trojan.FakeTestOnly": {"description": "A made-up entry for testing."},
        "SVGDynamicFunction": {"description": "attempted override, must be ignored"},
        "Bad.Entry": {},  # missing description -- must be skipped, not crash
        "Also.Bad": "not even a table",
    },
    custom_pacman_reasons={
        "Some new mismatch type": "A made-up pacman reason for testing.",
        "Size mismatch": "attempted override, must be ignored",
        "": "empty key, must be skipped",
    },
)
_buf_exp = io.StringIO()
with contextlib.redirect_stdout(_buf_exp):
    explanations.load_custom(_cfg_custom)
_exp_warnings = _buf_exp.getvalue()
assert "already built in" in _exp_warnings  # the two override attempts
assert _exp_warnings.count("already built in") == 2
assert "missing 'description'" in _exp_warnings
assert "must be a table" in _exp_warnings

assert explanations.explain_threat("Win.Trojan.FakeTestOnly").description == \
    "A made-up entry for testing."
assert explanations.explain_threat("SVGDynamicFunction") is _builtin, \
    "built-in entry must survive an attempted override unchanged"
assert explanations.explain_pacman_reason("Some new mismatch type") == \
    "A made-up pacman reason for testing."
assert explanations.explain_pacman_reason("Size mismatch") == "File size differs from what pacman recorded at install time.", \
    "built-in reason must survive an attempted override unchanged"

print("explanations.py custom-loading test passed ✓")

# --- secrets.py: load_custom() additive extension -----------------------

assert secrets.classify("/home/user/myvaultdir/anything.txt") == Confidence.NONE, \
    "sanity check: not flagged before the custom entry is loaded"

_cfg_secrets = Config(
    custom_secrets={
        "high_dirs": ["MyVaultDir"],  # mixed case, classify() must still match
        "high_filenames": ["my_custom_key"],
        "high_scoped_filenames": [["myapp", "config"]],
        "high_prefixes": [["mywallet_", "wallets"]],
        "medium_prefixes": [["myprefix_", "somedir"]],
        "medium_extensions": [[".mysecret", ""]],
        "bogus_key": ["ignored"],
    }
)
_buf_sec = io.StringIO()
with contextlib.redirect_stdout(_buf_sec):
    secrets.load_custom(_cfg_secrets)
assert "unknown custom_secrets key 'bogus_key'" in _buf_sec.getvalue()

assert secrets.classify("/home/user/myvaultdir/anything.txt") == Confidence.HIGH, \
    "custom high_dirs entry should now match, case-insensitively"
assert secrets.classify("/home/user/notes/my_custom_key") == Confidence.HIGH
assert secrets.classify("/home/user/myapp/config") == Confidence.HIGH
assert secrets.classify("/home/user/wallets/mywallet_main") == Confidence.HIGH, \
    "custom high_prefixes entry should match inside its required parent"
assert secrets.classify("/home/user/elsewhere/mywallet_main") == Confidence.NONE, \
    "custom high_prefixes entry must not match outside its required parent"
assert secrets.classify("/home/user/somedir/myprefix_thing") == Confidence.MEDIUM
assert secrets.classify("/home/user/anywhere/file.mysecret") == Confidence.MEDIUM

# Re-loading the same config must not duplicate entries.
_before = len(secrets._HIGH_DIRS)
secrets.load_custom(_cfg_secrets)
assert len(secrets._HIGH_DIRS) == _before, "re-loading the same custom_secrets must not duplicate entries"

print("secrets.py load_custom() test passed ✓")

# Malformed entries: the warning says WHERE the entry is, never what's in it.
# These patterns describe where secrets live, and warnings can end up in the
# systemd journal, so the pattern text itself must never be printed.
_cfg_bad = Config(custom_secrets={
    "high_prefixes": [["okprefix_", "okparent"], ["LEAKMARK_onlyone"]],   # #2: not a pair
    "medium_prefixes": [["", "LEAKMARK_parent"]],                          # #1: empty first element
    "high_scoped_filenames": [["LEAKMARK_name", 42]],                       # #1: second not a string
})
_buf_bad = io.StringIO()
with contextlib.redirect_stdout(_buf_bad):
    secrets.load_custom(_cfg_bad)
_bad_out = _buf_bad.getvalue()
assert "LEAKMARK" not in _bad_out, f"a custom_secrets pattern was printed: {_bad_out}"
assert "custom_secrets.high_prefixes entry #2 is malformed (expected a two-element list)" in _bad_out, _bad_out
assert "custom_secrets.medium_prefixes entry #1 is malformed (first element must be a non-empty string)" in _bad_out, _bad_out
assert "custom_secrets.high_scoped_filenames entry #1 is malformed (second element must be a string)" in _bad_out, _bad_out
assert _bad_out.count("is malformed") == 3, "the valid entry must not warn"
assert secrets.classify("/home/user/okparent/okprefix_x") == Confidence.HIGH, "valid entries next to bad ones still load"
print("secrets.py malformed-entry warnings test passed ✓")


# --- logsetup.py: per-run files, repeat collapsing, pruning ------------
import logging as _logging
import time as _t2
from datetime import datetime as _dt
from pathlib import Path as _P
from ensign_scan import logsetup as _ls

_lroot = _P(_tf.mkdtemp(prefix="ensign_logs_"))
_lcfg = Config(db_url=f"sqlite:///{_lroot / 't.db'}", log_file=_lroot / "error_logs.txt",
               clamd_socket="/nonexistent", log_keep_days=90, log_max_total_mb=1024)
assert _lcfg.log_dir == _lroot / "logs"
_blog = _logging.getLogger("ensign.testlogger")

# a run with no errors leaves no file behind
_p0 = _ls.setup(_lcfg, now=_dt(2026, 1, 1, 3, 0, 0))
_ls.shutdown()
assert _p0.name == "ensign-20260101-030000.log" and not _p0.exists(), "file is created lazily"

# repeats: first REPEAT_LIMIT of each distinct error in full, the rest counted
_p1 = _ls.setup(_lcfg, now=_dt(2026, 1, 2, 3, 0, 0))
for _n in range(50):
    _blog.error("stat failed for %s: %s", f"/x/{_n}", PermissionError(13, "Permission denied"))
for _n in range(5):
    _blog.error("stat failed for %s: %s", f"/y/{_n}", OSError(5, "I/O error"))   # other errno: its own count
for _n in range(3):
    _blog.error("one-off %s", _n)                                                  # distinct template each... same one
_ls.shutdown()
_text = _p1.read_text()
assert _text.count("stat failed for /x/") == _ls.REPEAT_LIMIT, _text.count("stat failed for /x/")
assert "/x/19" in _text and "/x/20" not in _text
assert _text.count("stat failed for /y/") == 5, "a different errno is a different error, not suppressed"
assert _text.count("one-off") == 3
assert f"suppressed {50 - _ls.REPEAT_LIMIT} more of: stat failed for %s: %s [PermissionError:13]" in _text, _text
assert "suppressed" in _text and _text.count("suppressed") == 1, "only the over-limit error gets a summary"
assert _logging.getLogger().handlers == [] or _p1 not in [getattr(h, "baseFilename", None) for h in _logging.getLogger().handlers]

# a second run gets its own file
_p2 = _ls.setup(_lcfg, now=_dt(2026, 1, 3, 3, 0, 0))
_blog.error("second run")
_ls.shutdown()
assert _p2 != _p1 and _p2.read_text().count("second run") == 1 and "second run" not in _p1.read_text()

# pruning by age: old runs go, newer stay, unrelated files are never touched
_pd = _lroot / "prune"; _pd.mkdir()
_now = _t2.time()
def _mk(name, age_days, size=10):
    f = _pd / name; f.write_bytes(b"x" * size)
    _os.utime(f, (_now - age_days * 86400,) * 2)
    return f
_old, _new, _other = _mk("ensign-old.log", 120), _mk("ensign-new.log", 10), _mk("notes.txt", 400)
assert _ls.prune(_pd, keep_days=90, max_total_mb=0, now=_now) == [_old]
assert _new.exists() and _other.exists() and not _old.exists()

# pruning by size: oldest first, never the protected (current) file, size limit wins over age
_a, _b, _c = _mk("ensign-a.log", 30, 1024 * 1024), _mk("ensign-b.log", 20, 1024 * 1024), _mk("ensign-c.log", 10, 1024 * 1024)
_new.unlink()
_gone = _ls.prune(_pd, keep_days=90, max_total_mb=2, now=_now)
assert _gone == [_a] and _b.exists() and _c.exists(), _gone
_gone = _ls.prune(_pd, keep_days=0, max_total_mb=1, protect=_b, now=_now)
assert _gone == [_c] and _b.exists(), "protected file survives even when over the limit"
assert _ls.prune(_pd, keep_days=0, max_total_mb=0, now=_now) == [], "0 and 0 disables both rules"
print("logsetup test passed ✓")

# --- runlock: one database-writing Ensign at a time -------------------
import fcntl as _fcntl
import subprocess as _sp
import sys as _sys
import tempfile as _tf
from pathlib import Path as _P
from ensign_scan.runlock import AlreadyRunning, RunLock

_rl_dir = _P(_tf.mkdtemp())
_lock_path = _rl_dir / "sub" / "ensign.lock"   # parent doesn't exist yet: acquire() creates it

_first = RunLock(_lock_path)
_first.acquire()
assert int(_lock_path.read_text().split()[0]) == _os.getpid(), "holder writes its pid into the file"

_second = RunLock(_lock_path)
try:
    _second.acquire()
    raise AssertionError("second acquire should have been refused")
except AlreadyRunning as _e:
    assert _e.holder_pid == _os.getpid() and _e.path == _lock_path
assert _second._fd is None, "a refused lock leaves no descriptor open"

_first.release()
_second.acquire()                              # free again straight after release
assert _lock_path.exists(), "the lock file is never deleted"
_second.release()
_second.release()                              # releasing twice is harmless

# the kernel frees the lock when the holder dies without releasing: no stale lock
_child = _sp.Popen([_sys.executable, "-c",
                    "import sys,time; from ensign_scan.runlock import RunLock; "
                    "RunLock(sys.argv[1]).acquire(); print('held', flush=True); time.sleep(60)",
                    str(_lock_path)], stdout=_sp.PIPE, text=True)
assert _child.stdout.readline().strip() == "held"
try:
    RunLock(_lock_path).acquire()
    raise AssertionError("lock held by another process should be refused")
except AlreadyRunning as _e:
    assert _e.holder_pid == _child.pid, (_e.holder_pid, _child.pid)
_child.kill(); _child.wait()
_after = RunLock(_lock_path); _after.acquire(); _after.release()   # killed holder left no stale lock

# unreadable-for-writing lock file (e.g. root-owned): still locks, via a read-only descriptor
if _os.geteuid() != 0:
    _ro = _rl_dir / "ro.lock"; _ro.write_text("1\n"); _ro.chmod(0o444)
    _a, _b = RunLock(_ro), RunLock(_ro)
    _a.acquire()
    try:
        _b.acquire(); raise AssertionError("read-only lock file must still exclude")
    except AlreadyRunning as _e:
        assert _e.holder_pid == 1, "pid is read from the file even though we couldn't write it"
    _a.release()
else:
    print("  (skipped read-only lock-file case: running as root)")

# end to end: main.py refuses to start while the lock is held, and exits 75
_cfg_dir = _P(_tf.mkdtemp())
(_cfg_dir / "c.toml").write_text(f'data_dir = "{_cfg_dir}"\n')
_holder = RunLock(_cfg_dir / "ensign.lock"); _holder.acquire()
_env = dict(_os.environ, HOME=str(_cfg_dir))
_run = _sp.run([_sys.executable, "main.py", "--config", str(_cfg_dir / "c.toml"), "--no-scan"],
               capture_output=True, text=True, env=_env, timeout=60)
assert _run.returncode == 75, (_run.returncode, _run.stdout, _run.stderr)
assert "already running" in _run.stdout and str(_os.getpid()) in _run.stdout, _run.stdout
assert "Greetings" not in _run.stdout, "refused before the greeting / any scanning"
_holder.release()
print("runlock test passed ✓")

# --- progress line: counts, and one summary line when not a terminal ---
import io as _io
from rich.console import Console as _Console
from ensign_scan.progress import RunProgress

_buf = _io.StringIO()
_con = _Console(file=_buf, force_terminal=False, width=120)
with RunProgress("Scan Progress", 6, workers=4, console=_con) as _bar:
    for _st in ["clean", "clean", "infected", "error", "failed", "skipped"]:
        _con.print(f"a file line ({_st})")        # per-file output still prints normally
        _bar.advance(_st)
_out = _buf.getvalue()
assert _out.count("a file line") == 6, "per-file lines are not swallowed by the bar"
_last = [l for l in _out.splitlines() if "Scan Progress" in l]
assert len(_last) == 1, f"not a terminal: exactly one summary line, got {len(_last)}"
assert "6 of 6 files" in _last[0] and "100%" in _last[0] and "workers : 4" in _last[0], _last[0]
assert "infected : 1" in _last[0], "one infected, written out at 120 columns"
assert "[##########" in _last[0] and "━" not in _last[0], "plain ASCII bar, full at 100%"
assert "errors : 2" in _last[0], "error + failed count as errors; skipped does not"

# advancing from many threads at once loses no counts
import threading as _th
_buf2 = _io.StringIO()
_con2 = _Console(file=_buf2, force_terminal=False, width=120)
with RunProgress("Scan Progress", 400, workers=8, console=_con2) as _bar2:
    def _hammer():
        for _ in range(100): _bar2.advance("infected")
    _ts = [_th.Thread(target=_hammer) for _ in range(4)]
    [t.start() for t in _ts]; [t.join() for t in _ts]
assert "400 of 400 files" in _buf2.getvalue() and "infected : 400" in _buf2.getvalue(), _buf2.getvalue()

# Scanner reports what happened to each file, and process_file still returns just the hash
import tempfile as _tf2
from pathlib import Path as _P2
from ensign_scan.clamd import ScanOutcome as _SO
from ensign_scan.models import ScanStatus as _SS3
class _FakeClamd:
    def ping(self): return True
    def max_threads(self): return 4
    def signature_version(self): return 7
    def daemon_uid(self): return 990       # an unprivileged clamav user
    def supports_fildes(self): return True
    def scan(self, path):
        if path.name.startswith("bad"): return _SO(_SS3.INFECTED, "x: Eicar FOUND", "Eicar")
        return _SO(_SS3.CLEAN, "x: OK", None)
    def scan_fd(self, fd, label):
        return self.scan(_P2(label))
_pd2 = _P2(_tf2.mkdtemp())
(_pd2 / "ok.txt").write_text("fine"); (_pd2 / "bad.txt").write_text("eicar")
_sc = Scanner(Config(db_url=f"sqlite:///{_pd2}/t.db", log_file=_pd2 / "e.txt", max_workers=2), clamd=_FakeClamd())
_h, _s = _sc._process_file(_pd2 / "ok.txt")
assert _s == "clean" and len(_h) == 64
assert _sc._process_file(_pd2 / "bad.txt")[1] == "infected"
assert _sc._process_file(_pd2 / "gone.txt") == (None, "skipped"), "a vanished file is skipped, not an error"
assert _sc.process_file(_pd2 / "ok.txt") == _h, "process_file keeps returning just the hash"

# a file that vanished after the walk listed it is skipped quietly; any other stat failure is still logged
import logging as _lg2
_seen = []
class _Grab2(_lg2.Handler):
    def emit(self, record): _seen.append(record.getMessage())
_g2 = _Grab2(level=_lg2.ERROR); _lg2.getLogger().addHandler(_g2)
try:
    assert _sc._process_file(_pd2 / "gone.txt") == (None, "skipped")
    assert not any("gone.txt" in m for m in _seen), "a vanished file must not be logged as an error"
    import ensign_scan.scanner as _scmod
    _real_soe = _scmod.stat_or_error
    _scmod.stat_or_error = lambda p: (None, PermissionError(13, "Permission denied"))
    try:
        assert _sc._process_file(_pd2 / "ok.txt") == (None, "skipped")
    finally:
        _scmod.stat_or_error = _real_soe
    assert any("ok.txt" in m and "Permission denied" in m for m in _seen), "other stat failures still get logged"
finally:
    _lg2.getLogger().removeHandler(_g2)
print("vanished-file logging test passed ✓")
assert _sc._process_all([_pd2 / "ok.txt", _pd2 / "bad.txt", _pd2 / "gone.txt"], True, "Scan Progress") == [_h, _sc.process_file(_pd2 / "bad.txt"), None]
print("progress line test passed ✓")

# narrow terminal: the counts and worker number go together, the progress stays
_bufn = _io.StringIO()
_conn = _Console(file=_bufn, force_terminal=False, width=60)
with RunProgress("Scan Progress", 10, workers=8, console=_conn) as _barn:
    for _st in ["infected", "error"] + ["clean"] * 8:
        _barn.advance(_st)
_ln = [l for l in _bufn.getvalue().splitlines() if "Scan Progress" in l][0]
assert len(_ln) <= 60, _ln
assert "10 of 10 files" in _ln and "100%" in _ln and "took" in _ln, _ln
assert "infected" not in _ln and "errors" not in _ln and "workers" not in _ln, _ln
print("progress narrow-width test passed ✓")

# the line follows the terminal width. Rendered mid-run (not started, so
# nothing is drawn until we ask): full line -> ETA only -> bar alone
def _midrun_line(width):
    b = _io.StringIO()
    c = _Console(file=b, force_terminal=False, width=width)
    bar = RunProgress("Scan Progress", 6, workers=8, console=c, clock=lambda: 0.0)
    for st in ["infected", "error"]:
        bar.advance(st)
    c.print(bar)
    line = b.getvalue().rstrip("\n")
    assert len(line) <= width, (width, len(line), line)
    return line
_w1, _w2, _w3 = _midrun_line(110), _midrun_line(80), _midrun_line(50)
assert "33% | ETA -- | infected : 1 | errors : 1 | workers : 8" in _w1, _w1
assert _w2.endswith("33% | ETA --"), _w2                 # counts and workers gone together
assert _w3.endswith("33%") and "|" not in _w3, _w3       # bar alone, no dangling separator
print("progress width-tiers test passed ✓")

# ETA: driven by a fake clock, based on the last minute's pace, honest when it can't know
from ensign_scan.progress import _fmt_duration, _fmt_elapsed
assert [_fmt_duration(x) for x in (3, 45, 89, 860, 7500)] == ["3s", "45s", "1m", "14m", "2h 05m"]
assert [_fmt_elapsed(x) for x in (3, 192, 7500)] == ["3s", "3m 12s", "2h 05m"]

_t = [0.0]
def _eta_line(bar, width=140):
    b = _io.StringIO(); c = _Console(file=b, force_terminal=False, width=width); bar._live.console = c
    c.print(bar); return b.getvalue()
_bar = RunProgress("Scan Progress", 1000, workers=4, console=_Console(file=_io.StringIO()), clock=lambda: _t[0])
_t[0] = 3.0
for _ in range(10): _bar.advance("clean")
assert "ETA --" in _eta_line(_bar), "under 5 seconds: not enough data to estimate"

_t[0] = 0.0
_bar2 = RunProgress("Scan Progress", 100, workers=4, console=_Console(file=_io.StringIO()), clock=lambda: _t[0])
_t[0] = 10.0
for _ in range(20): _bar2.advance("clean")
assert "ETA 40s" in _eta_line(_bar2), _eta_line(_bar2)      # 20 files in 10s, 80 left

# slow first 100 s, fast last 60 s: the estimate follows the current pace, not the average
_t[0] = 0.0
_bar3 = RunProgress("Scan Progress", 1000, workers=4, console=_Console(file=_io.StringIO()), clock=lambda: _t[0])
for _i in range(100):
    _t[0] = _i + 1.0; _bar3.advance("clean")                   # 1 file/s -> 100 done at t=100
for _i in range(600):
    _t[0] = 100 + (_i + 1) * 0.1; _bar3.advance("clean")       # 10 files/s -> 700 done at t=160
assert "ETA 30s" in _eta_line(_bar3), _eta_line(_bar3)          # 300 left at 10/s (a whole-run average would say 1m)
_t[0] = 300.0                                                   # then nothing finishes for a long while
assert "ETA --" in _eta_line(_bar3), "stalled: no pace to go on, so no estimate"

_t[0] = 0.0
_bar4 = RunProgress("Scan Progress", 3, workers=4, console=_Console(file=_io.StringIO()), clock=lambda: _t[0])
for _i in range(3):
    _t[0] = 64.0 * (_i + 1); _bar4.advance("clean")
_t[0] = 500.0                                                   # time passing after the finish changes nothing
assert "took 3m 12s" in _eta_line(_bar4), _eta_line(_bar4)
print("progress ETA test passed ✓")
