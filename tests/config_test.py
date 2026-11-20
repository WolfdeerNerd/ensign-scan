"""Tests for the multi-machine config loader. Run: python3 tests/config_test.py"""

import sys as _sys_path
from pathlib import Path as _Path

# Run against THIS checkout, never an installed copy of Ensign: the tests
# live in tests/, so without this "import ensign_scan" would find whatever
# is installed (or nothing) instead of the code next to them.
ROOT = _Path(__file__).resolve().parent.parent
_sys_path.path.insert(0, str(ROOT))
import os
import tempfile
from pathlib import Path

from ensign_scan.config import EXAMPLE_CONFIG, HOSTNAME, Config, _expand, HOME

# 1. No file at all -> built-in defaults
cfg = Config()
assert cfg.max_workers == 0  # 0 = auto
assert cfg.signature_max_age_days == 3
assert cfg.rescan_after_signature_updates == 7  # default: about weekly
assert cfg.sweep_huge_files is True  # the sweep is on by default
assert (cfg.resweep_after_signature_updates, cfg.resweep_after_days) == (30, 30)
assert cfg.infected_alert_seconds == 60
assert cfg.infected_alert_only_while_gaming is True
assert cfg.never_open_credentials is False  # every file is scanned by default
assert cfg.log_keep_days == 90 and cfg.log_max_total_mb == 2048
assert cfg.log_dir == cfg.data_dir / 'logs'
assert "ensign-scan/system.db" in cfg.db_url

# 2. TOML with global values + a hosts section for THIS machine
toml = f"""
data_dir = "~/Scripts/Ensign"
max_workers = 3
scan_targets = ["~/Downloads"]
signature_max_age_days = 7
rescan_after_signature_updates = 12
infected_alert_seconds = 15
infected_alert_only_while_gaming = false
log_keep_days = 30
log_max_total_mb = 0
bogus_key = true

[hosts.{HOSTNAME}]
max_workers = 8
snapshot_roots = ["~/snaps"]
excludes = ["~/.cache/", "/tmp"]

[hosts.some-other-box]
max_workers = 1
"""
with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
    f.write(toml)
    path = f.name

cfg = Config.load(path)
assert cfg.max_workers == 8, f"host override should win, got {cfg.max_workers}"
assert cfg.signature_max_age_days == 7, cfg.signature_max_age_days
assert cfg.rescan_after_signature_updates == 12, cfg.rescan_after_signature_updates
assert cfg.infected_alert_seconds == 15, cfg.infected_alert_seconds
assert cfg.infected_alert_only_while_gaming is False
assert cfg.log_keep_days == 30 and cfg.log_max_total_mb == 0
assert cfg.scan_targets == (HOME / "Downloads",), cfg.scan_targets
assert cfg.snapshot_roots == (str(HOME / "snaps"),), cfg.snapshot_roots
assert cfg.excludes == (str(HOME / ".cache"), "/tmp"), cfg.excludes
assert str(HOME / "Scripts/Ensign/system.db") in cfg.db_url, cfg.db_url
assert cfg.source == path

# 3. Explicitly requested missing file -> error (silent fallback is worse)
try:
    Config.load("/nonexistent/ensign.toml")
    raise AssertionError("should have raised FileNotFoundError")
except FileNotFoundError:
    pass

# 3b. Malformed hosts values -> clear ValueError, not a crash or a silent skip
for bad, expect in (
    ('hosts = "oops"', "'hosts' must be a table"),
    ('hosts = [1, 2]', "'hosts' must be a table"),
    (f'[hosts]\n"{HOSTNAME}" = 5', f"[hosts.{HOSTNAME}] must be a table"),
):
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
        f.write(bad + "\n")
    try:
        Config.load(f.name)
        raise AssertionError(f"should have raised ValueError for: {bad!r}")
    except ValueError as e:
        assert expect in str(e), (bad, str(e))
    finally:
        os.unlink(f.name)
print("malformed hosts test passed ✓")

# 4. Tilde expansion
assert _expand("~") == HOME
assert _expand("~/x") == HOME / "x"
assert _expand("/abs/path") == Path("/abs/path")

os.unlink(path)

# 2b. rescan_after_signature_updates: 7-31 allowed, 0 = off, others clamped with a warning
import contextlib, io
def _sig(value):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cfg = Config._from_dict({"rescan_after_signature_updates": value}, source="t")
    return cfg.rescan_after_signature_updates, buf.getvalue()
assert _sig(7) == (7, "") and _sig(31) == (31, "") and _sig(0) == (0, ""), "in range / off: untouched, silent"
v, msg = _sig(1);  assert v == 7 and "using 7" in msg, (v, msg)
v, msg = _sig(90); assert v == 31 and "using 31" in msg, (v, msg)
v, msg = _sig(-3); assert v == 7 and "using 7" in msg, (v, msg)
print("signature-rescan range test passed ✓")

# 99. The first-run template embedded in config.py must match
# config.example.toml exactly -- they drifted apart before -- and must
# parse as valid TOML that Config.load() accepts.
import tomllib
example_path = ROOT / "config.example.toml"
assert EXAMPLE_CONFIG == example_path.read_text(), \
    "EXAMPLE_CONFIG in ensign_scan/config.py has drifted from config.example.toml"
tomllib.loads(EXAMPLE_CONFIG)
with tempfile.TemporaryDirectory() as _d:
    _p = Path(_d) / "c.toml"
    _p.write_text(EXAMPLE_CONFIG)
    assert Config.load(_p).max_workers == 0
print("EXAMPLE_CONFIG sync test passed ✓")

print("All config tests passed ✓")

# resweep_after_*: 7-90 allowed, 0 = off, others clamped with a warning
for key in ("resweep_after_signature_updates", "resweep_after_days"):
    for value, expect in ((30, 30), (0, 0), (3, 7), (400, 90)):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cfg = Config._from_dict({key: value}, source="t")
        assert getattr(cfg, key) == expect, (key, value, getattr(cfg, key))
        assert ("outside 7-90" in buf.getvalue()) == (value != expect), (key, value, buf.getvalue())
print("resweep settings test passed ✓")

# Wrong types fail loudly, before anything runs
for raw, needle in (({"sweep_huge_files": "no"}, "true or false"),
                    ({"never_open_credentials": "yes"}, "true or false"),
                    ({"resweep_after_days": "30"}, "remove the quotes"),
                    ({"max_workers": True}, "whole number"),
                    ({"rescan_after_signature_updates": 7.5}, "whole number"),
                    ({"scan_targets": "~/Downloads"}, "list of paths"),
                    ({"excludes": [1, 2]}, "list of paths"),
                    ({"clamd_socket": 5}, "path in quotes"),
                    ({"data_dir": 5}, "path in quotes"),
                    ({"data_dir": "ensign-data"}, "start with / or ~/"),
                    ({"excludes": ["Downloads/big"]}, "start with / or ~/"),
                    ({"scan_targets": ["~/ok", "relative"]}, "start with / or ~/"),
                    ({"custom_secrets": "x"}, "must be a table"),
                    ({"custom_threats": ["a"]}, "must be a table")):
    try:
        Config._from_dict(raw, source="t")
    except ValueError as exc:
        assert needle in str(exc), (raw, exc)
    else:
        raise AssertionError(f"accepted {raw}")
assert Config._from_dict({"sweep_huge_files": False, "max_workers": 4}, source="t").max_workers == 4
assert Config._from_dict({"data_dir": "~/x", "excludes": ["/a", "~/b", "$HOME/c"]}, source="t").excludes
with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as bad:
    bad.write("not = valid = toml\n")
try:
    Config.load(Path(bad.name))
except ValueError as exc:
    assert bad.name in str(exc) and "not valid TOML" in str(exc), exc
else:
    raise AssertionError("broken TOML accepted")
finally:
    os.unlink(bad.name)
print("config type checks test passed ✓")

# ...and the command line says so in one line, with no traceback, and exits 1
import subprocess  # noqa: E402

with tempfile.TemporaryDirectory() as d:
    cfg = Path(d, "c.toml")
    cfg.write_text(f'data_dir = "{d}"\nsweep_huge_files = "no"\n')
    run = subprocess.run([_sys_path.executable, str(ROOT / "main.py"), "--config", str(cfg)],
                         capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
    assert run.returncode == 1 and "Config error" in run.stdout, (run.returncode, run.stdout, run.stderr)
    assert "Traceback" not in run.stdout + run.stderr, run.stderr
print("config error on the command line test passed ✓")
