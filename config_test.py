"""Tests for the multi-machine config loader. Run: python3 config_test.py"""
import os
import tempfile
from pathlib import Path

from ensign_scan.config import EXAMPLE_CONFIG, HOSTNAME, Config, _expand, HOME

# 1. No file at all -> built-in defaults
cfg = Config()
assert cfg.max_workers == 0  # 0 = auto
assert cfg.signature_max_age_days == 3
assert cfg.rescan_after_signature_updates == 7  # default: about weekly
assert cfg.infected_alert_seconds == 60
assert cfg.infected_alert_only_while_gaming is True
assert cfg.log_keep_days == 90 and cfg.log_max_total_mb == 2048
assert cfg.log_dir == cfg.data_dir / 'logs'
assert "ensign/system.db" in cfg.db_url

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
example_path = Path(__file__).parent / "config.example.toml"
assert EXAMPLE_CONFIG == example_path.read_text(), \
    "EXAMPLE_CONFIG in ensign_scan/config.py has drifted from config.example.toml"
tomllib.loads(EXAMPLE_CONFIG)
with tempfile.TemporaryDirectory() as _d:
    _p = Path(_d) / "c.toml"
    _p.write_text(EXAMPLE_CONFIG)
    assert Config.load(_p).max_workers == 0
print("EXAMPLE_CONFIG sync test passed ✓")

print("All config tests passed ✓")
