"""Live test of the pacman integration against a REAL pacman.

Skipped unless ENSIGN_TEST_PACMAN=1. CI sets it in the Arch Linux
container job; on your own Arch machine:

    ENSIGN_TEST_PACMAN=1 python3 tests/pacman_live_test.py

integrations_test.py checks the parser against sample lines. This checks
it against what pacman actually prints today, which is the only way to
notice when a pacman update changes its wording.
"""
from __future__ import annotations

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

if os.environ.get("ENSIGN_TEST_PACMAN") != "1":
    print("live pacman test skipped (set ENSIGN_TEST_PACMAN=1 to run it)")
    sys.exit(0)

from ensign_scan import pacman  # noqa: E402
from ensign_scan.db import make_engine  # noqa: E402
from ensign_scan.reports import pacman_report  # noqa: E402

assert pacman.available(), "ENSIGN_TEST_PACMAN=1 but pacman isn't on PATH"

# --- ownership ---------------------------------------------------------------
state, pkg = pacman.owner("/usr/bin/pacman")
assert state == "owned" and pkg.split()[0] == "pacman", (state, pkg)

with tempfile.NamedTemporaryFile() as f:
    assert pacman.owner(f.name) == ("unowned", None), "a fresh temp file belongs to no package"

# A path that doesn't exist must never come back "owned"
state, _ = pacman.owner("/usr/bin/ensign-no-such-file")
assert state in ("unowned", "unknown"), state
print("ownership test passed ✓")

# --- verify_all() against real -Qkk output ----------------------------------------------
result = pacman.verify_all()
assert result is not None and result.error is None, result and result.error
# Every line that looks like it could be a mismatch must parse. A gap means
# pacman prints a line shape the parser doesn't know, and those findings
# would silently disappear from the report.
assert result.candidate_line_count == len(result.mismatches), (
    f"{result.candidate_line_count - len(result.mismatches)} mismatch-shaped lines didn't parse; "
    f"run 'pacman -Qkk' and compare against _MISMATCH_RE"
)
print(f"verify_all test passed ✓ ({len(result.mismatches)} lines, all parsed)")

# --- the report renders real results ---------------------------------------------------
with tempfile.TemporaryDirectory() as d:
    engine = make_engine(f"sqlite:///{d}/live.db")
    with contextlib.redirect_stdout(io.StringIO()) as buf:
        pacman_report(engine, result)
    out = buf.getvalue()
    assert "PACMAN FILE INTEGRITY" in out, out
    assert "parser may need updating" not in out, out
print("pacman_report test passed ✓")

print("\nAll live pacman tests passed ✓")
