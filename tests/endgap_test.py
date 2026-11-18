"""Every run ends with one blank line before the shell prompt.

The scan's footer always ended with one. Standalone commands (--list-allowed,
--unallow, --diagnostics and the rest) used to end right on their last line,
pressed against the prompt. Now main() adds the gap for every run that
didn't already end with one -- never two.

    python3 tests/endgap_test.py
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

with tempfile.TemporaryDirectory() as d:
    env = {k: v for k, v in os.environ.items() if k not in ("SUDO_USER", "ENSIGN_CONFIG")}
    env.update(HOME=d, COLUMNS="200")
    target = Path(d, "a.txt")
    target.write_text("hi")
    for args in (["--list-allowed"], ["--list-allowed-all"], ["--list-infected"], ["--unallow", str(target)],
                 ["--diagnostics"], ["--version"], ["--no-scan"]):
        out = subprocess.run([sys.executable, str(ROOT / "main.py"), *args], env=env, capture_output=True,
                             text=True, stdin=subprocess.DEVNULL, timeout=300).stdout
        assert out.endswith("\n\n"), f"{args}: no blank line at the end: {out[-200:]!r}"
        assert not out.endswith("\n\n\n"), f"{args}: two blank lines at the end: {out[-200:]!r}"
        if args == ["--no-scan"]:
            assert "— Ensign\n\n" in out, "the footer keeps its own gap"

print("end gap test passed ✓")
