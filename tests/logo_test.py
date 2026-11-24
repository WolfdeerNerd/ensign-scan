"""The logo in the greeting: shown on a wide enough UTF-8 terminal, left out
everywhere else (a pipe or log, a narrow window, an encoding without block
characters), and the same drawing as assets/ensign-logo.txt.

    python3 tests/logo_test.py
"""
from __future__ import annotations

import sys as _sys_path
from pathlib import Path as _Path

# Run against THIS checkout, never an installed copy of Ensign.
ROOT = _Path(__file__).resolve().parent.parent
_sys_path.path.insert(0, str(ROOT))

import io  # noqa: E402
import re  # noqa: E402

from rich.console import Console  # noqa: E402

from ensign_scan import logo  # noqa: E402


def console(width=80, terminal=True, encoding="utf-8"):
    out = io.TextIOWrapper(io.BytesIO(), encoding=encoding)
    return Console(file=out, force_terminal=terminal, width=width, color_system="standard")


# The same drawing everywhere.
assert (ROOT / "assets" / "ensign-logo.txt").read_text(encoding="utf-8") == "\n".join(logo.LINES) + "\n"
assert set("".join(logo.LINES)) <= set("█╗╝╔╚═║ "), "blocks, box lines and spaces only"
assert logo.WIDTH == 47

# Shown: a wide UTF-8 terminal, letters cyan and the shadow grey.
lines = logo.banner(console())
assert lines is not None and len(lines) == len(logo.LINES)
assert all(len(line.plain) == len(row) + 1 for line, row in zip(lines, logo.LINES, strict=True)), "one-space indent"
styles = {str(span.style) for line in lines for span in line.spans}
assert styles == {logo.LETTER_STYLE, logo.SHADOW_STYLE}, styles
assert logo.banner(console(width=logo.WIDTH + 1)) is not None, "48 columns is just enough"

# Left out: everywhere it wouldn't render properly.
assert logo.banner(console(terminal=False)) is None, "a pipe or a log"
assert logo.banner(console(width=logo.WIDTH)) is None, "too narrow"
assert logo.banner(console(encoding="ascii")) is None, "no block characters"
assert logo.banner(console(encoding="latin-1")) is None, "no block characters"

# The greeting prints it above the usual lines, and leaves it out in a pipe.
from ensign_scan import cli  # noqa: E402
from ensign_scan.config import Config  # noqa: E402

for terminal in (True, False):
    con = console(terminal=terminal)
    saved = cli.get_console
    cli.get_console = lambda con=con: con
    real_print = cli.print
    cli.print = con.print
    try:
        cli.greet(Config())
    finally:
        cli.get_console, cli.print = saved, real_print
    con.file.flush()
    text = re.sub(r"\x1b\[[0-9;]*m", "", con.file.buffer.getvalue().decode())   # colors off
    assert "Greetings," in text
    assert ("██████╗" in text) == terminal, (terminal, text[:200])

print("logo test passed ✓")
