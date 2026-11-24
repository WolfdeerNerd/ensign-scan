"""Ensign's logo, for the greeting at the start of a run.

ENSIGN in solid blocks with a box-line drop shadow, in the style of old
ANSI-art banners, on hand-made letters (the same drawing as
assets/ensign-logo.txt and the README's SVGs). The letters print in the
terminal's own cyan and the shadow in its grey, so the terminal's theme
decides the exact shades.

It's printed only where it will look right: on a terminal (not into a
pipe or a log), at least WIDTH + 1 columns wide, with an encoding that has
the block and box characters. Anywhere else the greeting is plain text, as
before. Rich leaves the colors out when NO_COLOR is set.
"""
from __future__ import annotations

from rich.console import Console
from rich.text import Text

LINES = (
    "██████╗ ███╗  ██╗ ██████╗ ██╗ ██████╗ ███╗  ██╗",
    "██╔═══╝ ████╗ ██║ ██╔═══╝ ██║ ██╔═══╝ ████╗ ██║",
    "█████╗  ██╔██╗██║ ██████╗ ██║ ██║███╗ ██╔██╗██║",
    "██╔══╝  ██║╚████║ ╚═══██║ ██║ ██║╚██║ ██║╚████║",
    "██████╗ ██║ ╚███║ ██████║ ██║ ██████║ ██║ ╚███║",
    "╚═════╝ ╚═╝  ╚══╝ ╚═════╝ ╚═╝ ╚═════╝ ╚═╝  ╚══╝",
)
WIDTH = max(map(len, LINES))

LETTER_STYLE = "cyan"
SHADOW_STYLE = "bright_black"   # the terminal's grey


def banner(console: Console) -> list[Text] | None:
    """The logo as styled lines for `console`, or None where it wouldn't
    render properly (see the module docstring)."""
    if not console.is_terminal or console.width <= WIDTH:
        return None
    try:
        "".join(LINES).encode(console.encoding)
    except (UnicodeEncodeError, LookupError):
        return None
    lines = []
    for row in LINES:
        text = Text(" ")   # the greeting's one-space indent
        for run in _runs(row):   # one span per run of the same kind: fewer escape codes
            style = LETTER_STYLE if run[0] == "█" else None if run[0] == " " else SHADOW_STYLE
            text.append(run, style=style)
        lines.append(text)
    return lines


def _runs(row: str) -> list[str]:
    """`row` split into runs of blocks, box lines and spaces."""
    kind = lambda ch: "█" if ch == "█" else " " if ch == " " else "box"  # noqa: E731
    runs: list[str] = []
    for ch in row:
        if runs and kind(runs[-1][0]) == kind(ch):
            runs[-1] += ch
        else:
            runs.append(ch)
    return runs
