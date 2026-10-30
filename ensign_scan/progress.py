"""A live progress line pinned to the bottom of the terminal during a scan.

    ✓ notes.txt ................ 3f2a9c1e5b7d4e8a… clean
    ✓ photo.jpg ................ 91c0d4ee7a31b2f0… clean
    Scan Progress: 1,234 of 5,678 files [########------------]  21%  ! 2  ✗ 3  · 8 workers

The bar is plain ASCII, in the style of pacman's, and is drawn here rather
than by a ready-made widget so its look and its width are ours to control.

The per-file lines keep scrolling above it; this one line is redrawn in
place. That works because rich's Live display shares the console that the
rest of Ensign already prints through: anything printed while it runs is
inserted above the bar, from any thread.

When output is not a terminal (a systemd service, cron, a pipe) nothing is
redrawn. Rich prints the line once, in its final state, so logs get one
summary line instead of thousands of half-finished ones.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from typing import Callable

from rich import get_console
from rich.console import Console, ConsoleOptions, RenderResult
from rich.live import Live
from rich.text import Text

# Statuses (from Scanner._process_file) counted in the line's detail text.
_INFECTED = "infected"
_ERRORS = {"error", "failed"}

_SEP = Text(" | ")  # the pipes keep "21% 2 3" from reading as arithmetic
_BAR_MIN = 10  # below this much room for the bar, the line drops detail
_BAR_MAX = 50

# ETA: estimated from the pace over roughly the last minute, not the whole run,
# so it follows the current speed. Until WARMUP seconds have passed there isn't
# enough to go on and it shows "--".
_ETA_WINDOW = 60.0
_ETA_WARMUP = 5.0
_SAMPLE_EVERY = 0.5  # seconds between recorded (time, done) points


def _fmt_duration(seconds: float) -> str:
    """45s, 14m, 2h 05m. Rounded for reading, not for precision."""
    seconds = max(0, int(round(seconds)))
    if seconds < 60:
        return f"{seconds}s"
    minutes = (seconds + 30) // 60
    if minutes < 60:
        return f"{minutes}m"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m" if hours < 100 else "99h+"


def _fmt_elapsed(seconds: float) -> str:
    """How long something took, to the second: 45s, 3m 12s, 2h 05m."""
    seconds = max(0, int(round(seconds)))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60:02d}s"
    return f"{seconds // 3600}h {seconds % 3600 // 60:02d}m"


class RunProgress:
    """Context manager: `with RunProgress(...) as bar:` then `bar.advance(status)`
    once per file, from any thread."""

    def __init__(self, label: str, total: int, workers: int, console: Console | None = None,
                 clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._start = clock()
        self._end: float | None = None
        self._samples: deque[tuple[float, int]] = deque([(self._start, 0)])
        self._label = label
        self._total = total
        self._workers = workers
        self._done = 0
        self._infected = 0
        self._errors = 0
        self._lock = threading.Lock()
        self._live = Live(self, console=console or get_console(), refresh_per_second=10)

    def advance(self, status: str | None) -> None:
        """Count one finished file. `status` is the file's outcome."""
        now = self._clock()
        with self._lock:
            self._done += 1
            if now - self._samples[-1][0] >= _SAMPLE_EVERY:
                self._samples.append((now, self._done))
            if self._done >= self._total:
                self._end = now
            if status == _INFECTED:
                self._infected += 1
            elif status in _ERRORS:
                self._errors += 1

    def _eta(self, now: float, done: int) -> str:
        """"ETA 14m", "ETA --" while there isn't enough data, or "took 3m 12s"
        once finished. Call with the lock held."""
        if done >= self._total:
            return f"took {_fmt_elapsed((self._end or now) - self._start)}"
        if now - self._start < _ETA_WARMUP:
            return "ETA --"
        cutoff = now - _ETA_WINDOW
        while len(self._samples) > 1 and self._samples[1][0] <= cutoff:
            self._samples.popleft()
        t0, done0 = self._samples[0]
        if now <= t0 or done <= done0:
            return "ETA --"  # nothing finished in the window: no pace to go on
        rate = (done - done0) / (now - t0)
        return f"ETA {_fmt_duration((self._total - done) / rate)}"

    def _detail(self, infected: int, errors: int, eta: str | None, *, words: bool, workers: bool) -> Text:
        """What follows the bar, in the colors of the per-file lines (red
        infected, yellow error). `words` picks the label text; the symbols
        are the same ones the per-file lines use."""
        parts = [Text(eta)] if eta else []
        parts += [
            Text.assemble(("infected" if words else "!", "red"), f" : {infected:,}"),
            Text.assemble(("errors" if words else "✗", "yellow"), f" : {errors:,}"),
        ]
        if workers:
            parts.append(Text(f"workers : {self._workers}"))
        return _SEP.join(parts)

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        # Called by Live on every refresh; sized to the terminal at that moment.
        now = self._clock()
        with self._lock:
            done, infected, errors = self._done, self._infected, self._errors
            eta = self._eta(now, done)
        fraction = done / self._total if self._total else 1.0

        head = f"{self._label}: {done:,} of {self._total:,} files "
        percent = f" {int(fraction * 100):>3}%"
        bar_end = Text.assemble(percent, _SEP)

        def room_for(d: Text) -> int:
            return options.max_width - len(head) - len(bar_end.plain) - len(d.plain) - 2  # 2 = the brackets

        # Use the richest form that still leaves the bar _BAR_MIN room. What
        # goes first is what matters least: the worker count (it never
        # changes), then the full words, and only on a very narrow terminal
        # the ETA. The infected/error counts are the last thing to go.
        for eta_text, words, workers in ((eta, True, True), (eta, True, False),
                                         (eta, False, False), (None, False, False)):
            detail = self._detail(infected, errors, eta_text, words=words, workers=workers)
            if room_for(detail) >= _BAR_MIN:
                break
        width = max(5, min(_BAR_MAX, room_for(detail)))
        filled = int(width * fraction)

        line = Text(no_wrap=True, overflow="ellipsis")
        line.append(head, style="bold")
        line.append("[")
        line.append("#" * filled, style="green")
        line.append("-" * (width - filled), style="dim")
        line.append("]")
        line.append_text(bar_end)
        line.append_text(detail)
        yield line

    def __enter__(self) -> "RunProgress":
        self._live.start()
        return self

    def __exit__(self, *exc) -> None:
        self._live.stop()
        if not self._live.console.is_terminal:
            # Live prints the final state once but leaves the cursor at the
            # end of that line; end it so the next output starts fresh.
            self._live.console.print()
