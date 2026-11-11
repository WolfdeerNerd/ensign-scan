"""Cross-reference pacman's own file-integrity check against Ensign's
tracked hashes -- entirely local, nothing leaves the machine.

`pacman -Qkk` verifies every installed file against the checksums,
sizes, and permissions pacman recorded when the package was installed.
A mismatch means "this file differs from what the package manager
thinks it installed" -- which is either a legitimate local edit (a
config file you changed on purpose) or something worth a closer look.
Ensign can't tell those apart on its own; this just surfaces pacman's
findings and, where Ensign has also scanned the same file, shows what
Ensign's last look at it found.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass

from .base import Backend, c_locale_env

# Best-effort parser: pacman's exact wording for `-Qkk` output has not
# been verified against a live install in this environment. Two prefix
# shapes are handled: "warning: pkg: /path (reason)" for genuine
# mismatches, and "backup file: pkg: /path (reason)" for pacman's own
# backup/config files -- the latter is expected to differ (that's what
# marking a file "backup" means: pacman won't complain about you
# editing it) and is reported separately, not alongside real anomalies.
# The bulk of `-Qkk` output is neither shape -- one "N total files, M
# altered files" summary line per package, matched or not -- so the
# sanity check below counts only lines that look like they could be a
# mismatch (contain a parenthetical), not every line pacman prints.
_MISMATCH_RE = re.compile(
    r"^(?:(?P<kind>warning|backup file):\s*)?(?P<pkg>\S+):\s+(?P<path>/\S+)\s+\((?P<reason>.+)\)\s*$"
)


# Reasons that mean pacman could not READ the file, not that the file
# differs from the package. Seen in real `pacman -Qkk` output when it is
# run without root: root-only files can't be opened, so nothing was checked.
UNVERIFIED_REASONS = frozenset({
    "failed to calculate SHA256 checksum",
    "Permission denied",
})


@dataclass(frozen=True)
class PacmanMismatch:
    package: str
    filepath: str
    reason: str
    # True for pacman's own backup/config files (e.g. /etc/fstab) --
    # expected to be locally modified, not itself a sign of anything.
    is_backup: bool = False

    @property
    def unverified(self) -> bool:
        """pacman couldn't read this file, so it was never actually compared."""
        return self.reason in UNVERIFIED_REASONS

    # The same shape as base.FileMismatch, so one report serves every backend.
    @property
    def is_config(self) -> bool:
        return self.is_backup

    excluded = False  # pacman has no path-exclude equivalent


@dataclass(frozen=True)
class PacmanVerifyResult:
    mismatches: list[PacmanMismatch]
    # Count of output lines that look like they COULD be a mismatch
    # (contain a parenthetical) -- excludes the one-per-package
    # "N total files, M altered" summary lines, which were never meant
    # to match. A gap between this and len(mismatches) means the parser
    # is missing a real line shape; a gap against total raw output
    # lines does not, since most of that output is summary noise by
    # design.
    candidate_line_count: int
    # Set if the command ran but didn't complete cleanly (timeout, a
    # permission problem, etc). Distinct from verify_all() returning
    # None, which means pacman itself isn't on PATH at all.
    error: str | None = None

def available() -> bool:
    return shutil.which("pacman") is not None


_OWNER_RE = re.compile(r"is owned by (\S+) (\S+)")


def owner(path: str, timeout: float = 10.0) -> tuple[str, str | None]:
    """Ask pacman which package owns a file (`pacman -Qo`). Read-only, local.

    Returns (state, package): ("owned", "name version"), ("unowned", None)
    when pacman says no package owns it, or ("unknown", None) when pacman
    is missing, timed out, or failed -- so an error is never reported as
    "not owned".
    """
    if not available():
        return ("unknown", None)
    try:
        result = subprocess.run(["pacman", "-Qo", "--", path], capture_output=True,
                                text=True, timeout=timeout, env=c_locale_env())
    except (subprocess.TimeoutExpired, OSError):
        return ("unknown", None)
    match = _OWNER_RE.search(result.stdout)
    if result.returncode == 0 and match:
        return ("owned", f"{match[1]} {match[2]}")
    if "No package owns" in result.stderr:
        return ("unowned", None)
    return ("unknown", None)


def verify_all(timeout: float = 600.0) -> PacmanVerifyResult | None:
    """Run `pacman -Qkk` and parse mismatches. Read-only; changes nothing.

    Returns None ONLY if pacman isn't on PATH at all -- e.g. not an Arch
    system. If pacman exists but the command itself fails (a timeout is
    the most likely cause: -Qkk hashes every file of every installed
    package, which can take a while on a system with many packages), the
    returned PacmanVerifyResult carries the real reason in `.error`
    instead of being silently indistinguishable from "not installed."
    """
    if not available():
        return None
    try:
        result = subprocess.run(
            ["pacman", "-Qkk"], capture_output=True, text=True, timeout=timeout,
            env=c_locale_env(),
        )
    except subprocess.TimeoutExpired:
        return PacmanVerifyResult(
            mismatches=[], candidate_line_count=0,
            error=f"pacman -Qkk did not finish within {timeout:.0f}s. It checks "
                  f"every file of every installed package, which can be slow on "
                  f"systems with many packages -- try again, or increase the timeout.",
        )
    except OSError as exc:
        return PacmanVerifyResult(mismatches=[], candidate_line_count=0, error=f"pacman -Qkk failed to run: {exc}")

    lines = [ln.strip() for ln in (result.stdout + "\n" + result.stderr).splitlines() if ln.strip()]
    mismatches = []
    candidates = 0
    for line in lines:
        if "(" not in line:
            continue  # per-package "N total files, M altered" summary noise
        candidates += 1
        match = _MISMATCH_RE.match(line)
        if match:
            mismatches.append(PacmanMismatch(
                package=match.group("pkg"),
                filepath=match.group("path"),
                reason=match.group("reason"),
                is_backup=(match.group("kind") == "backup file"),
            ))
    return PacmanVerifyResult(mismatches=mismatches, candidate_line_count=candidates)


class PacmanBackend(Backend):
    """Arch Linux and derivatives (Manjaro, EndeavourOS, ...)."""
    name = "pacman"
    label = "pacman"
    verify_all_command = "sudo pacman -Qkk"
    config_word = "backup/config"

    def available(self) -> bool:
        return available()

    def owner(self, path: str) -> tuple[str, str | None]:
        return owner(path)

    def verify_all(self) -> PacmanVerifyResult | None:
        return verify_all()

    def verify_command(self, package: str) -> str | None:
        return f"pacman -Qkk {package}"

    def explain_reason(self, reason: str) -> str | None:
        from .. import explanations  # imported here: explanations is a sibling package module
        return explanations.explain_pacman_reason(reason)
