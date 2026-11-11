"""The interface every package-manager backend implements.

Ensign asks a package manager two read-only questions:

  * owner(path)    -- which installed package owns this file, if any
  * verify_all()   -- which installed files no longer match their package

Each backend answers them with its own commands (pacman, dpkg, rpm).
Callers only ever talk to this interface, so nothing outside
ensign_scan/pkgdb needs to know which distribution it is running on.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


def c_locale_env() -> dict[str, str]:
    """The current environment with messages forced to English.

    Every backend parses its package manager's output by matching text
    ("is owned by", "No package owns", "missing"). Package managers
    translate those messages, so on a German or French system the parser
    would see words it doesn't know and quietly report "unknown" for
    everything. LC_ALL=C makes the output the same on every system.
    """
    return {**os.environ, "LC_ALL": "C"}


# How many unparsed lines a VerifyResult keeps, to show in the report.
UNPARSED_KEPT = 5


@dataclass(frozen=True)
class FileMismatch:
    """One way one installed file differs from its package's record.

    A file that differs in several ways (size and checksum, say) gives one
    FileMismatch per way, the same shape pacman's own output has.
    """
    package: str
    filepath: str
    # The difference in words ("Checksum mismatch", "File missing", ...).
    # explain_reason() looks these up for the report.
    reason: str
    # A file the package marks as configuration (pacman "backup", dpkg
    # conffile, rpm %config). Edited on purpose all the time, so reported
    # separately from real anomalies.
    is_config: bool = False
    # The package manager couldn't read the file, so it was never compared.
    unverified: bool = False
    # Left out on purpose by the system's own settings (dpkg path-exclude,
    # which minimal and container installs use to drop docs and man pages).
    excluded: bool = False


@dataclass(frozen=True)
class VerifyResult:
    mismatches: list[FileMismatch]
    # Output lines that look like a finding. More of these than parsed
    # mismatches means the package manager printed a line shape the parser
    # doesn't know, and the report says so instead of dropping it.
    candidate_line_count: int
    # Set if the command ran but didn't finish cleanly (a timeout, say).
    # Distinct from verify_all() returning None: "can't run here at all".
    error: str | None = None
    # Output lines that parsed. One line can give several mismatches (a
    # file with a size AND a checksum change), so this, not
    # len(mismatches), is what to compare with candidate_line_count.
    parsed_line_count: int = 0
    # The first few candidate lines that didn't parse, as printed, so the
    # report can show what it couldn't read instead of silently dropping it.
    unparsed: tuple[str, ...] = ()


class Backend:
    # Short identifier, also the value accepted by `package_verification`.
    name: str = "base"
    # What users call this package manager in messages ("pacman package").
    label: str = "package"
    # The full-system check, as a user would run it by hand with root.
    # Shown when files couldn't be verified without root.
    verify_all_command: str | None = None
    # How the report names the package manager's config-file group.
    config_word: str = "config"

    def available(self) -> bool:
        """True if this backend's commands can actually run here."""
        raise NotImplementedError

    def owner(self, path: str) -> tuple[str, str | None]:
        """("owned", "name version"), ("unowned", None), or ("unknown", None).

        "unknown" covers every failure (command missing, timed out,
        unexpected output), so an error is never reported as "not owned".
        """
        raise NotImplementedError

    def verify_all(self):
        """Check every installed file against the package database.
        Returns a VerifyResult (or a backend's compatible result), or None
        if this can't run here."""
        raise NotImplementedError

    def verify_command(self, package: str) -> str | None:
        """The command a user can run to check one package by hand, shown
        as a hint next to findings. None if there is no such command."""
        return None

    def explain_reason(self, reason: str) -> str | None:
        """A plain-words note for a mismatch reason, or None."""
        return None
