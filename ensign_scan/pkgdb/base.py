"""The interface every package-manager backend implements.

Ensign asks a package manager two read-only questions:

  * owner(path)    -- which installed package owns this file, if any
  * verify_all()   -- which installed files no longer match their package

Each backend answers them with its own commands (pacman, later dpkg,
rpm, ...). Callers only ever talk to this interface, so nothing outside
ensign_scan/pkgdb needs to know which distribution it is running on.
"""
from __future__ import annotations


class Backend:
    # Short identifier, also the value accepted by `package_verification`.
    name: str = "base"
    # What users call this package manager in messages ("pacman package").
    label: str = "package"

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
        Returns a backend-specific result, or None if this can't run here."""
        raise NotImplementedError

    def verify_command(self, package: str) -> str | None:
        """The command a user can run to check one package by hand, shown
        as a hint next to findings. None if there is no such command."""
        return None
