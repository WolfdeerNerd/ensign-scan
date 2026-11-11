"""Compatibility shim: the pacman code now lives in ensign_scan.pkgdb.pacman.

Kept so existing imports (`from ensign_scan.pacman import ...`) and the
test suite keep working unchanged. New code should go through
ensign_scan.pkgdb, which picks the right package manager for the system.
"""
from .pkgdb.pacman import *  # noqa: F401,F403
from .pkgdb.pacman import _MISMATCH_RE, _OWNER_RE  # noqa: F401  (private names aren't star-exported)
