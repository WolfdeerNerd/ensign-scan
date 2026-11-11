"""The backend used when no package manager is available or wanted.

It answers "unknown" to everything. That is deliberate: "no package
manager here" must never look like "no package owns this file", which
would make every system file appear foreign.
"""
from __future__ import annotations

from .base import Backend


class NoneBackend(Backend):
    name = "none"
    label = "package"

    def __init__(self, reason: str = "package verification is off") -> None:
        # Why package verification isn't running, in plain words, for the
        # report and --diagnostics. Never contains paths or user details.
        self.reason = reason

    def available(self) -> bool:
        return True  # always usable; it just never knows anything

    def owner(self, path: str) -> tuple[str, str | None]:
        return ("unknown", None)

    def verify_all(self):
        return None
