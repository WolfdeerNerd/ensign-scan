"""The YARA engine: yara-x, VirusTotal's rewrite of YARA in Rust.

yara-x is where YARA is developed now; the original C library (libyara,
and yara-python on top of it) only gets bug fixes. It is also memory-safe,
which matters here: the engine parses untrusted files inside Ensign's own
process, which runs as root under sudo. It scans a file of any size in one
pass. Optional: pip install yara-x.

Callers only use the Engine interface below, so another engine can be
added later without changing them.
"""
from __future__ import annotations

from dataclasses import dataclass


class RuleError(Exception):
    """The engine refused the rules (a syntax or compile error)."""


class ScanFailed(Exception):
    """The scan didn't finish: a timeout, or the file couldn't be read."""


@dataclass(frozen=True)
class Hit:
    rule: str            # the rule's identifier
    meta: dict           # the rule's meta: section
    offset: int | None   # where the first match starts, if the engine says


class Engine:
    name = "base"
    version = ""

    def compile(self, source: str):
        raise NotImplementedError

    def scan_file(self, rules, path: str, timeout: int) -> list[Hit]:
        raise NotImplementedError

    def scan_bytes(self, rules, data: bytes) -> list[Hit]:
        raise NotImplementedError

    @property
    def label(self) -> str:
        return f"{self.name} {self.version}".strip()


class YaraX(Engine):
    name = "yara-x"

    def __init__(self, module) -> None:
        self.yx = module
        try:  # the module itself has no __version__; the installed package records it
            from importlib.metadata import version
            self.version = version("yara-x")
        except Exception:
            self.version = ""

    def compile(self, source: str):
        try:
            return self.yx.compile(source)
        except self.yx.CompileError as exc:
            raise RuleError(str(exc)) from None

    def _hits(self, results) -> list[Hit]:
        hits = []
        for rule in results.matching_rules:
            offsets = [m.offset for p in rule.patterns for m in p.matches]
            hits.append(Hit(rule.identifier, dict(rule.metadata), min(offsets) if offsets else None))
        return hits

    def scan_file(self, rules, path: str, timeout: int) -> list[Hit]:
        scanner = self.yx.Scanner(rules)
        scanner.set_timeout(timeout)
        try:
            return self._hits(scanner.scan_file(path))
        except self.yx.TimeoutError:
            raise ScanFailed(f"YARA didn't finish within {timeout}s") from None
        except self.yx.ScanError as exc:
            raise ScanFailed(str(exc)) from None

    def scan_bytes(self, rules, data: bytes) -> list[Hit]:
        return self._hits(self.yx.Scanner(rules).scan(data))


def find() -> Engine | None:
    """yara-x if it is installed, else None."""
    try:
        import yara_x
    except ImportError:
        return None
    return YaraX(yara_x)


MISSING = "yara-x isn't installed (pip install yara-x)"
