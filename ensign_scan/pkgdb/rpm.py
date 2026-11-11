"""rpm backend: Fedora, RHEL and its rebuilds, openSUSE, Mageia, ...

  owner:   rpm -qf <path>     which package owns this file
  verify:  rpm -Va --nodeps   every installed file vs. its recorded digest

Both are read-only. --nodeps skips rpm's dependency check, which isn't
about files and would add "Unsatisfied dependencies" lines to the output.
"""
from __future__ import annotations

import os
import shutil
import subprocess

from . import verifyfmt
from .base import UNPARSED_KEPT, Backend, FileMismatch, VerifyResult, c_locale_env

# %{=NAME} repeats the package name for every file in the [...] loop.
_ALL_FILES_QF = "[%{FILENAMES}\t%{=NAME}\n]"


def available() -> bool:
    return shutil.which("rpm") is not None


def _parent_resolved(path: str) -> str:
    """Resolve the directories but not the file (see dpkg._parent_resolved)."""
    head, tail = os.path.split(path)
    return os.path.join(os.path.realpath(head or "/"), tail)


def _query_owner(path: str, timeout: float) -> tuple[str, str | None]:
    try:
        result = subprocess.run(
            ["rpm", "-qf", "--qf", "%{NAME} %{VERSION}-%{RELEASE}\\n", "--", path],
            capture_output=True, text=True, timeout=timeout, env=c_locale_env(), errors="surrogateescape",
        )
    except (subprocess.TimeoutExpired, OSError):
        return ("unknown", None)
    text = result.stdout + result.stderr
    if result.returncode == 0 and result.stdout.strip():
        # A file shared by two packages (multilib) prints one line each;
        # the first is enough for "who owns this".
        return ("owned", result.stdout.strip().splitlines()[0])
    if "is not owned by any package" in text:
        return ("unowned", None)
    return ("unknown", None)


def owner(path: str, timeout: float = 10.0) -> tuple[str, str | None]:
    """Which installed package owns `path`. ("unknown", None) on any failure."""
    if not available():
        return ("unknown", None)
    state, package = _query_owner(path, timeout)
    resolved = _parent_resolved(path)
    if state != "owned" and resolved != path:
        retry = _query_owner(resolved, timeout)
        if retry[0] == "owned" or state == "unknown":
            return retry
    return (state, package)


def _all_owners(timeout: float) -> dict[str, str]:
    """{path: package} for every file of every package, in one query.

    rpm -V doesn't say which package a line belongs to. One full listing
    is faster and more reliable than an `rpm -qf` per finding: with
    several files sharing names across packages, per-file output can't
    always be matched back to the file that was asked about.
    """
    try:
        result = subprocess.run(["rpm", "-qa", "--qf", _ALL_FILES_QF], capture_output=True,
                                text=True, timeout=timeout, env=c_locale_env(), errors="surrogateescape")
    except (subprocess.TimeoutExpired, OSError):
        return {}
    owners: dict[str, str] = {}
    for line in result.stdout.splitlines():
        path, sep, package = line.rpartition("\t")
        if sep and path:
            owners.setdefault(path, package)
    return owners


def parse_verify(output: str, owners: dict[str, str]) -> VerifyResult:
    """Turn `rpm -Va` output into a VerifyResult (no commands run)."""
    mismatches: list[FileMismatch] = []
    candidates = parsed_lines = 0
    unparsed: list[str] = []
    for line in output.splitlines():
        if not verifyfmt.is_candidate(line):
            continue
        candidates += 1
        parsed = verifyfmt.parse_line(line)
        if parsed is None:
            if len(unparsed) < UNPARSED_KEPT:
                unparsed.append(line.strip())
            continue
        parsed_lines += 1
        package = owners.get(parsed.path, "(unknown package)")
        for reason in parsed.reasons:
            mismatches.append(FileMismatch(
                package=package, filepath=parsed.path, reason=reason,
                is_config=parsed.is_config,
                unverified=(reason == verifyfmt.UNREADABLE),
            ))
    return VerifyResult(mismatches=mismatches, candidate_line_count=candidates,
                        parsed_line_count=parsed_lines, unparsed=tuple(unparsed))


def verify_all(timeout: float | None = None) -> VerifyResult | None:
    """`rpm -Va --nodeps`, with each finding's package looked up afterwards.
    No time limit unless one is passed (see pacman.verify_all)."""
    if not available():
        return None
    try:
        result = subprocess.run(["rpm", "-Va", "--nodeps"], capture_output=True, text=True,
                                timeout=timeout, env=c_locale_env(), errors="surrogateescape")
    except subprocess.TimeoutExpired:
        return VerifyResult([], 0, error=f"rpm -Va did not finish within {timeout:.0f}s. It checks "
                                         f"every file of every installed package.")
    except OSError as exc:
        return VerifyResult([], 0, error=f"rpm -Va failed to run: {exc}")
    output = result.stdout + "\n" + result.stderr
    owners = _all_owners(timeout=120.0) if result.stdout.strip() else {}
    return parse_verify(output, owners)


class RpmBackend(Backend):
    """Fedora, RHEL and rebuilds, openSUSE, Mageia."""
    name = "rpm"
    label = "rpm"
    verify_all_command = "sudo rpm -Va"
    config_word = "config"

    def available(self) -> bool:
        return available()

    def owner(self, path: str) -> tuple[str, str | None]:
        return owner(path)

    def verify_all(self) -> VerifyResult | None:
        return verify_all()

    def verify_command(self, package: str) -> str | None:
        return f"rpm -V {package}"

    def explain_reason(self, reason: str) -> str | None:
        from .. import explanations
        return explanations.explain_package_reason(reason)
