"""dpkg backend: Debian, Ubuntu and their derivatives (Mint, Pop!_OS, ...).

  owner:   dpkg-query -S <path>        which package lists this file
  verify:  dpkg --verify               every installed file vs. its MD5

Both are read-only. dpkg's integrity data is an MD5 per file
(/var/lib/dpkg/info/*.md5sums). MD5 is broken for deliberately crafted
collisions, so this catches accidental and careless changes, not an
attacker who builds a matching file on purpose. It is still the
distribution's own record, which is what this check compares against.
"""
from __future__ import annotations

import fnmatch
import os
import shutil
import subprocess
from pathlib import Path

from . import verifyfmt
from .base import Backend, FileMismatch, VerifyResult, c_locale_env

_CFG_FILE = Path("/etc/dpkg/dpkg.cfg")
_CFG_DIR = Path("/etc/dpkg/dpkg.cfg.d")


def available() -> bool:
    return shutil.which("dpkg") is not None and shutil.which("dpkg-query") is not None


def _parent_resolved(path: str) -> str:
    """The same file with its *directories* resolved, the file itself not.

    Debian and Ubuntu moved /bin, /lib, ... into /usr ("usrmerge"); /bin
    is now a symlink to /usr/bin, and dpkg records /usr/bin/ls, so it
    doesn't recognise /bin/ls. Resolving only the parent fixes that
    without following a symlinked *file* to its target, which would
    report the target's owner instead.
    """
    head, tail = os.path.split(path)
    return os.path.join(os.path.realpath(head or "/"), tail)


def _parse_search(stdout: str) -> dict[str, str]:
    """`dpkg-query -S` output -> {path: first owning package}.

    Lines look like "coreutils: /usr/bin/ls", "libc6:amd64: /usr/lib/...",
    or "pkg-a, pkg-b: /shared/path". Diversion lines ("diversion by X
    from: ...") are notes about a file, not owners, and are skipped.
    Package names can contain ":" (the architecture), so the split is on
    the first ": /", the start of the path.
    """
    owners: dict[str, str] = {}
    for line in stdout.splitlines():
        if line.startswith("diversion ") or ": /" not in line:
            continue
        packages, _, rest = line.partition(": /")
        first = packages.split(",")[0].strip()
        if first:
            owners.setdefault("/" + rest, first)
    return owners


def _search_with_answers(paths: list[str], timeout: float) -> tuple[dict[str, str], set[str]] | None:
    """dpkg-query -S for several paths at once: (owners, paths dpkg said
    nothing owns). None if the command couldn't run at all.

    dpkg-query treats its arguments as shell patterns, so a path containing
    "*" or "[" could match OTHER files. Only results whose path equals the
    one asked about are kept; nothing is ever matched by pattern.

    "Nothing owns it" counts only when dpkg says so in its own words for
    that path. dpkg-query exits non-zero for that AND for real failures (a
    damaged database), and a failure must come out as "unknown".
    """
    try:
        result = subprocess.run(["dpkg-query", "-S", "--", *paths], capture_output=True,
                                text=True, timeout=timeout, env=c_locale_env(), errors="surrogateescape")
    except (subprocess.TimeoutExpired, OSError):
        return None
    found = _parse_search(result.stdout)
    unowned = {p for p in paths if f"no path found matching pattern {p}" in result.stderr}
    return {p: found[p] for p in paths if p in found}, unowned


def _search(paths: list[str], timeout: float) -> dict[str, str] | None:
    """Owners only (see _search_with_answers)."""
    answer = _search_with_answers(paths, timeout)
    return None if answer is None else answer[0]


def _version(package: str, timeout: float) -> str | None:
    try:
        result = subprocess.run(["dpkg-query", "-W", "-f=${Version}", "--", package],
                                capture_output=True, text=True, timeout=timeout, env=c_locale_env(), errors="surrogateescape")
    except (subprocess.TimeoutExpired, OSError):
        return None
    return result.stdout.strip() if result.returncode == 0 and result.stdout.strip() else None


def owner(path: str, timeout: float = 10.0) -> tuple[str, str | None]:
    """Which installed package owns `path`. ("unknown", None) on any failure."""
    if not available():
        return ("unknown", None)
    candidates = list(dict.fromkeys([path, _parent_resolved(path)]))
    answer = _search_with_answers(candidates, timeout)
    if answer is None:
        return ("unknown", None)
    found, unowned = answer
    for candidate in candidates:
        if candidate in found:
            package = found[candidate]
            version = _version(package, timeout)
            return ("owned", f"{package} {version}" if version else package)
    if all(candidate in unowned for candidate in candidates):
        return ("unowned", None)
    # A pattern match for some other file (see _search_with_answers), or an
    # error dpkg reported in other words: either way, no real answer.
    return ("unknown", None)


def read_path_filters(cfg_file: Path = _CFG_FILE, cfg_dir: Path = _CFG_DIR) -> list[tuple[str, str]]:
    """dpkg's path-exclude / path-include settings, in the order dpkg reads them.

    dpkg reads the files in dpkg.cfg.d/ in name order, then dpkg.cfg. A
    setting may be written "path-exclude=/x/*" or "path-exclude /x/*".
    """
    try:
        files = sorted(p for p in cfg_dir.iterdir() if p.is_file()) if cfg_dir.is_dir() else []
    except OSError:  # unreadable: dpkg itself couldn't read it either, so nothing applies
        files = []
    files.append(cfg_file)
    filters: list[tuple[str, str]] = []
    for cfg in files:
        try:
            lines = cfg.read_text().splitlines()
        except OSError:
            continue
        for raw in lines:
            line = raw.strip()
            for option in ("path-exclude", "path-include"):
                if line.startswith(option):
                    value = line[len(option):].lstrip(" =\t").strip()
                    if value:
                        filters.append((option, value))
    return filters


def is_excluded(path: str, filters: list[tuple[str, str]]) -> bool:
    """dpkg's rule: the LAST pattern that matches decides. Its patterns
    are fnmatch globs where "*" also matches "/", as in Python's fnmatch."""
    excluded = False
    for option, pattern in filters:
        if fnmatch.fnmatchcase(path, pattern):
            excluded = option == "path-exclude"
    return excluded


def parse_verify(output: str, owners: dict[str, str], filters: list[tuple[str, str]]) -> VerifyResult:
    """Turn `dpkg --verify` output into a VerifyResult (no commands run)."""
    mismatches: list[FileMismatch] = []
    candidates = parsed_lines = 0
    for line in output.splitlines():
        if not verifyfmt.is_candidate(line):
            continue
        candidates += 1
        parsed = verifyfmt.parse_line(line)
        if parsed is None:
            continue
        parsed_lines += 1
        excluded = parsed.missing and is_excluded(parsed.path, filters)
        package = owners.get(parsed.path, "(unknown package)")
        for reason in parsed.reasons:
            mismatches.append(FileMismatch(
                package=package, filepath=parsed.path, reason=reason,
                is_config=parsed.is_config,
                unverified=(reason == verifyfmt.UNREADABLE),
                excluded=excluded,
            ))
    return VerifyResult(mismatches=mismatches, candidate_line_count=candidates,
                        parsed_line_count=parsed_lines)


def verify_all(timeout: float | None = None) -> VerifyResult | None:
    """`dpkg --verify`, with each finding's package looked up afterwards.
    No time limit unless one is passed (see pacman.verify_all)."""
    if not available():
        return None
    try:
        result = subprocess.run(["dpkg", "--verify"], capture_output=True, text=True,
                                timeout=timeout, env=c_locale_env(), errors="surrogateescape")
    except subprocess.TimeoutExpired:
        return VerifyResult([], 0, error=f"dpkg --verify did not finish within {timeout:.0f}s. It "
                                         f"checks every file of every installed package.")
    except OSError as exc:
        return VerifyResult([], 0, error=f"dpkg --verify failed to run: {exc}")

    output = result.stdout + "\n" + result.stderr
    filters = read_path_filters()
    # Look up packages only for files that will be shown individually:
    # excluded files are summarised by count, and on a minimal install
    # there can be thousands of them.
    wanted = []
    for line in output.splitlines():
        parsed = verifyfmt.parse_line(line)
        if parsed and not (parsed.missing and is_excluded(parsed.path, filters)):
            wanted.append(parsed.path)
    owners: dict[str, str] = {}
    for start in range(0, len(wanted), 200):  # keep each command line a sane length
        owners.update(_search(wanted[start:start + 200], timeout=60.0) or {})
    return parse_verify(output, owners, filters)


class DpkgBackend(Backend):
    """Debian, Ubuntu and derivatives."""
    name = "dpkg"
    label = "dpkg"
    verify_all_command = "sudo dpkg --verify"
    config_word = "config (conffile)"

    def available(self) -> bool:
        return available()

    def owner(self, path: str) -> tuple[str, str | None]:
        return owner(path)

    def verify_all(self) -> VerifyResult | None:
        return verify_all()

    def verify_command(self, package: str) -> str | None:
        return f"dpkg --verify {package}"

    def explain_reason(self, reason: str) -> str | None:
        from .. import explanations
        return explanations.explain_package_reason(reason)
