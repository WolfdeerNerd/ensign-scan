#!/usr/bin/env python3
"""Would "new author + new network fetch" have caught a hijacked AUR package?

In June 2026 attackers adopted orphaned AUR packages and added a line to
their build scripts that installed a malicious npm package. Your AUR
helper keeps a git clone of every package it built (~/.cache/yay/<pkg>,
~/.cache/paru/clone/<pkg>), so the history of each build script is
already on your disk. This probe walks that history, read-only, and
counts how often two signals fire:

  fetch       a commit adds a line to PKGBUILD or an .install script that
              fetches or runs more code (npm/bun/pnpm/yarn installs, pip,
              curl or wget piped to a shell, base64 piped to a shell...)
  new author  the commit's author email never appears earlier in that
              package's history (and the package had earlier commits)

The rule under test is both at once. The point is its false-positive rate
on your real packages: how many legitimate updates would have tripped it.

Limits, so the numbers aren't over-read:
  - Author emails are whatever the committer's own git said. The AUR checks
    the SSH key that pushed, not the author line, so an attacker can copy
    the previous maintainer's email. This catches attackers who don't.
  - Only packages you built, and only the history your clone has.
  - The fetch patterns are a starting list, easy to dodge on purpose.

Prints counts only, unless --show (package names and the matching lines).
Runs `git log` on the cached clones with external diff tools, textconv and
pagers turned off; changes nothing. Standard library only, plus git.

    python experiments/aur-builds/aur_history_probe.py
    python experiments/aur-builds/aur_history_probe.py --show
    python experiments/aur-builds/aur_history_probe.py --cache /some/other/clone/folder
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

# A line that fetches or runs more code during a build or install.
FETCH = re.compile(r"""
    \b(npm|pnpm|yarn|bun)\s+(install|i|add|ci)\b
  | \b(npx|bunx|pnpx)\s
  | \bpip3?\s+install\b
  | \b(curl|wget)\b[^|\n]*\|\s*(ba|z|da)?sh\b
  | \bbase64\s+(-d|--decode)\b[^|\n]*\|\s*(ba|z)?sh\b
  | \b(curl|wget)\b[^\n]*(&&|;)\s*chmod\s+\+?[0-7]*x
  | \beval\s+["']?\$\((curl|wget)\b
""", re.VERBOSE)
WATCHED = re.compile(r"(^|/)(PKGBUILD|[^/]*\.install)$")
# Safe git: no external diff, no textconv, no pager, no fsmonitor, no
# config from the clone that could run a program.
GIT = ["git", "-c", "core.fsmonitor=false", "-c", "core.pager=cat", "-c", "diff.external=",
       "--no-pager"]


@dataclass
class Commit:
    sha: str
    email: str
    date: str
    added: list[str] = field(default_factory=list)   # added lines in watched files


def clones(caches: list[Path]) -> list[Path]:
    found = []
    for cache in caches:
        if not cache.is_dir():
            continue
        for d in sorted(cache.iterdir()):
            if (d / ".git").exists() and not d.is_symlink():
                found.append(d)
    return found


def history(repo: Path) -> list[Commit]:
    """Oldest first: each commit's author and the lines it added to watched files."""
    out = subprocess.run(
        [*GIT, "-C", str(repo), "log", "--reverse", "--no-color", "--no-ext-diff", "--no-textconv",
         "--format=\x01%H\x02%ae\x02%aI", "-p", "--unified=0", "--", "PKGBUILD", "*.install"],
        capture_output=True, timeout=120, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
    if out.returncode != 0:
        raise RuntimeError(out.stderr.decode(errors="replace").strip()[:200])
    commits, current, watched = [], None, False
    for raw in out.stdout.decode("utf-8", "replace").splitlines():
        if raw.startswith("\x01"):
            sha, email, date = raw[1:].split("\x02")
            current = Commit(sha, email.strip().lower(), date)
            commits.append(current)
        elif raw.startswith("+++ "):
            watched = bool(WATCHED.search(raw[4:].removeprefix("b/")))
        elif raw.startswith("+") and current is not None and watched:
            current.added.append(raw[1:])
    return commits


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    home = Path.home()
    ap.add_argument("--cache", type=Path, action="append", default=[],
                    help="a folder of package clones (default: yay's and paru's)")
    ap.add_argument("--show", action="store_true", help="print package names and matching lines")
    args = ap.parse_args()
    caches = args.cache or [home / ".cache/yay", home / ".cache/paru/clone", home / ".cache/pikaur/aur_repos",
                            home / ".cache/trizen"]

    repos = clones(caches)
    if not repos:
        print("No cached AUR clones found. Pass --cache FOLDER.")
        return 1
    tally, now_fetching = Counter(), 0
    for repo in repos:
        try:
            commits = history(repo)
        except (RuntimeError, OSError, subprocess.TimeoutExpired) as e:
            tally["packages git couldn't read"] += 1
            if args.show:
                print(f"  (couldn't read {repo.name}: {e})")
            continue
        tally["packages"] += 1
        tally["commits"] += len(commits)
        tally["packages with one commit only"] += len(commits) == 1
        authors_before: set[str] = set()
        for i, c in enumerate(commits):
            fetch_lines = [line for line in c.added if FETCH.search(line)]
            new_author = i > 0 and c.email not in authors_before
            first = i == 0
            tally["first commits that add a fetch"] += first and bool(fetch_lines)
            tally["later commits that add a fetch"] += (not first) and bool(fetch_lines)
            tally["commits by a new author"] += new_author
            if new_author and fetch_lines:
                tally["RULE FIRES: new author + new fetch"] += 1
                tally["  ...of them the newest commit (what you'd build next)"] += i == len(commits) - 1
                if args.show:
                    print(f"  {repo.name}  {c.date[:10]}  {c.sha[:10]}")
                    for line in fetch_lines[:3]:
                        print(f"      + {line.strip()[:120]}")
            authors_before.add(c.email)
        # The naive rule, for comparison: was a fetch ever added to the build script?
        if commits and any(FETCH.search(line) for c in commits for line in c.added):
            now_fetching += 1

    print(f"Clones found in: {', '.join(str(c) for c in caches if c.is_dir())}"
          if args.show else f"Cache folders with clones: {sum(1 for c in caches if c.is_dir())}")
    for key in ("packages", "packages git couldn't read", "packages with one commit only", "commits",
                "first commits that add a fetch", "later commits that add a fetch", "commits by a new author",
                "RULE FIRES: new author + new fetch", "  ...of them the newest commit (what you'd build next)"):
        print(f"  {key}: {tally[key]}")
    print(f"\nFor comparison, the naive rule (any fetch ever added): {now_fetching} of "
          f"{tally['packages']} packages would be flagged.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
