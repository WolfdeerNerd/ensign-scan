"""Fail if a home-directory path naming a real account is about to be
published: in the repository's files, or in a pull request's title,
description or commit messages.

A path like /home/NAME/... gives away a username, and often more (which
folders exist, what is installed). This repository is public, so such a
path belongs in neither the code nor the pull requests. Pasted terminal
output and tracebacks are how one usually gets in.

What is flagged: /home/NAME, /Users/NAME and C:\\Users\\NAME, unless NAME
is one of the stand-ins in PLACEHOLDERS (/home/user, /home/you, ...).
Forms with no name in them ("~", "$HOME", "/home/<name>", "/home/$USER")
are never flagged.

Two ways to run it:

  python3 .github/scripts/check_personal_info.py --files [DIR]
      Every file git tracks under DIR (default: the current directory).
      Without git, every file found there, minus build and cache folders.
      Runs in the "lint" job of .github/workflows/tests.yml.

  python3 .github/scripts/check_personal_info.py PR_JSON COMMITS_JSON
      A pull request's title, description and commit messages, from the
      same two files check_conversation_links.py reads. Runs in
      .github/workflows/pr-text.yml.

Only WHERE a path was found is printed, never the path: the logs of a
public repository's Actions runs are public too, so printing it would
publish the very thing this check is meant to catch.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_conversation_links import commits_from, pull_from  # noqa: E402

# Stand-in account names that may follow /home/ and friends. Lower case;
# the comparison ignores case. Add to this list when documentation or a
# test needs a new stand-in.
PLACEHOLDERS = frozenset({
    "user", "username", "you", "yourname", "name", "me", "u", "w",
    "example", "alice", "bob",
})

# The account name: letters, digits, "_" and "-", with dots only inside it,
# so the full stop ending a sentence ("... lives in /home/user.") is not
# taken as part of the name.
_NAME = r"([A-Za-z0-9_][A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]+)*)"
PATTERN = re.compile(r"(?:/home/|/Users/|\b[A-Za-z]:\\Users\\)" + _NAME)

# Skipped when walking a folder that isn't a git checkout.
_SKIP_DIRS = {".git", "__pycache__", "dist", "build", ".venv", "venv", ".ruff_cache", ".mypy_cache"}
_MAX_BYTES = 5 * 1024 * 1024   # larger files aren't source or docs


def lines_with_paths(text: str | None) -> list[int]:
    """1-based numbers of the lines in `text` holding a home-directory path
    with a name that isn't a placeholder."""
    if not text:
        return []
    return sorted({text.count("\n", 0, m.start()) + 1 for m in PATTERN.finditer(text)
                   if m.group(1).lower() not in PLACEHOLDERS})


def tracked_files(root: str) -> list[str]:
    """Paths (relative to `root`) of the files to check."""
    try:
        out = subprocess.run(["git", "-C", root, "ls-files", "-z"], capture_output=True, check=True)
        return sorted(os.fsdecode(p) for p in out.stdout.split(b"\0") if p)
    except (OSError, subprocess.CalledProcessError):
        pass   # no git, or not a checkout: walk the folder instead
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.endswith(".egg-info")]
        found += [os.path.relpath(os.path.join(dirpath, name), root) for name in filenames]
    return sorted(found)


def file_findings(root: str) -> list[str]:
    """One "file, line N" per place a path was found under `root`."""
    found = []
    for rel in tracked_files(root):
        path = os.path.join(root, rel)
        try:
            if os.path.islink(path) or not os.path.isfile(path) or os.path.getsize(path) > _MAX_BYTES:
                continue
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            continue
        lines = lines_with_paths(text)
        if lines:
            found.append(f"{rel}, line {', '.join(map(str, lines))}")
    return found


def text_findings(title: str | None, body: str | None, commits: list[dict]) -> list[str]:
    """One line per place a path was found in a pull request's text."""
    found = []
    if lines_with_paths(title):
        found.append("PR title")
    lines = lines_with_paths(body)
    if lines:
        found.append(f"PR description, line {', '.join(map(str, lines))}")
    for commit in commits:
        lines = lines_with_paths(commit.get("commit", {}).get("message"))
        if lines:
            found.append(f"commit {commit.get('sha', '?')[:12]}, message line {', '.join(map(str, lines))}")
    return found


def main(argv: list[str]) -> int:
    if len(argv) in (2, 3) and argv[1] == "--files":
        found = file_findings(argv[2] if len(argv) == 3 else ".")
        where, fix = "this repository's files", (
            "Replace the name with a stand-in (/home/user, ~, $HOME). If the name is itself a "
            "stand-in, add it to PLACEHOLDERS in .github/scripts/check_personal_info.py.")
    elif len(argv) == 3:
        title, body = pull_from(argv[1])
        found = text_findings(title, body, commits_from(argv[2]))
        where, fix = "this pull request", (
            "The description or title: edit it on GitHub (this check runs again by itself). "
            "Then delete the old version from the description's \"edited\" history, which "
            "keeps it visible.\nA commit message: reword the commit (git rebase -i, or git "
            "commit --amend for the last one) and force-push the branch.")
    else:
        print("usage: check_personal_info.py --files [DIR]\n"
              "       check_personal_info.py PR_JSON COMMITS_JSON", file=sys.stderr)
        return 2
    if not found:
        print(f"No home-directory paths with a real name in {where}.")
        return 0
    print(f"A home-directory path naming an account (/home/NAME, /Users/NAME or C:\\Users\\NAME) "
          f"is in {where}. This repository is public, so it must come out before merging:")
    for place in found:
        print(f"  - {place}")
        print(f"::error::Home-directory path in {place}")
    print("\n" + fix)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
