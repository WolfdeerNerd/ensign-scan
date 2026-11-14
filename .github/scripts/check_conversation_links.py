"""Fail if a pull request's title, description or commit messages hold a
link to a private claude.ai page: a conversation, a Claude Code session,
a shared chat, a project or an artifact.

Those are working notes, and this repository is public: a link published
here stays in GitHub's history even after it is edited out. The check
runs in .github/workflows/pr-text.yml, on every pull request and again
whenever its title or description is edited.

Input, both files written by the workflow with `gh api`:
  argv[1]   the pull request itself (its "title" and "body")
  argv[2]   GitHub's "list commits on a pull request" response, every
            page, as `gh api --paginate --slurp` writes it

The title and description are read from a file, not handed over in
environment variables: the runner prints a step's environment in its
log, so a link there would be published by the very check meant to
catch it. For the same reason only WHERE a link was found is printed,
never the link itself: the logs of a public repository's Actions runs
are public too.

Run by hand:
  gh api repos/OWNER/REPO/pulls/N > pr.json
  gh api --paginate --slurp repos/OWNER/REPO/pulls/N/commits > commits.json
  python3 .github/scripts/check_conversation_links.py pr.json commits.json
"""
from __future__ import annotations

import json
import re
import sys

# What counts as a conversation link. Generic product links stay allowed
# (claude.com/claude-code, a bare claude.ai/code): they point at no one's
# conversation.
PATTERN = re.compile(
    r"claude\.ai/(?:code/)?(?:session_|chat/|share/|project/|artifact/)"
    r"|\bsession_01[0-9A-Za-z]{10,}"   # a session id, even without the URL
    r"|^[ \t]*Claude-Session:",        # the commit trailer Claude Code adds
    re.IGNORECASE | re.MULTILINE,
)


def lines_with_links(text: str | None) -> list[int]:
    """1-based numbers of the lines in `text` holding a conversation link."""
    if not text:
        return []
    return sorted({text.count("\n", 0, m.start()) + 1 for m in PATTERN.finditer(text)})


def pull_from(path: str) -> tuple[str | None, str | None]:
    """The pull request's (title, description). GitHub sends no description
    at all (null) when it was left empty."""
    with open(path, encoding="utf-8") as f:
        pull = json.load(f)
    return pull.get("title"), pull.get("body")


def commits_from(path: str) -> list[dict]:
    """The commits from the slurped API response: a list of pages, each a
    list of commits (a single flat list is accepted too)."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if data and isinstance(data[0], list):
        return [c for page in data for c in page]
    return data


def findings(title: str | None, body: str | None, commits: list[dict]) -> list[str]:
    """One line per place a link was found, naming the place, not the link."""
    found = []
    if lines_with_links(title):
        found.append("PR title")
    lines = lines_with_links(body)
    if lines:
        found.append(f"PR description, line {', '.join(map(str, lines))}")
    for commit in commits:
        lines = lines_with_links(commit.get("commit", {}).get("message"))
        if lines:
            found.append(f"commit {commit.get('sha', '?')[:12]}, message line {', '.join(map(str, lines))}")
    return found


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: check_conversation_links.py PR_JSON COMMITS_JSON", file=sys.stderr)
        return 2
    title, body = pull_from(argv[1])
    found = findings(title, body, commits_from(argv[2]))
    if not found:
        print("No conversation links in the title, description or commit messages.")
        return 0
    print("A link to a private claude.ai page (a conversation, session, project or "
          "artifact) is in this pull request. This repository is public, so it must "
          "come out before merging:")
    for place in found:
        print(f"  - {place}")
        print(f"::error::Conversation link in {place}")
    print("\nThe description or title: edit it on GitHub (this check runs again by "
          "itself). Then delete the old version from the description's \"edited\" "
          "history, which keeps it visible.\n"
          "A commit message: reword the commit (git rebase -i, or git commit --amend "
          "for the last one) and force-push the branch.")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
