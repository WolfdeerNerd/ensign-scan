"""Can anyone besides root change what a path names?

Under sudo, Ensign must not read a config or write into a folder that
another user can change. If it did, anything running as that user (the
malware Ensign is looking for) could:

  * edit the config: add its own folder to `excludes` and hide from the
    root scan, or point `data_dir` anywhere on the system;
  * plant a symlink where root writes: root follows it and truncates or
    overwrites whatever file it points to (/etc/shadow, say);
  * swap the database for a crafted file, which root then parses.

So as root, every place Ensign reads its config from or writes to must pass
untrusted_reason(): the path and every folder above it are owned by root and
not writable by group or others. Symlinks along the way are allowed only if
root owns them, and their target is checked the same way. A part of the path
that doesn't exist yet is fine: it's inside a folder only root can write to,
and Ensign creates it with umask 077.

This mirrors OpenSSH's StrictModes, and git's refusal (since CVE-2022-24765)
to use a repository another user owns.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

_MAX_SYMLINKS = 40  # the kernel's own limit (MAXSYMLINKS)


def untrusted_reason(path: Path | str) -> str | None:
    """None if only root can change what `path` names, else the reason why not."""
    return _walk(os.path.abspath(path), 0)


def _walk(path: str, followed: int) -> str | None:
    if followed > _MAX_SYMLINKS:
        return f"{path}: too many symlinks"
    parts = Path(path).parts          # ("/", "var", "lib", ...)
    current = parts[0]
    st = os.lstat(current)
    why = _not_root_only(current, st)
    if why:
        return why
    shared = _is_shared(st)
    for i, part in enumerate(parts[1:], start=1):
        if part == ".":
            continue
        if part == "..":
            # Lexical is right here: `current` has no symlinks in it (each
            # one was replaced by its target), so its parent is the real one.
            current = os.path.dirname(current)
            shared = _is_shared(os.lstat(current))
            continue
        candidate = os.path.join(current, part)
        try:
            st = os.lstat(candidate)
        except FileNotFoundError:
            if shared:
                # In /tmp, say, anyone could create this name before root does.
                return f"{candidate} doesn't exist yet, and another user could create it first in {current}"
            return None   # the rest gets created by root, inside a root-only folder
        if stat.S_ISLNK(st.st_mode):
            if st.st_uid != 0:
                return f"{candidate} is a symlink owned by uid {st.st_uid}, not root"
            target = os.path.join(current, os.readlink(candidate))   # absolute target wins
            return _walk(os.path.join(target, *parts[i + 1:]), followed + 1)
        why = _not_root_only(candidate, st)
        if why:
            return why
        shared = _is_shared(st)
        current = candidate
    if shared:
        return f"{current} is shared: other users can create files in it"
    return None


def _is_shared(st: os.stat_result) -> bool:
    """A root-owned sticky folder others can write to, like /tmp."""
    return bool(st.st_mode & (stat.S_IWGRP | stat.S_IWOTH))


def _not_root_only(path: str, st: os.stat_result) -> str | None:
    """Why only-root can't be assumed for this one entry, or None.

    A root-owned folder with the sticky bit (like /tmp, mode 1777) may be
    writable by others: they can add entries, but can't rename or delete
    root's. So it's allowed on the way to something root already owns,
    never as the place itself, or above a name that doesn't exist yet
    (_walk checks both)."""
    if st.st_uid != 0:
        return f"{path} is owned by uid {st.st_uid}, not root"
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        if stat.S_ISDIR(st.st_mode) and st.st_mode & stat.S_ISVTX:
            return None
        return f"{path} can be changed by other users (mode {stat.S_IMODE(st.st_mode):o})"
    return None
