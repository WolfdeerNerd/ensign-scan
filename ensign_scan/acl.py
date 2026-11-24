"""Let exactly one other user read a file root owns: a POSIX ACL entry.

Classic permissions have three sets (owner, group, everyone else). With
root as the owner, "root writes, exactly one user reads" can't be said
with them: the group set reaches everyone in the group, and the last set
reaches every account. A POSIX ACL adds a named-user entry, which can.

Protected mode (protect.py) uses it so the user's own runs can read root's
copy of their config and decisions, and nobody else can.

The kernel takes an ACL as the `system.posix_acl_access` extended
attribute, in a small binary format (linux/posix_acl_xattr.h): a 4-byte
version (2), then 8 bytes per entry -- tag (u16), permissions (u16), id
(u32) -- sorted by tag, then id. Setting it updates the mode bits too:
owner from USER_OBJ, group bits from MASK (the most any named entry or
the group can get), others from OTHER. This is what `setfacl` writes;
doing it here means no dependency on the `acl` package.

grant() and revoke() add or remove one named-user entry and keep the rest
(the owner, group and other entries, any named groups). set_only() instead
makes the ACL exactly the owner plus one user, which is what protected mode
uses for its own files, so nothing inherited or set up earlier comes along.
"""
from __future__ import annotations

import errno
import os
import stat
import struct

XATTR = "system.posix_acl_access"
_VERSION = 2
_UNDEFINED = 0xFFFFFFFF

USER_OBJ, USER, GROUP_OBJ, GROUP, MASK, OTHER = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20

READ, EXECUTE = 4, 1


class ACLUnsupported(OSError):
    """The filesystem can't hold ACLs (EOPNOTSUPP)."""


def _entries(path: str) -> list[tuple[int, int, int]]:
    """The file's ACL as (tag, perm, id), or the three entries its mode
    stands for when it has none."""
    try:
        raw = os.getxattr(path, XATTR, follow_symlinks=False)
    except OSError as exc:
        if exc.errno == errno.ENODATA:
            mode = os.lstat(path).st_mode
            return [(USER_OBJ, (mode >> 6) & 7, _UNDEFINED),
                    (GROUP_OBJ, (mode >> 3) & 7, _UNDEFINED),
                    (OTHER, mode & 7, _UNDEFINED)]
        if exc.errno == errno.EOPNOTSUPP:
            raise ACLUnsupported(exc.errno, f"{path}: this filesystem doesn't support ACLs") from None
        raise
    version, = struct.unpack_from("<I", raw)
    if version != _VERSION or (len(raw) - 4) % 8:
        raise ValueError(f"{path}: unexpected ACL format")
    return [struct.unpack_from("<HHI", raw, off) for off in range(4, len(raw), 8)]


def _write(path: str, entries: list[tuple[int, int, int]]) -> None:
    named = [e for e in entries if e[0] in (USER, GROUP)]
    base = [e for e in entries if e[0] in (USER_OBJ, GROUP_OBJ, OTHER)]
    if not named:
        # Nothing beyond the mode left: drop the ACL, and give the group
        # bits back to the group (they showed the mask until now).
        try:
            os.removexattr(path, XATTR, follow_symlinks=False)
        except OSError as exc:
            if exc.errno != errno.ENODATA:
                raise
        perms = {tag: perm for tag, perm, _ in base}
        # fchmod on a descriptor opened without following a symlink: chmod's
        # own follow_symlinks=False isn't available on Linux before Python 3.13.
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            keep = stat.S_IMODE(os.fstat(fd).st_mode) & 0o7000
            os.fchmod(fd, keep | perms[USER_OBJ] << 6 | perms[GROUP_OBJ] << 3 | perms[OTHER])
        finally:
            os.close(fd)
        return
    group_obj = next(perm for tag, perm, _ in base if tag == GROUP_OBJ)
    mask = group_obj
    for _tag, perm, _id in named:
        mask |= perm
    full = base + named + [(MASK, mask, _UNDEFINED)]
    full.sort(key=lambda e: (e[0], e[2]))   # the kernel wants tag order, then id order
    blob = struct.pack("<I", _VERSION) + b"".join(struct.pack("<HHI", *e) for e in full)
    try:
        os.setxattr(path, XATTR, blob, follow_symlinks=False)
    except OSError as exc:
        if exc.errno == errno.EOPNOTSUPP:
            raise ACLUnsupported(exc.errno, f"{path}: this filesystem doesn't support ACLs") from None
        raise


def grant(path: str, uid: int, perm: int) -> None:
    """Give user `uid` exactly `perm` (READ, EXECUTE, or both) on `path`,
    replacing any entry it had. Never grants write."""
    if perm & ~(READ | EXECUTE):
        raise ValueError("acl.grant gives read and/or search only, never write")
    entries = [e for e in _entries(path) if not (e[0] == USER and e[2] == uid) and e[0] != MASK]
    entries.append((USER, perm, uid))
    _write(path, entries)


def set_only(path: str, uid: int, perm: int) -> None:
    """Make `path`'s ACL exactly: the owner as its mode says, user `uid`
    with `perm`, nobody else (no group, no other, no named entries). On a
    folder, also drop any default ACL, so nothing created inside inherits
    entries. For protected mode's own files, where an entry inherited from
    a default ACL on a folder above would otherwise let someone else read
    them once a named entry turns the mask on."""
    if perm & ~(READ | EXECUTE):
        raise ValueError("acl.set_only gives read and/or search only, never write")
    owner = (stat.S_IMODE(os.lstat(path).st_mode) >> 6) & 7
    _write(path, [(USER_OBJ, owner, _UNDEFINED), (USER, perm, uid),
                  (GROUP_OBJ, 0, _UNDEFINED), (OTHER, 0, _UNDEFINED)])
    if stat.S_ISDIR(os.lstat(path).st_mode):
        try:
            os.removexattr(path, "system.posix_acl_default", follow_symlinks=False)
        except OSError as exc:
            if exc.errno not in (errno.ENODATA, errno.EOPNOTSUPP):
                raise


def exactly(path: str, uid: int, perm: int) -> bool:
    """True if `path`'s ACL is what set_only() makes: no group or other
    access, and `uid` the only named entry, with `perm`."""
    entries = _entries(path)
    named = [(tag, p, id_) for tag, p, id_ in entries if tag in (USER, GROUP)]
    plain = {tag: p for tag, p, _ in entries if tag in (GROUP_OBJ, OTHER)}
    return named == [(USER, perm, uid)] and plain.get(GROUP_OBJ) == 0 and plain.get(OTHER) == 0


def revoke(path: str, uid: int) -> None:
    """Remove user `uid`'s entry from `path`, if it has one."""
    entries = _entries(path)
    if not any(tag == USER and id_ == uid for tag, _perm, id_ in entries):
        return
    _write(path, [e for e in entries if not (e[0] == USER and e[2] == uid) and e[0] != MASK])


def user_perm(path: str, uid: int) -> int | None:
    """User `uid`'s named entry on `path` (without the mask), or None."""
    for tag, perm, id_ in _entries(path):
        if tag == USER and id_ == uid:
            return perm
    return None


def named_users(path: str) -> dict[int, int]:
    """Every named-user entry on `path`: uid -> permissions."""
    return {id_: perm for tag, perm, id_ in _entries(path) if tag == USER}
