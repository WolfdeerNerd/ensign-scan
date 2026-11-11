"""Parser for the verify output format dpkg and rpm share.

`rpm -V` invented it and `dpkg --verify` copies it (dpkg calls it its
"rpm" verify format). Each line is one file that differs:

    S.5....T.  c /etc/ens.conf
    ??5?????? c /etc/adduser.conf
    missing     /usr/share/doc/coreutils/AUTHORS
    missing     /var/lib/polkit-1/localauthority (Permission denied)

  1. nine characters, one per test, or the word "missing"
  2. optionally a file-type marker: c = config file (rpm also uses
     d doc, g ghost, l license, r readme, a artifact)
  3. the path

The spacing between them differs: dpkg uses one space before the
marker, rpm two, and rpm's "missing" lines three. So the parser splits
on runs of spaces rather than on fixed columns.

A "missing" line can end in an error in brackets: dpkg couldn't even
look, usually because a parent directory is root-only. "Permission
denied" there means "not checked", not "gone". Only a real system error
message counts as that suffix -- a file can be named "notes (copy)", and
"(copy)" is part of its name.

In the test columns a letter means that test FAILED, "." means it passed
and "?" means it couldn't be done. Position 2 is the content checksum,
the one that decides whether the file was really checked:

    position  0 S size      3 D device    6 G group
              1 M mode      4 L symlink   7 T mtime
              2 5 checksum  5 U user      8 P capabilities

dpkg only implements the checksum test and prints "?" for the other
eight. So "?" only means "couldn't check" at position 2; anywhere else
it's ignored. Both layouts were checked against real output (dpkg 1.22,
rpm 4.18) when this was written.

Neither tool says which package a line belongs to; the backends look
that up separately.
"""
from __future__ import annotations

import errno
import os
import re
from dataclasses import dataclass

# Letter at each position -> the reason the report shows.
_TESTS = {
    0: ("S", "Size mismatch"),
    1: ("M", "Mode mismatch"),
    2: ("5", "Checksum mismatch"),
    3: ("D", "Device number mismatch"),
    4: ("L", "Symlink path mismatch"),
    5: ("U", "Owner mismatch"),
    6: ("G", "Group mismatch"),
    7: ("T", "Modification time mismatch"),
    8: ("P", "Capabilities mismatch"),
}
MISSING = "File missing"
UNREADABLE = "Could not read file"

_LINE_RE = re.compile(r"^(?P<flags>[SM5DLUGTP.?]{9}|missing) +(?:(?P<marker>[cdglra]) +)?(?P<path>/.*)$")
# "(Permission denied)" and other errno texts dpkg appends to "missing" lines
_ERRNO_SUFFIX_RE = re.compile(r"^(?P<path>/.*) \((?P<error>[^()]+)\)$")
# Every message the C library can produce for a system error, in English:
# dpkg runs in the C locale (base.c_locale_env), and Python doesn't apply
# the user's language to os.strerror(). Only these count as an error suffix.
_ERRNO_MESSAGES = frozenset(os.strerror(code) for code in errno.errorcode)


@dataclass(frozen=True)
class VerifyLine:
    path: str
    # Reasons in the report's words, in column order. Empty never happens:
    # a line is only printed when something differs or couldn't be checked.
    reasons: tuple[str, ...]
    is_config: bool
    missing: bool
    unreadable: bool


def is_candidate(line: str) -> bool:
    """Could this line be a finding? Used for the parser sanity check:
    anything ending in an absolute path that isn't an error message."""
    stripped = line.strip()
    if not stripped or stripped.startswith(("error:", "warning:", "dpkg:", "dpkg-query:", "rpm:")):
        return False
    return " /" in stripped


def parse_line(line: str) -> VerifyLine | None:
    """One verify line, or None if it isn't in the expected shape."""
    match = _LINE_RE.match(line.rstrip("\n"))
    if not match:
        return None
    flags, marker, path = match["flags"], match["marker"], match["path"]
    is_config = marker == "c"
    if flags == "missing":
        suffix = _ERRNO_SUFFIX_RE.match(path)
        if suffix and suffix["error"] in _ERRNO_MESSAGES:
            path = suffix["path"]
            if suffix["error"] == "Permission denied":
                return VerifyLine(path, (UNREADABLE,), is_config, missing=False, unreadable=True)
        return VerifyLine(path, (MISSING,), is_config, missing=True, unreadable=False)
    reasons = [reason for pos, (letter, reason) in _TESTS.items() if flags[pos] == letter]
    unreadable = flags[2] == "?"
    if unreadable:
        reasons.append(UNREADABLE)
    if not reasons:
        return None  # nothing failed and nothing unreadable: not a line either tool prints
    return VerifyLine(path, tuple(reasons), is_config, missing=False, unreadable=unreadable)
