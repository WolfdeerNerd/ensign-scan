#!/usr/bin/env python3
"""
bigfile_census.py -- EXPERIMENT, read-only. What is actually inside the
files ClamAV can't scan?

A raw-byte check (Ensign's sweep, or converted signatures) sees a file's
bytes as they sit on disk. Whether that is "close to clean" depends on how
the contents are stored:

  stored raw     contents sit there uncompressed: a raw-byte check sees
                 them, so its result means a lot
  openable       contents are packed with a common method (zlib, gzip, zip,
                 zstd, lz4, xz, bzip2): a tool could unpack them and hand
                 the pieces to ClamAV
  opaque         bytes look random and nothing recognisable is inside:
                 encrypted, or packed with a method only the game knows.
                 No generic tool can look inside

This samples each file (it does not read all of it) and reports which of
those it looks like. Standard library only.

Usage: bigfile_census.py FILE [FILE ...]
       find ~ -xdev -type f -size +2G -print0 | xargs -0 python bigfile_census.py
"""
from __future__ import annotations

import math
import re
import sys
import tarfile
import zipfile
import zlib
from collections import Counter
from pathlib import Path

WINDOW = 4 * 2**20      # bytes read per sample
SAMPLES = 48            # samples per file, evenly spread
HIGH_ENTROPY = 7.9      # bits per byte; 8.0 is perfectly random-looking

# Markers that are long enough to trust on sight.
MARKERS = {
    "zstd": b"\x28\xb5\x2f\xfd",
    "lz4": b"\x04\x22\x4d\x18",
    "xz": b"\xfd7zXZ\x00",
    "bzip2": b"BZh91AY&SY",
    "7z": b"7z\xbc\xaf\x27\x1c",
    "rar": b"Rar!\x1a\x07",
    "elf": b"\x7fELF\x02\x01\x01",
}
# Short markers that appear by chance, so each candidate is tested.
ZLIB = re.compile(rb"\x78[\x01\x5e\x9c\xda]")
GZIP = re.compile(rb"\x1f\x8b\x08")
ZIP = re.compile(rb"PK\x03\x04")
MZ = re.compile(rb"MZ")


def entropy(buf: bytes) -> float:
    """Shannon entropy in bits per byte: ~8 for compressed or encrypted
    data, noticeably lower for text, code and most uncompressed assets."""
    total = len(buf)
    return -sum(n / total * math.log2(n / total) for n in Counter(buf).values())


def inflates(buf: bytes, at: int, wbits: int) -> bool:
    """Does a real compressed stream start here? Try to unpack a little:
    chance matches fail almost at once, real streams keep producing output."""
    try:
        out = zlib.decompressobj(wbits).decompress(buf[at:at + 8192], 4096)
    except zlib.error:
        return False
    return len(out) >= 1024


def looks_like_zip_entry(buf: bytes, at: int) -> bool:
    if at + 30 > len(buf):
        return False
    method = int.from_bytes(buf[at + 8:at + 10], "little")
    name_len = int.from_bytes(buf[at + 26:at + 28], "little")
    return method in (0, 8, 9, 12, 14, 93, 95) and 0 < name_len < 512


def looks_like_pe(buf: bytes, at: int) -> bool:
    if at + 64 > len(buf):
        return False
    pe_at = at + int.from_bytes(buf[at + 60:at + 64], "little")
    return pe_at + 4 <= len(buf) and buf[pe_at:pe_at + 4] == b"PE\0\0"


def census(path: Path):
    size = path.stat().st_size
    count = min(SAMPLES, max(1, size // WINDOW))
    step = (size - WINDOW) // max(1, count - 1) if count > 1 else 0
    found: Counter = Counter()
    entropies = []
    with open(path, "rb") as fh:
        for i in range(count):
            fh.seek(i * step)
            buf = fh.read(WINDOW)
            if not buf:
                break
            entropies.append(entropy(buf))
            for name, marker in MARKERS.items():
                found[name] += buf.count(marker)
            found["zlib"] += sum(inflates(buf, m.start(), 15) for m in ZLIB.finditer(buf))
            found["gzip"] += sum(inflates(buf, m.start(), 31) for m in GZIP.finditer(buf))
            found["zip"] += sum(looks_like_zip_entry(buf, m.start()) for m in ZIP.finditer(buf))
            found["pe"] += sum(looks_like_pe(buf, m.start()) for m in MZ.finditer(buf))
    sampled = len(entropies) * WINDOW
    return size, sampled, entropies, +found


def standard_archive(path: Path) -> str | None:
    """Is the file itself a zip or a tar? Sampling can miss this: an archive
    of a few large, already-compressed members shows almost no markers."""
    try:
        if zipfile.is_zipfile(path):
            return "zip"
        if tarfile.is_tarfile(path):
            return "tar"
    except OSError:
        pass
    return None


def verdict(entropies, found, archive: str | None = None) -> str:
    if archive:
        return f"openable (a {archive} archive)"
    high = sum(e >= HIGH_ENTROPY for e in entropies) / len(entropies)
    packed = sum(n for k, n in found.items() if k not in ("pe", "elf"))
    if packed >= 20:
        return "openable (common compression inside)"
    if high >= 0.8:
        return "opaque (random-looking, nothing recognisable)"
    if high <= 0.2:
        return "stored raw (a raw-byte check sees the contents)"
    return "mixed (part raw, part random-looking)"


def main() -> int:
    paths = [Path(a) for a in sys.argv[1:]]
    if not paths:
        print(__doc__)
        return 2
    for path in paths:
        try:
            size, sampled, entropies, found = census(path)
        except OSError as err:
            print(f"{path}: could not be read ({err})")
            continue
        mean = sum(entropies) / len(entropies)
        high = sum(e >= HIGH_ENTROPY for e in entropies) / len(entropies)
        inside = ", ".join(f"{k} {n}" for k, n in found.most_common()) or "nothing recognised"
        print(f"{path}: {size / 2**30:.2f} GiB, sampled {sampled / 2**20:.0f} MiB")
        print(f"  {verdict(entropies, found, standard_archive(path))}")
        print(f"  entropy {mean:.2f} bits/byte, {high:.0%} of samples random-looking; "
              f"found in sample: {inside}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
