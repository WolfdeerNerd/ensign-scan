#!/usr/bin/env python3
"""
ndb_yara_proto.py -- EXPERIMENT, not part of Ensign.

Question being tested: can files over ClamAV's ~2 GiB ceiling be checked in
one pass, using ClamAV's own body signatures, by translating them into YARA
rules and letting yara-x do the matching?

What it does
  1. Reads ClamAV's databases (*.cvd / *.cld / loose *.ndb), read-only.
  2. Translates each .ndb "extended signature" into one YARA rule.
     Anything it cannot translate faithfully is skipped and counted --
     never guessed at.
  3. Puts the rules in buckets by ClamAV target type (any file / PE / ELF)
     and compiles each bucket, in memory, on every run.
  4. Scans files with the "any file" bucket plus the bucket for their type.

What it does NOT do (so a quiet result here never means "clean")
  - no unpacking: nothing inside archives, installers or images is seen
  - no .ldb logical signatures, no hash signatures, no bytecode
  - no target types that ClamAV normalises first (HTML, text, mail)

The compiled rules are never saved to disk. A file of compiled rules holds
the raw bytes of every signature, so ClamAV reports it as infected: an
earlier version cached them, and Ensign flagged the cache.

Needs: Python 3.11+, yara-x  (pip install yara-x)

Usage
  ndb_yara_proto.py [--db /var/lib/clamav] FILE [FILE ...]
  ndb_yara_proto.py --stats            # convert + compile only, show numbers
  ndb_yara_proto.py --dump-rules DIR   # also write the generated .yar files
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import tarfile
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import yara_x

# A pattern needs at least this many fully-known bytes in a row somewhere.
# Shorter anchors make the matcher stop constantly to check false candidates.
MIN_FIXED_RUN = 4

# ClamAV drops a signature whose "max functionality level" is below the
# engine's. Every engine from the last several years is far above the old
# values that appear in that field, so a MaxFL below this means "retired".
ASSUMED_ENGINE_FLEVEL = 200

# ClamAV target type -> our bucket. Types that are missing here are skipped:
# 3 (HTML), 4 (mail) and 7 (text) are matched by ClamAV against a normalised
# copy of the file, so the same bytes are not in the raw file.
BUCKETS = {"0": "any", "1": "pe", "6": "elf"}
MODULE_FOR_BUCKET = {"any": None, "pe": "pe", "elf": "elf"}


class Skip(Exception):
    """This signature can't be translated faithfully; the message says why."""


# --------------------------------------------------------------------------
# 1. Reading ClamAV's databases
# --------------------------------------------------------------------------

def read_databases(db_dir: Path):
    """Return (ndb_lines, ignored_names).

    A .cvd/.cld file is a 512-byte text header followed by a tar archive
    (gzip-compressed in a .cvd). Members are read straight from the archive
    into memory; nothing is extracted to disk.
    """
    ndb_lines: list[tuple[str, str]] = []      # (source file, line)
    ignored: set[str] = set()

    def take(name: str, data: bytes):
        text = data.decode("latin-1")
        if name.endswith(".ndb"):
            ndb_lines.extend((name, ln) for ln in text.splitlines() if ln.strip())
        elif name.endswith(".ign2"):       # "SigName" or "SigName:md5"
            ignored.update(ln.split(":")[0].strip() for ln in text.splitlines())
        elif name.endswith(".ign"):        # "dbfile:line:SigName"
            ignored.update(ln.split(":")[-1].strip() for ln in text.splitlines())

    for path in sorted(db_dir.iterdir()):
        if not path.is_file():
            continue
        suffix = path.suffix.lower()
        if suffix in (".cvd", ".cld"):
            with open(path, "rb") as fh:
                fh.seek(512)
                with tarfile.open(fileobj=fh, mode="r|*") as tar:
                    for member in tar:
                        if member.isfile() and member.name.endswith((".ndb", ".ign", ".ign2")):
                            take(os.path.basename(member.name), tar.extractfile(member).read())
        elif suffix in (".ndb", ".ign", ".ign2"):
            take(path.name, path.read_bytes())

    return ndb_lines, ignored


# --------------------------------------------------------------------------
# 2. Translating one signature
# --------------------------------------------------------------------------
#
# ClamAV .ndb line:   Name:TargetType:Offset:HexSignature[:MinFL[:MaxFL]]
#
# HexSignature pieces and their YARA hex-string equivalents:
#   41          byte                     41
#   ??  4?  ?1  any byte / half a byte   ??  4?  ?1
#   *           any number of bytes      [-]
#   {n}         exactly n bytes          [n]
#   {-n}        n bytes or fewer         [0-n]
#   {n-}        n bytes or more          [n-]
#   {n-m}       n to m bytes             [n-m]
#   [n-m]       same idea, older form    [n-m]
#   (aa|bbcc)   one of these             ( AA | BB CC )
#   !(aa|bb)    none of these            -- skipped
#   (B) (L) (W) word/line boundaries     -- skipped

_BYTE = re.compile(r"[0-9a-fA-F?]{2}")


def parse_hex(sig: str, inside_alt: bool = False) -> list:
    """Turn a ClamAV hex signature into tokens:
    ("b", "4A") byte, ("j", lo, hi_or_None) jump, ("alt", [tokens, ...])."""
    out: list = []
    i, n = 0, len(sig)
    while i < n:
        ch = sig[i]
        if ch == "*":
            out.append(("j", 0, None))
            i += 1
        elif ch in "{[":
            close = "}" if ch == "{" else "]"
            end = sig.find(close, i)
            if end < 0:
                raise Skip("malformed gap")
            out.append(("j", *_parse_range(sig[i + 1:end])))
            i = end + 1
        elif ch == "!":
            raise Skip("negated alternative")
        elif ch == "(":
            end = _matching_paren(sig, i)
            inner = sig[i + 1:end]
            if inner in ("B", "L", "W"):
                raise Skip("boundary marker")
            alts = [parse_hex(part, inside_alt=True) for part in _split_alts(inner)]
            if any(not a for a in alts):
                raise Skip("empty alternative")
            out.append(("alt", alts))
            i = end + 1
        elif _BYTE.match(sig, i):
            out.append(("b", sig[i:i + 2].upper()))
            i += 2
        else:
            raise Skip("malformed hex")

    # Neighbouring gaps add up: {2}{3} is {5}.
    merged: list = []
    for tok in out:
        if tok[0] == "j" and merged and merged[-1][0] == "j":
            _, lo, hi = merged[-1]
            hi = None if hi is None or tok[2] is None else hi + tok[2]
            merged[-1] = ("j", lo + tok[1], hi)
        else:
            merged.append(tok)

    if not merged:
        raise Skip("empty signature")
    if merged[0][0] == "j" or merged[-1][0] == "j":
        raise Skip("gap at start or end")
    if inside_alt and any(t[0] == "j" and t[2] is None for t in merged):
        raise Skip("unbounded gap inside alternative")
    return merged


def _parse_range(text: str) -> tuple[int, int | None]:
    try:
        if "-" not in text:
            return int(text), int(text)
        lo, hi = text.split("-", 1)
        return (int(lo) if lo else 0), (int(hi) if hi else None)
    except ValueError:
        raise Skip("malformed gap") from None


def _matching_paren(sig: str, start: int) -> int:
    depth = 0
    for i in range(start, len(sig)):
        if sig[i] == "(":
            depth += 1
        elif sig[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    raise Skip("unbalanced parentheses")


def _split_alts(inner: str) -> list[str]:
    parts, depth, cur = [], 0, []
    for ch in inner:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "|" and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return parts


def render_hex(tokens: list) -> str:
    parts = []
    for tok in tokens:
        if tok[0] == "b":
            parts.append(tok[1])
        elif tok[0] == "j":
            _, lo, hi = tok
            parts.append(f"[{lo}]" if lo == hi else f"[{lo}-{'' if hi is None else hi}]")
        else:
            parts.append("( " + " | ".join(render_hex(a) for a in tok[1]) + " )")
    return " ".join(parts)


def longest_fixed_run(tokens: list) -> int:
    best = run = 0
    for tok in tokens:
        run = run + 1 if tok[0] == "b" and "?" not in tok[1] else 0
        best = max(best, run)
    return best


_OFFSET = re.compile(
    r"^(?:(?P<abs>\d+)"
    r"|EOF-(?P<eof>\d+)"
    r"|EP(?P<ep>[+-]\d+)"
    r"|S(?P<sec>\d+)\+(?P<secoff>\d+)"
    r"|SL\+(?P<last>\d+)"
    r"|SE(?P<whole>\d+))"
    r"(?:,(?P<shift>\d+))?$"
)


def render_condition(offset: str, bucket: str) -> str:
    """ClamAV's Offset field -> a YARA condition on where $a may start."""
    if offset == "*":
        return "$a"
    m = _OFFSET.match(offset)
    if not m:
        raise Skip("unknown offset form")
    shift = m["shift"]

    if m["abs"] is not None:
        base = m["abs"]
    elif m["eof"] is not None:
        base = f"filesize - {m['eof']}"
    else:
        # The remaining forms depend on the executable's layout, which YARA's
        # pe / elf modules read for us.
        if bucket == "any":
            raise Skip("executable-relative offset on a non-executable target")
        if m["ep"] is not None:
            base = f"{bucket}.entry_point {m['ep'][0]} {m['ep'][1:]}"
        else:
            start, size = (
                ("raw_data_offset", "raw_data_size") if bucket == "pe" else ("offset", "size")
            )
            if m["sec"] is not None:
                base = f"{bucket}.sections[{m['sec']}].{start} + {m['secoff']}"
            elif m["last"] is not None:
                base = (f"{bucket}.sections[{bucket}.number_of_sections - 1].{start}"
                        f" + {m['last']}")
            else:   # SEx: anywhere inside section x
                sec = f"{bucket}.sections[{m['whole']}]"
                return f"$a in ({sec}.{start}..{sec}.{start} + {sec}.{size})"

    if shift is None:
        return f"$a at {base}"
    return f"$a in ({base}..{base} + {shift})"


@dataclass
class Converted:
    bucket: str
    name: str
    source: str
    hex: str
    condition: str

    def rule(self, ident: str) -> str:
        name = self.name.replace("\\", "\\\\").replace('"', '\\"')
        return (
            f"rule {ident} {{\n"
            f'  meta:\n    clamav_name = "{name}"\n    source = "{self.source}"\n'
            f"  strings:\n    $a = {{ {self.hex} }}\n"
            f"  condition:\n    {self.condition}\n}}\n"
        )


def convert_line(source: str, line: str, ignored: set[str]) -> Converted:
    fields = line.strip().split(":")
    if len(fields) < 4:
        raise Skip("malformed line")
    name, target, offset, hexsig = fields[:4]
    if name in ignored:
        raise Skip("disabled by ClamAV's ignore list")
    if len(fields) > 5 and fields[5].isdigit() and int(fields[5]) < ASSUMED_ENGINE_FLEVEL:
        raise Skip("retired (max functionality level)")
    bucket = BUCKETS.get(target)
    if bucket is None:
        raise Skip(f"target type {target} not handled")
    tokens = parse_hex(hexsig)
    if longest_fixed_run(tokens) < MIN_FIXED_RUN:
        raise Skip("too weak (short fixed part)")
    return Converted(bucket, name, source, render_hex(tokens), render_condition(offset, bucket))


# --------------------------------------------------------------------------
# 3. Compiling
# --------------------------------------------------------------------------

def build_rules(ndb_lines, ignored, dump_dir: Path | None = None):
    """Convert everything, compile one ruleset per bucket.
    Returns ({bucket: Rules}, stats)."""
    skipped: Counter = Counter()
    per_bucket: dict[str, list[Converted]] = {b: [] for b in MODULE_FOR_BUCKET}
    for source, line in ndb_lines:
        try:
            conv = convert_line(source, line, ignored)
        except Skip as why:
            skipped[str(why)] += 1
            continue
        per_bucket[conv.bucket].append(conv)

    compiled, counts, rejected = {}, {}, 0
    for bucket, items in per_bucket.items():
        module = MODULE_FOR_BUCKET[bucket]
        header = f'import "{module}"\n' if module else ""
        texts = [conv.rule(f"clam_{bucket}_{idx}") for idx, conv in enumerate(items)]

        # Fast path: hand yara-x the whole bucket as one source (seconds).
        compiler = yara_x.Compiler()
        try:
            compiler.add_source(header + "".join(texts))
            failed = bool(compiler.errors())
        except yara_x.CompileError:
            failed = True
        if failed:
            # Slow path: one rule per call, so a rule yara-x refuses costs
            # only itself. Much slower, so only used when something is wrong.
            compiler = yara_x.Compiler()
            kept = []
            for text in texts:
                before = len(compiler.errors())
                try:
                    compiler.add_source(header + text)
                except yara_x.CompileError:
                    pass
                if len(compiler.errors()) > before:
                    rejected += 1
                else:
                    kept.append(text)
            texts = kept
        compiled[bucket] = compiler.build()
        counts[bucket] = len(texts)
        if dump_dir is not None:
            dump_dir.mkdir(parents=True, exist_ok=True)
            (dump_dir / f"{bucket}.yar").write_text(header + "".join(texts))
    if rejected:
        skipped["refused by yara-x"] = rejected

    stats = {
        "signatures_read": len(ndb_lines),
        "rules": counts,
        "skipped": dict(skipped.most_common()),
    }
    return compiled, stats


def convert_and_compile(db_dir: Path, dump_dir: Path | None):
    """Read the databases, convert and compile. Returns (rules, stats, timing)."""
    t0 = time.perf_counter()
    ndb_lines, ignored = read_databases(db_dir)
    read_secs = time.perf_counter() - t0
    t0 = time.perf_counter()
    compiled, stats = build_rules(ndb_lines, ignored, dump_dir)
    timing = {"read_databases": read_secs, "convert_and_compile": time.perf_counter() - t0}
    return compiled, stats, timing


# --------------------------------------------------------------------------
# 4. Scanning
# --------------------------------------------------------------------------

def detect_bucket(path: Path) -> str | None:
    """Tiny stand-in for ClamAV's file typing: is this a PE or an ELF?"""
    with open(path, "rb") as fh:
        head = fh.read(64)
        if head[:4] == b"\x7fELF":
            return "elf"
        if head[:2] == b"MZ" and len(head) >= 64:
            fh.seek(int.from_bytes(head[60:64], "little"))
            if fh.read(4) == b"PE\0\0":
                return "pe"
    return None


def scan_file(path: Path, compiled: dict, timeout: int):
    """Returns (hits, buckets_used, seconds). A hit is (clamav_name, offset)."""
    buckets = ["any"]
    kind = detect_bucket(path)
    if kind:
        buckets.append(kind)
    hits = []
    t0 = time.perf_counter()
    for bucket in buckets:
        scanner = yara_x.Scanner(compiled[bucket])
        scanner.set_timeout(timeout)
        results = scanner.scan_file(str(path))
        for rule in results.matching_rules:
            meta = dict(rule.metadata)
            offsets = [m.offset for p in rule.patterns for m in p.matches]
            hits.append((meta.get("clamav_name", rule.identifier),
                         min(offsets) if offsets else None))
    return hits, buckets, time.perf_counter() - t0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[1])
    ap.add_argument("files", nargs="*", type=Path)
    ap.add_argument("--db", type=Path, default=Path("/var/lib/clamav"),
                    help="ClamAV database folder (read-only)")
    ap.add_argument("--dump-rules", type=Path, metavar="DIR",
                    help="write the generated YARA rules there, to read them")
    ap.add_argument("--stats", action="store_true", help="show conversion numbers")
    ap.add_argument("--timeout", type=int, default=3600,
                    help="seconds allowed per file and bucket")
    args = ap.parse_args()

    compiled, stats, timing = convert_and_compile(args.db, args.dump_rules)

    if args.stats or not args.files:
        print(f"signatures read : {stats['signatures_read']}")
        for bucket, count in stats["rules"].items():
            print(f"rules [{bucket:>3}]     : {count}")
        print("skipped:")
        for why, count in stats["skipped"].items():
            print(f"  {count:>7}  {why}")
        for step, secs in timing.items():
            print(f"{step:<20}: {secs:.1f}s")

    found_any = False
    for path in args.files:
        try:
            size = path.stat().st_size
            hits, buckets, secs = scan_file(path, compiled, args.timeout)
        except (OSError, yara_x.ScanError, yara_x.TimeoutError) as err:
            print(f"{path}: could not be checked ({err})")
            continue
        rate = size / secs / 1e6 if secs else 0.0
        print(f"{path}: {size / 2**30:.2f} GiB, rules {'+'.join(buckets)}, "
              f"{secs:.1f}s ({rate:.0f} MB/s)")
        if hits:
            found_any = True
            for name, offset in sorted(set(hits)):
                print(f"  RAW PATTERN HIT  {name}  at byte {offset}")
        else:
            print("  no converted signature matched "
                  "(partial check: this is not a clean verdict)")
    return 3 if found_any else 0


if __name__ == "__main__":
    sys.exit(main())
