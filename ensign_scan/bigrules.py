"""YARA rules for files too large for ClamAV, made from ClamAV's own signatures.

The sweep (scanner.sweep_huge) reads a file over ~2 GiB in overlapping
slices and hands each one to clamd. That finds most signatures, but by
design it misses two kinds:

  * signatures tied to a position: an offset from the start ("at byte
    3,000,000,000"), from the end ("100 bytes before the end"), or from an
    executable's entry point or sections. A slice has its own start and
    end, so the positions are wrong in every slice but the first or last.
  * patterns that can stretch further than the slices overlap (1 MiB),
    such as "these bytes, then anything, then those bytes".

This module turns exactly those signatures, from ClamAV's body-signature
databases (.ndb), into YARA rules, which scan the whole file in one pass.
Everything else stays with the sweep. A rule that can't be translated
faithfully is skipped and counted, never guessed at. An experiment
(docs/Large_Files_Research.md) checked the translation against clamscan:
2,000 of 2,000 test files agreed.

The rules are rebuilt whenever freshclam has changed the databases. Before
a run that sweeps, ensure() compares the databases with the ones the
rules were built from, rebuilds if they differ, and says so if a rebuild
fails. `ensign-scan --update-rules` does the same on its own.

The rules are stored as YARA source text, never compiled: a file of
compiled rules holds every signature's raw bytes, and ClamAV flags it
as infected.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tarfile
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from . import yaraengine

# Bump when the translation changes, so existing rules are rebuilt.
CONVERTER_VERSION = 1

# The sweep's slice overlap (scanner._SWEEP_OVERLAP_MAX). A floating
# pattern that can't be longer than this is found whole in some slice.
SWEEP_OVERLAP = 2**20

# A pattern needs at least this many fully known bytes in a row. Shorter
# anchors make the matcher stop constantly on false candidates.
MIN_FIXED_RUN = 4

# ClamAV skips a signature whose functionality-level range excludes its
# engine. Current engines are far above the old values seen as a maximum
# ("retired"), and a signature asking for a minimum above this is left
# out rather than assumed to apply.
ASSUMED_ENGINE_FLEVEL = 200

# ClamAV target type -> bucket. Missing types are skipped: 3 (HTML),
# 4 (mail) and 7 (text) are matched by ClamAV against a normalised copy
# of the file, so the same bytes aren't in the raw file.
BUCKETS = {"0": "any", "1": "pe", "6": "elf"}
MODULE_FOR_BUCKET = {"any": None, "pe": "pe", "elf": "elf"}

# Ensign's own rule, compiled in with the others: after every build and
# every load it must match SELFTEST_DATA, or the rules aren't trusted.
# It uses both things the converted rules rely on: an end-of-file offset
# and an unbounded gap.
SELFTEST_RULE = """rule ensign_selftest {
  meta:
    clamav_name = "Ensign.SelfTest"
  strings:
    $a = { 45 4E 53 49 47 4E [-] 53 45 4C 46 54 45 53 54 }
  condition:
    $a and uint32(filesize - 4) == 0x4E474953
}
"""
SELFTEST_DATA = b"ENSIGN" + b"\0" * 4096 + b"SELFTEST" + b"SIGN"
SELFTEST_NAME = "Ensign.SelfTest"

RULES_DIRNAME = "yara"
# Where freshclam keeps the databases when clamd.conf doesn't say.
DEFAULT_DATABASE_DIR = "/var/lib/clamav"
STATE_NAME = "clamav-gaps.json"


class Skip(Exception):
    """This signature can't be translated faithfully; the message says why."""


class Unneeded(Exception):
    """The sweep already finds this signature; no rule needed."""


# ----------------------------------------------------------------------
# Reading ClamAV's databases
# ----------------------------------------------------------------------

_DB_SUFFIXES = (".cvd", ".cld", ".ndb", ".ign", ".ign2")


def database_files(db_dir: Path) -> list[Path]:
    return sorted(p for p in db_dir.iterdir() if p.is_file() and p.suffix.lower() in _DB_SUFFIXES)


def fingerprint(db_dir: Path) -> str:
    """Which databases the rules are made from: name, size and time of
    each file freshclam writes. Any update changes it."""
    h = hashlib.sha256()
    for path in database_files(db_dir):
        st = path.stat()
        h.update(f"{path.name}\0{st.st_size}\0{st.st_mtime_ns}\n".encode())
    return h.hexdigest()


def read_databases(db_dir: Path) -> tuple[list[tuple[str, str]], set[str], dict[str, int]]:
    """(ndb lines as (source, line), names on ClamAV's ignore lists,
    {database: version}).

    A .cvd/.cld file is a 512-byte text header ("ClamAV-VDB:date:version:
    ...") followed by a tar archive, gzip-compressed in a .cvd. Members are
    read into memory; nothing is extracted to disk.
    """
    ndb: list[tuple[str, str]] = []
    ignored: set[str] = set()
    versions: dict[str, int] = {}

    def take(name: str, data: bytes, container: str | None = None) -> None:
        text = data.decode("latin-1")
        if name.endswith(".ndb"):
            # A signature from a signed database (main.cvd, daily.cld) keeps
            # its name; ClamAV names every other one NAME.UNOFFICIAL, so the
            # rules do too. "daily.cvd/daily.ndb" marks the signed kind.
            source = f"{container}/{name}" if container else name
            ndb.extend((source, ln) for ln in text.splitlines() if ln.strip())
        elif name.endswith(".ign2"):       # "SigName" or "SigName:md5"
            ignored.update(ln.split(":")[0].strip() for ln in text.splitlines())
        elif name.endswith(".ign"):        # "dbfile:line:SigName"
            ignored.update(ln.split(":")[-1].strip() for ln in text.splitlines())

    for path in database_files(db_dir):
        if path.suffix.lower() in (".cvd", ".cld"):
            with open(path, "rb") as fh:
                header = fh.read(512).decode("latin-1").split(":")
                if len(header) > 2 and header[2].isdigit():
                    versions[path.stem] = int(header[2])
                with tarfile.open(fileobj=fh, mode="r|*") as tar:
                    for member in tar:
                        if member.isfile() and member.name.endswith((".ndb", ".ign", ".ign2")):
                            take(os.path.basename(member.name), tar.extractfile(member).read(), path.name)
        else:
            take(path.name, path.read_bytes())
    return ndb, ignored, versions


# ----------------------------------------------------------------------
# Translating one signature
# ----------------------------------------------------------------------
#
# ClamAV .ndb line:   Name:TargetType:Offset:HexSignature[:MinFL[:MaxFL]]
#
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
    """A ClamAV hex signature as tokens: ("b", "4A") a byte, ("j", lo, hi
    or None) a gap, ("alt", [tokens, ...]) alternatives."""
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

    merged: list = []   # neighbouring gaps add up: {2}{3} is {5}
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


def max_span(tokens: list) -> float:
    """The most bytes a match can cover (inf for an unbounded gap)."""
    total = 0.0
    for tok in tokens:
        if tok[0] == "b":
            total += 1
        elif tok[0] == "j":
            total += float("inf") if tok[2] is None else tok[2]
        else:
            total += max(max_span(a) for a in tok[1])
    return total


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
        # The rest depend on the executable's layout, which the pe and elf
        # modules read.
        if bucket == "any":
            raise Skip("executable-relative offset on a non-executable target")
        if m["ep"] is not None:
            base = f"{bucket}.entry_point {m['ep'][0]} {m['ep'][1:]}"
        else:
            start, size = ("raw_data_offset", "raw_data_size") if bucket == "pe" else ("offset", "size")
            if m["sec"] is not None:
                base = f"{bucket}.sections[{m['sec']}].{start} + {m['secoff']}"
            elif m["last"] is not None:
                base = f"{bucket}.sections[{bucket}.number_of_sections - 1].{start} + {m['last']}"
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
        source = self.source.replace("\\", "\\\\").replace('"', '\\"')
        return (f"rule {ident} {{\n"
                f'  meta:\n    clamav_name = "{name}"\n    source = "{source}"\n'
                f"  strings:\n    $a = {{ {self.hex} }}\n"
                f"  condition:\n    {self.condition}\n}}\n")


def convert_line(source: str, line: str, ignored: set[str]) -> Converted:
    """One .ndb line as a rule, if the sweep can miss it. Raises Unneeded
    for a signature the sweep finds anyway, Skip for one that can't be
    translated."""
    fields = line.strip().split(":")
    if len(fields) < 4:
        raise Skip("malformed line")
    name, target, offset, hexsig = fields[:4]
    if name in ignored:
        raise Skip("disabled by ClamAV's ignore list")
    if len(fields) > 4 and fields[4].isdigit() and int(fields[4]) > ASSUMED_ENGINE_FLEVEL:
        raise Skip("needs a newer engine (min functionality level)")
    if len(fields) > 5 and fields[5].isdigit() and int(fields[5]) < ASSUMED_ENGINE_FLEVEL:
        raise Skip("retired (max functionality level)")
    bucket = BUCKETS.get(target)
    if bucket is None:
        raise Skip(f"target type {target} not handled")
    tokens = parse_hex(hexsig)
    if offset == "*" and max_span(tokens) <= SWEEP_OVERLAP:
        raise Unneeded()
    if longest_fixed_run(tokens) < MIN_FIXED_RUN:
        raise Skip("too weak (short fixed part)")
    shown_name = name if "/" in source else f"{name}.UNOFFICIAL"
    return Converted(bucket, shown_name, source, render_hex(tokens), render_condition(offset, bucket))


# ----------------------------------------------------------------------
# Building, storing and loading
# ----------------------------------------------------------------------

def _header(bucket: str) -> str:
    module = MODULE_FOR_BUCKET[bucket]
    return f'import "{module}"\n' if module else ""


def _compiles(engine: yaraengine.Engine, header: str, texts: list[str]) -> bool:
    try:
        engine.compile(header + "".join(texts))
        return True
    except yaraengine.RuleError:
        return False


def _keep_compiling(engine: yaraengine.Engine, header: str, texts: list[str]) -> list[str]:
    """The rules the engine accepts. One compile for the whole set when all
    is well; otherwise halve and retry, so a few refused rules cost a few
    dozen compiles instead of one per rule."""
    if not texts or _compiles(engine, header, texts):
        return texts
    if len(texts) == 1:
        return []
    mid = len(texts) // 2
    return _keep_compiling(engine, header, texts[:mid]) + _keep_compiling(engine, header, texts[mid:])


@dataclass
class Build:
    sources: dict[str, str]            # bucket -> YARA source text
    counts: dict[str, int]             # bucket -> rules
    signatures_read: int
    covered_by_sweep: int
    skipped: dict[str, int]
    versions: dict[str, int]


def build(db_dir: Path, engine: yaraengine.Engine) -> Build:
    ndb, ignored, versions = read_databases(db_dir)
    if not ndb:
        raise RuntimeError(f"no .ndb signatures found in {db_dir}")
    skipped: Counter = Counter()
    unneeded = 0
    per_bucket: dict[str, list[Converted]] = {b: [] for b in MODULE_FOR_BUCKET}
    for source, line in ndb:
        try:
            conv = convert_line(source, line, ignored)
        except Unneeded:
            unneeded += 1
            continue
        except Skip as why:
            skipped[str(why)] += 1
            continue
        per_bucket[conv.bucket].append(conv)
    sources, counts = {}, {}
    for bucket, items in per_bucket.items():
        header = _header(bucket)
        texts = [conv.rule(f"clam_{bucket}_{idx}") for idx, conv in enumerate(items)]
        if bucket == "any":
            texts.append(SELFTEST_RULE)
        kept = _keep_compiling(engine, header, texts)
        refused = len(texts) - len(kept)
        if refused:
            skipped[f"refused by {engine.name}"] += refused
        sources[bucket] = header + "".join(kept)
        counts[bucket] = len(kept) - (1 if bucket == "any" and SELFTEST_RULE in kept else 0)
    return Build(sources, counts, len(ndb), unneeded, dict(skipped.most_common()), versions)


def rules_dir(data_dir: Path) -> Path:
    return data_dir / RULES_DIRNAME


def _write_atomic(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def read_state(data_dir: Path) -> dict:
    try:
        return json.loads((rules_dir(data_dir) / STATE_NAME).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _write_state(data_dir: Path, state: dict) -> None:
    folder = rules_dir(data_dir)
    folder.mkdir(parents=True, exist_ok=True)
    _write_atomic(folder / STATE_NAME, json.dumps(state, indent=2, sort_keys=True) + "\n")


def _stamp(db_dir: Path, engine: yaraengine.Engine) -> dict:
    return {"fingerprint": fingerprint(db_dir), "engine": engine.name,
            "converter": CONVERTER_VERSION, "overlap": SWEEP_OVERLAP}


@dataclass
class Loaded:
    """Compiled rules ready to scan with, and what they were built from."""
    engine: yaraengine.Engine
    compiled: dict                      # bucket -> engine's compiled rules
    count: int
    built_at: str
    versions: dict[str, int] = field(default_factory=dict)


def _load(data_dir: Path, engine: yaraengine.Engine, state: dict) -> Loaded:
    """Compile the stored rules and run the self-test. Raises on any doubt."""
    folder = rules_dir(data_dir)
    compiled = {}
    for bucket in MODULE_FOR_BUCKET:
        text = (folder / f"clamav-gaps-{bucket}.yar").read_text(encoding="utf-8")
        compiled[bucket] = engine.compile(text)
    hits = engine.scan_bytes(compiled["any"], SELFTEST_DATA)
    if not any(h.meta.get("clamav_name") == SELFTEST_NAME for h in hits):
        raise RuntimeError(f"self-test failed: {engine.label} didn't match Ensign's test rule")
    if engine.scan_bytes(compiled["any"], b"ENSIGN" + b"\0" * 64 + b"SELFTEST"):
        raise RuntimeError(f"self-test failed: {engine.label} matched data it shouldn't")
    return Loaded(engine, compiled, sum(state.get("counts", {}).values()), state.get("built_at", "?"),
                  state.get("versions", {}))


@dataclass
class Status:
    loaded: Loaded | None      # None: the YARA pass can't run this time
    ok: bool                   # False: the user must hear about it
    message: str               # one or two plain sentences for the top of the run
    rebuilt: bool = False
    # Something went wrong (shown in red), as opposed to "not installed",
    # which is a choice (shown in yellow).
    failed: bool = True


def update(data_dir: Path, db_dir: Path, engine: yaraengine.Engine | None, by_hand: bool = False) -> Status:
    """Rebuild the rules if the databases changed since the last build, or
    the last try failed, then load them. `by_hand` (--update-rules):
    rebuild in any case, and accept a big drop in the rule count, with a
    warning, instead of refusing it.

    A failed rebuild keeps the previous rules, which are still used, and
    says so. The failure is also recorded, so every run reports it, and
    tries again, until a rebuild succeeds.
    """
    if engine is None:
        return Status(None, False, f"YARA check of files too large for ClamAV is off: "
                                   f"{yaraengine.MISSING}.", failed=False)
    state = read_state(data_dir)
    error = warning = None
    try:
        stamp = _stamp(db_dir, engine)
    except OSError as exc:
        stamp = None
        error = f"couldn't read ClamAV's databases in {db_dir} ({exc.strerror or exc})"
    current = stamp is not None and not state.get("last_error") \
        and all(state.get(k) == v for k, v in stamp.items())
    rebuilt = False
    if stamp is not None and (by_hand or not current):
        started = time.monotonic()
        try:
            result = build(db_dir, engine)
            total = sum(result.counts.values())
            previous = sum(state.get("counts", {}).values())
            if total == 0:
                raise RuntimeError("the conversion produced no rules")
            if previous and total < previous // 2:
                drop = (f"the conversion produced {total} rules, less than half the {previous} "
                        f"from the last build")
                if not by_hand:
                    raise RuntimeError(drop + "; kept the previous rules in case the databases are "
                                       "damaged. If ClamAV really dropped them, accept the new "
                                       "count with ensign-scan --update-rules")
                warning = drop
            folder = rules_dir(data_dir)
            folder.mkdir(parents=True, exist_ok=True)
            for bucket, text in result.sources.items():
                _write_atomic(folder / f"clamav-gaps-{bucket}.yar", text)
            state = {**stamp, "built_at": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
                     "engine_version": engine.version, "counts": result.counts,
                     "signatures_read": result.signatures_read,
                     "covered_by_sweep": result.covered_by_sweep, "skipped": result.skipped,
                     "versions": result.versions, "build_seconds": round(time.monotonic() - started, 1)}
            _write_state(data_dir, state)
            rebuilt = True
        except Exception as exc:   # any failure: keep the old rules, and say so
            error = str(exc) or type(exc).__name__
    if error:
        state["last_error"] = error
        state["last_error_at"] = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
        try:
            _write_state(data_dir, state)
        except OSError:
            pass
    loaded = None
    if state.get("counts"):
        try:
            loaded = _load(data_dir, engine, state)
        except FileNotFoundError:
            loaded = None
        except Exception as exc:
            return Status(None, False, f"YARA rules for files too large for ClamAV couldn't be "
                                       f"loaded ({exc}). Those files get the sweep only. Retry: "
                                       f"ensign-scan --update-rules")
    if error and loaded:
        return Status(loaded, False, f"YARA rules for files too large for ClamAV couldn't be updated "
                                     f"({error}). Using the rules from {loaded.built_at}, made from "
                                     f"older signatures. Retry: ensign-scan --update-rules")
    if error:
        return Status(None, False, f"YARA rules for files too large for ClamAV couldn't be built "
                                   f"({error}). Those files get the sweep only. Retry: "
                                   f"ensign-scan --update-rules")
    if loaded is None:
        return Status(None, False, "YARA rules for files too large for ClamAV are missing. "
                                   "Build them: ensign-scan --update-rules")
    word = "rebuilt from the new signatures" if rebuilt else "up to date"
    message = (f"YARA rules for files too large for ClamAV: {loaded.count} signatures, {word} "
               f"({engine.label}).")
    if warning:
        return Status(loaded, False, message + f" Note: {warning}.", rebuilt)
    return Status(loaded, True, message, rebuilt)
