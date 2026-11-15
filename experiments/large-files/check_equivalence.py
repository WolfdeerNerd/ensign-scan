#!/usr/bin/env python3
"""Check the converter against ClamAV itself.

For a random sample of signatures: build a small file that the ORIGINAL
ClamAV signature must match, then ask both clamscan (original signature)
and yara-x (converted rule) whether they see it. They should agree.

Usage: check_equivalence.py --db /var/lib/clamav [--sample 600] [--seed 1]
Needs clamscan on PATH. Writes only inside a temporary folder.
"""
import argparse, random, re, shutil, struct, subprocess, sys, tempfile
from collections import Counter
from pathlib import Path
import ndb_yara_proto as P

SEC_SIZE, N_SECS, EP_IN_SEC0 = 0x8000, 4, 0x200


def instance(tokens, rng):
    """Concrete bytes that satisfy a parsed signature."""
    out = bytearray()
    for tok in tokens:
        if tok[0] == "b":
            hi, lo = tok[1]
            hi = rng.choice("0123456789ABCDEF") if hi == "?" else hi
            lo = rng.choice("0123456789ABCDEF") if lo == "?" else lo
            out.append(int(hi + lo, 16))
        elif tok[0] == "j":
            _, lo, hi = tok
            top = lo + 3 if hi is None else hi
            out += rng.randbytes(rng.randint(lo, min(top, lo + 3)))
        else:
            out += instance(rng.choice(tok[1]), rng)
    return bytes(out)


def pe_shell(rng):
    """A minimal 32-bit PE: headers + N_SECS sections of random bytes."""
    hdr = bytearray(0x400)
    hdr[0:2] = b"MZ"; struct.pack_into("<I", hdr, 60, 0x80)
    hdr[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", hdr, 0x84, 0x14C, N_SECS, 0, 0, 0, 224, 0x0102)
    opt = 0x98
    struct.pack_into("<HBBIIIIII", hdr, opt, 0x10B, 6, 0, SEC_SIZE, 0, 0,
                     0x1000 + EP_IN_SEC0, 0x1000, 0x1000)
    struct.pack_into("<IIIHHHHHHIIIIHH", hdr, opt + 28, 0x400000, 0x1000, 0x200,
                     4, 0, 0, 0, 4, 0, 0, 0x1000 + N_SECS * 0x8000, 0x400, 0, 3, 0)
    struct.pack_into("<IIIIII", hdr, opt + 72, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    table = opt + 224
    for i in range(N_SECS):
        struct.pack_into("<8sIIIIIIHHI", hdr, table + 40 * i, b".s%d" % i, SEC_SIZE,
                         0x1000 + i * 0x8000, SEC_SIZE, 0x400 + i * SEC_SIZE,
                         0, 0, 0, 0, 0xE0000020)
    return hdr + bytearray(rng.randbytes(SEC_SIZE * N_SECS))


def build_file(offset, bucket, body, rng):
    """Place `body` where the ClamAV offset says. None if we can't."""
    m = P._OFFSET.match(offset) if offset != "*" else None
    shift = rng.randint(0, int(m["shift"])) if m and m["shift"] else 0
    if bucket == "pe":
        f = pe_shell(rng)
        sec = lambda i: 0x400 + i * SEC_SIZE
        if offset == "*":
            at = sec(1) + rng.randint(0, 500)
        elif m["abs"] is not None:
            at = int(m["abs"])
        elif m["eof"] is not None:
            at = len(f) - int(m["eof"])
        elif m["ep"] is not None:
            at = sec(0) + EP_IN_SEC0 + int(m["ep"])
        elif m["sec"] is not None:
            if int(m["sec"]) >= N_SECS: return None
            at = sec(int(m["sec"])) + int(m["secoff"])
        elif m["last"] is not None:
            at = sec(N_SECS - 1) + int(m["last"])
        else:
            if int(m["whole"]) >= N_SECS: return None
            at = sec(int(m["whole"])) + rng.randint(0, 500)
        at += shift
        if at < 0x400 or at + len(body) > len(f): return None
        f[at:at + len(body)] = body
        return bytes(f)
    if bucket != "any": return None
    tail = rng.randbytes(rng.randint(0, 300))
    if offset == "*":
        # Zero bytes up front make ClamAV type the file as binary. If it
        # decides a file is text it matches a normalised copy instead, and
        # this check is about the translation, not about file typing.
        return bytes(4000) + rng.randbytes(rng.randint(0, 300)) + body + tail
    if m["abs"] is not None:
        return rng.randbytes(int(m["abs"]) + shift) + body + tail
    if m["eof"] is not None:
        after = int(m["eof"]) - shift - len(body)
        if after < 0: return None
        return bytes(4000) + rng.randbytes(rng.randint(0, 300)) + body + rng.randbytes(after)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", type=Path, default=Path("/var/lib/clamav"))
    ap.add_argument("--sample", type=int, default=600)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--near-miss", action="store_true",
                    help="break one fixed byte in each file: both should now stay quiet")
    args = ap.parse_args()
    rng = random.Random(args.seed)

    lines, ignored = P.read_databases(args.db)
    rng.shuffle(lines)
    work = Path(tempfile.mkdtemp(prefix="ndbcheck-"))
    files = work / "files"; files.mkdir()
    chosen, expect, made = [], {}, Counter()
    for source, line in lines:
        if len(chosen) >= args.sample: break
        try:
            conv = P.convert_line(source, line, ignored)
        except P.Skip:
            continue
        f = line.split(":")
        tokens = P.parse_hex(f[3])
        if args.near_miss:      # change the first fully-known byte
            i = next(k for k, t in enumerate(tokens) if t[0] == "b" and "?" not in t[1])
            tokens[i] = ("b", f"{int(tokens[i][1], 16) ^ 0xFF:02X}")
        data = build_file(f[2], conv.bucket, instance(tokens, rng), rng)
        if data is None: continue
        name = f"f{len(chosen):05d}"
        (files / name).write_bytes(data)
        expect[name] = f[0]; chosen.append((source, line))
        made[conv.bucket + " " + re.sub(r"\d+", "N", f[2])] += 1
    (work / "sample.ndb").write_text("".join(l.rstrip("\n") + "\n" for _, l in chosen))

    out = subprocess.run(["clamscan", "--allmatch", "--no-summary", "-d",
                          str(work / "sample.ndb"), str(files)],
                         capture_output=True, text=True, errors="replace").stdout
    clam = {n: set() for n in expect}
    for ln in out.splitlines():
        m = re.match(r".*/(f\d+): (.+?)(?:\.UNOFFICIAL)? FOUND$", ln)
        if m: clam[m[1]].add(m[2])

    compiled, _ = P.build_rules(chosen, ignored)
    yara = {}
    for name in expect:
        hits, _, _ = P.scan_file(files / name, compiled, 60)
        yara[name] = {h[0] for h in hits}

    both = only_clam = only_yara = neither = extra_diff = 0
    problems = []
    for name, sig in expect.items():
        c, y = sig in clam[name], sig in yara[name]
        both += c and y; neither += (not c and not y)
        if c and not y: only_clam += 1; problems.append(("clamav only", sig))
        if y and not c: only_yara += 1; problems.append(("yara only", sig))
        if clam[name] != yara[name]: extra_diff += 1
    print("files built per offset form:", dict(made))
    print(f"sampled {len(expect)}: both matched {both}, ClamAV only {only_clam}, "
          f"YARA only {only_yara}, neither {neither}, files with any difference {extra_diff}")
    for kind, sig in problems[:15]:
        print("  ", kind, sig)
    shutil.rmtree(work)
    return 1 if (only_clam or only_yara) else 0


if __name__ == "__main__":
    sys.exit(main())
