#!/usr/bin/env python3
"""Can Ensign look up flagged files in NIST's NSRL directly, without importing it?

Opens an NSRL RDSv3 SQLite database (the "modern minimal" release, say)
read-only and answers the questions the design depends on:

  1. Which table or view holds SHA-256 hashes, and with what columns.
  2. Whether a SHA-256 lookup uses an index (fast) or reads the whole
     table (minutes per lookup on a database this size).
  3. How long a lookup takes, for hashes that are there and ones that aren't.
  4. With --ensign-db: how many of the files Ensign has flagged are in
     NSRL at all. Counts only, unless --show.

Never writes to either database. Standard library only.

    python experiments/hash-libraries/nsrl_probe.py RDS_xxxx_modern_minimal.db
    python experiments/hash-libraries/nsrl_probe.py NSRL.db --ensign-db ~/.local/share/ensign-scan/system.db
    python experiments/hash-libraries/nsrl_probe.py NSRL.db --hash   # SHA-256 of the file (not NIST's dbhash: see --help)
"""
from __future__ import annotations

import argparse
import hashlib
import os
import random
import sqlite3
import sys
import time
from pathlib import Path


def connect_ro(path: Path) -> sqlite3.Connection:
    # immutable=1: SQLite won't even take a lock or look for a journal, so a
    # database on a read-only disk or owned by someone else still opens.
    return sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro&immutable=1", uri=True)


def sha256_places(conn: sqlite3.Connection) -> list[tuple[str, str, str, list[str]]]:
    """(kind, name, sha256 column, all columns) for every table/view with a SHA-256 column."""
    found = []
    for kind, name in conn.execute("SELECT type, name FROM sqlite_master WHERE type IN ('table', 'view')"):
        columns = [row[1] for row in conn.execute(f'PRAGMA table_info("{name}")')]
        for column in columns:
            if column.lower() in ("sha256", "sha_256", "sha-256"):
                found.append((kind, name, column, columns))
    return found


def plan(conn: sqlite3.Connection, name: str, column: str) -> str:
    rows = conn.execute(f'EXPLAIN QUERY PLAN SELECT 1 FROM "{name}" WHERE "{column}" = ?', ("0" * 64,)).fetchall()
    return "; ".join(str(r[-1]) for r in rows)


def stored_form(conn: sqlite3.Connection, name: str, column: str) -> str | None:
    """One stored value, to see whether hashes are upper- or lowercase hex, or raw bytes."""
    row = conn.execute(f'SELECT "{column}" FROM "{name}" WHERE "{column}" IS NOT NULL LIMIT 1').fetchone()
    return row[0] if row else None


def as_stored(hex_digest: str, sample) -> object:
    if isinstance(sample, bytes):
        return bytes.fromhex(hex_digest)
    if isinstance(sample, str) and sample.isupper():
        return hex_digest.upper()
    return hex_digest.lower()


def timed_lookups(conn, name, column, values) -> tuple[float, int]:
    query = f'SELECT 1 FROM "{name}" WHERE "{column}" = ? LIMIT 1'
    start, hits = time.perf_counter(), 0
    for value in values:
        hits += conn.execute(query, (value,)).fetchone() is not None
    return (time.perf_counter() - start) / max(1, len(values)), hits


def some_present(conn, name, column, n: int) -> list:
    """Up to n hashes that are in the table, picked by random rowid (no OFFSET scan)."""
    try:
        low, high = conn.execute(f'SELECT min(rowid), max(rowid) FROM "{name}"').fetchone()
    except sqlite3.OperationalError:   # a view has no rowid
        return [r[0] for r in conn.execute(f'SELECT "{column}" FROM "{name}" LIMIT ?', (n,))]
    if low is None:
        return []
    picks = []
    for _ in range(n * 3):
        row = conn.execute(f'SELECT "{column}" FROM "{name}" WHERE rowid >= ? LIMIT 1',
                           (random.randint(low, high),)).fetchone()
        if row and row[0]:
            picks.append(row[0])
        if len(picks) >= n:
            break
    return picks


def flagged_hashes(ensign_db: Path) -> list[tuple[str, str | None, str]]:
    """(sha256, threat name, path) for files Ensign has flagged (infected or allowed)."""
    conn = connect_ro(ensign_db)
    try:
        rows = conn.execute("SELECT file_hash, threat_name, filepath FROM files "
                            "WHERE scan_status IN ('infected', 'allowed') AND file_hash IS NOT NULL").fetchall()
    finally:
        conn.close()
    return [(h, t, os.fsdecode(p) if isinstance(p, bytes) else p) for h, t, p in rows]


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("nsrl_db", type=Path)
    ap.add_argument("--ensign-db", type=Path, help="Ensign's system.db, to count flagged files found in NSRL")
    ap.add_argument("--samples", type=int, default=200, help="lookups to time (default 200)")
    ap.add_argument("--show", action="store_true", help="print each flagged file found (path and threat)")
    ap.add_argument("--hash", action="store_true", help="SHA-256 of the file. Not comparable with NIST's dbhashes.txt, which lists SQLite dbhash values (a hash of the contents); check those with: dbhash FILE")
    args = ap.parse_args()

    size = args.nsrl_db.stat().st_size
    print(f"NSRL file: {size / 2**30:.1f} GiB")
    if args.hash:
        start = time.perf_counter()
        print(f"  SHA-256: {file_sha256(args.nsrl_db)}  ({time.perf_counter() - start:.0f} s)")
    conn = connect_ro(args.nsrl_db)

    places = sha256_places(conn)
    if not places:
        print("No table or view has a SHA-256 column. Tables:",
              [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")])
        return 1
    print("\nWhere SHA-256 hashes are:")
    for kind, name, column, columns in places:
        print(f"  {kind} {name}.{column}   columns: {', '.join(columns)}")
        print(f"    lookup plan: {plan(conn, name, column)}")
    indexes = [(r[0], r[1]) for r in conn.execute(
        "SELECT name, tbl_name FROM sqlite_master WHERE type = 'index' AND name NOT LIKE 'sqlite_%'")]
    print(f"  indexes: {', '.join(f'{n} (on {t})' for n, t in indexes) or 'none'}")

    # Time lookups in the first place that has an index; else the first one.
    kind, name, column, _ = next((p for p in places if "USING" in plan(conn, p[1], p[2])), places[0])
    if "USING" not in plan(conn, name, column):
        print(f"\n!! A lookup in {name} reads the whole table. Ensign would need its own index or copy.")
        print("   Timing 3 lookups only (each may take a while)...")
        args.samples = 3
    sample = stored_form(conn, name, column)
    print(f"\nTiming lookups in {kind} {name} (stored as "
          f"{'raw bytes' if isinstance(sample, bytes) else 'uppercase hex' if str(sample).isupper() else 'lowercase hex'}):")
    misses = [as_stored(os.urandom(32).hex(), sample) for _ in range(args.samples)]
    per, hits = timed_lookups(conn, name, column, misses)
    print(f"  {len(misses)} hashes not there: {per * 1000:.2f} ms each ({hits} found by chance)")
    present = some_present(conn, name, column, args.samples)
    if present:
        per, hits = timed_lookups(conn, name, column, present)
        print(f"  {len(present)} hashes that are there: {per * 1000:.2f} ms each ({hits} found)")

    if args.ensign_db:
        flagged = flagged_hashes(args.ensign_db)
        found = [(h, t, p) for h, t, p in flagged
                 if conn.execute(f'SELECT 1 FROM "{name}" WHERE "{column}" = ? LIMIT 1',
                                 (as_stored(h, sample),)).fetchone()]
        print(f"\nFlagged files in Ensign's database: {len(flagged)}; in NSRL: {len(found)}")
        if args.show:
            for _h, t, p in found:
                print(f"  {p}  [{t}]")
    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
