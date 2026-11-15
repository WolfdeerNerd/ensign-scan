#!/usr/bin/env python3
"""
archive_walker_proto.py -- EXPERIMENT, not part of Ensign. Read-only.

ClamAV can't scan a file over about 2 GiB, so it never looks inside a big
zip or tar. This opens the archive itself and gives ClamAV each member as
if it were an ordinary file, so every member gets ClamAV's full check
(all signature types, and ClamAV's own unpacking of anything nested).

How a member is checked depends on its unpacked size:
  under clamd's limit     -> clamd                       "checked"
  up to about 2 GiB       -> clamscan, limits off        "checked"
  over about 2 GiB        -> clamd, in overlapping        "swept"
                             slices (raw bytes only,
                             like Ensign's sweep)

Nothing is written to disk: a member is unpacked into memory (a memfd) and
ClamAV is handed that open file. Unpacking goes through the archive in
order; the waiting on ClamAV happens for several members at once.

Memory is minded the way Ensign minds its clamscan runs. Everything this
run holds (unpacked members, slices, and the signature copy each clamscan
loads) is counted, and something new starts only if both are true:
  - the count stays within a fixed share of RAM (Ensign's
    clamscan_memory_percent setting, 25% unless you changed it), and
  - it fits in what is free right now, after a reserve kept for the rest
    of the machine (the larger of 2 GiB and 10% of RAM).
The second rule is what makes it step back when something else, such as an
Ensign scan running alongside, is using the memory. One member too big for
the share is still checked, alone, if the free memory allows.

It uses Ensign's own clamd code as a library, so verdicts are read exactly
as Ensign reads them. Ensign itself is not changed and its database is not
touched.

What a quiet result does and doesn't mean
  - "contents scanned" is the closest this gets to clean: ClamAV checked
    every member in full.
  - Swept members were only searched for raw byte patterns.
  - Members it could not open (password-protected, damaged, or packed
    with a method nothing here can unpack) are listed, never assumed fine.
  - ClamAV's own limits on nesting depth and unpacked size still apply
    inside each member.
  - Only the members are looked at, not stray bytes between or after them.

Formats: zip (including zip64), tar and compressed tar (.tar.gz, .tar.xz,
.ova, ...).

Zip members packed with Deflate64 (which Windows uses for very large
files, and Python's zip reader can't unpack) are unpacked with the
inflate64 library, if it is installed. What comes out is checked against
the size and checksum the zip records for that member before it is trusted.

ClamAV also stops scanning any one file after two minutes. For members
that go to clamscan this lifts that limit, if the Ensign it runs with has
the max_scantime_ms option; a run that hangs is still ended by a time
allowance based on its size.

Needs: Python 3.11+, Ensign 0.6.0 or newer importable (the ensign_scan
package), clamd running, clamscan installed.
Optional: inflate64 (Arch: python-inflate64; elsewhere: pip install inflate64).

Usage: archive_walker_proto.py [--config PATH] [--memory-percent N] ARCHIVE [ARCHIVE ...]
"""
from __future__ import annotations

import argparse
import inspect
import os
import sys
import tarfile
import threading
import time
import zipfile
import zlib
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

try:
    from ensign_scan.clamd import (ClamdClient, clamscan_user, memory_available,
                                   scan_fds_with_clamscan)
    from ensign_scan.config import Config
    from ensign_scan.fsutil import human_size, printable
    from ensign_scan.models import ScanStatus
except ImportError as exc:      # say how to fix it instead of a bare traceback
    sys.exit(f"Can't import Ensign ({exc}).\nRun this with the Python that has ensign-scan "
             f"installed, or point PYTHONPATH at a checkout of the repo:\n"
             f"  PYTHONPATH=/path/to/ensign-scan python {sys.argv[0]} ARCHIVE")

try:
    import inflate64                # optional: unpacks Deflate64 zip members
except ImportError:
    inflate64 = None

# ClamAV stops scanning any one file after two minutes unless told otherwise.
# Newer Ensign lets the caller lift that for clamscan runs; older Ensign can't.
CAN_LIFT_SCAN_TIME = "max_scantime_ms" in inspect.signature(scan_fds_with_clamscan).parameters

CHUNK = 2**20                       # bytes copied per step while unpacking
DEFLATE64 = 9                       # the zip format's number for this method
PACKED_STEP = 64 * 2**10            # packed bytes unpacked per step: small, because a few
                                    # packed bytes can unpack into a great many
CLAMAV_CEILING = 2**31 - 3          # largest file ClamAV scans (measured on ClamAV 1.5.4)
SLICE_MAX = 256 * 2**20             # same slice and overlap sizes as Ensign's sweep
OVERLAP_MAX = 2**20
HEURISTIC_PREFIX = "Heuristics."    # structure guesses misfire on slices: noted, not counted
AT_ONCE_MAX = 8                     # the most scans sent to clamd at the same time
CLAMSCANS_AT_ONCE_MAX = 8           # the most clamscan runs at the same time
CLAMSCAN_BATCH_MAX = 4 * 2**30      # most unpacked bytes given to one clamscan run
CLAMSCAN_BATCH_FILES = 64           # most members given to one clamscan run
# Each clamscan loads its own copy of the signatures, about what clamd holds.
CLAMSCAN_COPY_MARGIN = 1.25
CLAMSCAN_COPY_FALLBACK = 1536 * 2**20   # if clamd's own use can't be read
# Kept free for everything else on the machine: the larger of these.
RESERVE_MIN = 2 * 2**30
RESERVE_FRACTION = 0.10
WAIT_FOR_MEMORY = 300               # seconds to wait for others to free memory before skipping
# Time allowed for one clamscan run: a fixed allowance plus a second per 2 MiB.
# With the per-file limit lifted, this is what ends a run that hangs.
CLAMSCAN_BASE_SECONDS = 600
CLAMSCAN_BYTES_PER_SECOND = 2 * 2**20


class CantOpen(Exception):
    """This member can't be unpacked; the message is the reason shown."""


def read_member(stream, size: int):
    """Yield a member's unpacked bytes in chunks, never more than `size`."""
    left = size
    while left > 0:
        try:
            block = stream.read(min(CHUNK, left))
        except (zipfile.BadZipFile, tarfile.TarError, EOFError, OSError, ValueError) as exc:
            raise CantOpen(f"damaged ({exc})") from None
        if not block:
            raise CantOpen("damaged (shorter than the archive says)")
        left -= len(block)
        yield block


class Deflate64Member:
    """One Deflate64 zip member, unpacked with the inflate64 library.

    Python's zipfile reads the zip's index (names, sizes, checksums, where
    each member starts) but can't unpack this method. So this reads the
    member's packed bytes straight from the file and unpacks them itself,
    then holds the result to the size and CRC-32 checksum the zip records:
    if they don't match, the member counts as unread."""

    def __init__(self, path: Path, info: zipfile.ZipInfo):
        self.size, self.crc_wanted = info.file_size, info.CRC
        self.packed_left = info.compress_size
        self.seen, self.crc = 0, 0
        self.ready = bytearray()                # unpacked, not yet handed out
        self.inflater = inflate64.Inflater()
        self.fh = open(path, "rb")
        try:
            # Each member starts with a 30-byte header, then its name and an
            # "extra" field whose lengths the header gives; the data follows.
            self.fh.seek(info.header_offset)
            header = self.fh.read(30)
            if len(header) < 30 or header[:4] != b"PK\x03\x04":
                raise CantOpen("damaged (member header missing)")
            self.fh.seek(int.from_bytes(header[26:28], "little")
                         + int.from_bytes(header[28:30], "little"), os.SEEK_CUR)
        except BaseException:
            self.fh.close()
            raise

    def _unpack_more(self) -> bool:
        if self.packed_left <= 0:
            return False
        packed = self.fh.read(min(PACKED_STEP, self.packed_left))
        if not packed:
            return False
        self.packed_left -= len(packed)
        try:
            self.ready += self.inflater.inflate(packed)
        except Exception as exc:
            raise zipfile.BadZipFile(f"Deflate64 data can't be unpacked: {exc}") from None
        return True

    def read(self, n: int) -> bytes:
        while len(self.ready) < n and self._unpack_more():
            pass
        block = bytes(self.ready[:n])
        del self.ready[:n]
        self.seen += len(block)
        self.crc = zlib.crc32(block, self.crc)
        if self.seen >= self.size:              # the last block: now it must all add up
            while not self.ready and self._unpack_more():
                pass                            # anything still unpacking would be extra data
            if self.seen != self.size or self.ready or self.crc != self.crc_wanted:
                raise zipfile.BadZipFile("unpacked data doesn't match the zip's own checksum")
        return block

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.fh.close()


def members_of(path: Path):
    """Yield (name, size, opener) for each regular file in the archive.
    opener() returns a readable stream, or raises CantOpen."""
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue

                def opener(info=info):
                    try:
                        return archive.open(info)
                    except NotImplementedError:         # checked first: it is a kind of RuntimeError
                        if info.flag_bits & 0x1:
                            raise CantOpen("password-protected") from None
                        if info.compress_type != DEFLATE64:
                            raise CantOpen(f"compression method {info.compress_type} "
                                           f"not supported") from None
                        if inflate64 is None:
                            raise CantOpen("Deflate64 needs the inflate64 library, "
                                           "which isn't installed") from None
                        return Deflate64Member(path, info)
                    except RuntimeError as exc:         # zipfile's word for "needs a password"
                        raise CantOpen("password-protected" if "password" in str(exc).lower()
                                       else f"can't be opened ({exc})") from None
                    except (zipfile.BadZipFile, OSError) as exc:
                        raise CantOpen(f"damaged ({exc})") from None

                yield info.filename, info.file_size, opener
        return
    try:
        archive = tarfile.open(path, mode="r|*")        # "|": read as a stream, start to end
    except tarfile.TarError:
        raise CantOpen("not a zip or tar archive") from None
    with archive:
        while True:
            try:
                member = archive.next()
            except (tarfile.TarError, EOFError, OSError) as exc:
                raise CantOpen(f"damaged ({exc})") from None
            if member is None:
                break
            if not member.isreg():
                continue                                 # links, devices, folders: no content
            yield member.name, member.size, lambda member=member: archive.extractfile(member)


def into_memfd(blocks) -> int:
    """Copy blocks into a new in-memory file and return its descriptor."""
    fd = os.memfd_create("walker-member", os.MFD_CLOEXEC)
    try:
        for block in blocks:
            view = memoryview(block)
            while view:                                 # a write may take only part of it
                view = view[os.write(fd, view):]
        os.lseek(fd, 0, os.SEEK_SET)
    except BaseException:
        os.close(fd)
        raise
    return fd


class MemoryMinder:
    """Counts what this run holds in memory and decides when more may start.
    See the two rules in the notes at the top of this file."""

    def __init__(self, percent: int):
        room = memory_available()
        self.total = room[1] if room else None
        self.budget = self.total * percent // 100 if room else 2 * 2**30
        self.reserve = max(RESERVE_MIN, int(self.total * RESERVE_FRACTION)) if room else 0
        self.held = 0
        self.peak = 0
        # Bytes the unpacking thread itself is holding while it asks for more
        # (its working buffer during a sweep). Nothing can free those, so
        # they don't count as "something to wait for".
        self.floor = 0
        # Set once the wait for other programs has run out, so that every
        # member after that one doesn't sit through the same long wait.
        self.starved = False
        self.changed = threading.Condition()

    def _fits(self, need: int) -> bool:
        if self.held > self.floor and self.held + need > self.budget:
            return False
        room = memory_available()           # read fresh: others use memory too
        return room is None or need <= room[0] - self.reserve

    def take(self, need: int, wait: bool = True) -> bool:
        """Count `need` bytes as held, waiting until that is allowed. False if
        it isn't allowed (wait=False), or if nothing of ours is left to wait
        for and other programs still hold the memory after a few minutes."""
        gave_up_at = None
        with self.changed:
            while not self._fits(need):
                if not wait:
                    return False
                if self.held <= self.floor:
                    if self.starved:
                        return False
                    if gave_up_at is None:
                        gave_up_at = time.monotonic() + WAIT_FOR_MEMORY
                    elif time.monotonic() > gave_up_at:
                        self.starved = True
                        return False
                self.changed.wait(timeout=1.0)   # woken by give(); the timeout re-reads free memory
            self.starved = False
            self.held += need
            self.peak = max(self.peak, self.held)
            return True

    def give(self, amount: int) -> None:
        with self.changed:
            self.held -= amount
            self.changed.notify_all()


class Walker:
    def __init__(self, client: ClamdClient, config: Config, memory_percent: int | None = None):
        self.client = client
        self.limits = client.limits()
        self.clamd_limit = self.limits.scan_limit
        self.slice_size = min(SLICE_MAX, self.clamd_limit - 1)
        self.overlap = min(OVERLAP_MAX, self.slice_size // 4)
        cpus = max(1, (os.cpu_count() or 2) // 2)
        # How many scans to have at clamd together: Ensign's max_workers if
        # set, otherwise two fewer than clamd's own thread limit and half the
        # CPU threads, like Ensign.
        self.at_once = config.max_workers if config.max_workers > 0 else min(
            AT_ONCE_MAX, max(1, (client.max_threads() or 4) - 2), cpus)
        self.clamscans = config.max_clamscans if config.max_clamscans > 0 else min(
            CLAMSCANS_AT_ONCE_MAX, cpus)
        self.minder = MemoryMinder(config.clamscan_memory_percent
                                   if memory_percent is None else memory_percent)
        self.clamscan_copy = int((client.memory_in_use() or CLAMSCAN_COPY_FALLBACK)
                                 * CLAMSCAN_COPY_MARGIN)
        # One clamscan run scans its members one after another, so with memory
        # to spare, large members are spread over several runs to scan side by
        # side. Small batches cost a signature load each, hence the floor.
        self.batch_target = max(256 * 2**20, min(CLAMSCAN_BATCH_MAX,
                                                 self.minder.budget // (4 * self.clamscans)))
        self.clamd_pool = ThreadPoolExecutor(max_workers=self.at_once)
        self.clamscan_pool = ThreadPoolExecutor(max_workers=self.clamscans)
        # Each waiting scan keeps a file open, and open files are limited:
        # this caps how many are queued or running at clamd at once.
        self.clamd_slots = threading.BoundedSemaphore(self.at_once * 4)
        self.lock = threading.Lock()                    # guards the result lists below

    def describe(self) -> str:
        m = self.minder
        text = (f"clamd scans members under {human_size(self.clamd_limit)}, {self.at_once} at a "
                f"time; larger ones go to clamscan, up to {self.clamscans} at a time (each "
                f"needing about {human_size(self.clamscan_copy)}); over "
                f"{human_size(CLAMAV_CEILING)} are swept in {human_size(self.slice_size)} slices")
        text += ("\nclamscan runs here have no per-file time limit" if CAN_LIFT_SCAN_TIME else
                 "\nthis Ensign can't lift ClamAV's 2-minute per-file limit for clamscan: a member "
                 "that takes longer is listed as not fully scanned")
        if m.total:
            text += (f"\nmemory: this run holds at most {human_size(m.budget)} "
                     f"({m.budget * 100 // m.total}% of RAM), and starts nothing new unless "
                     f"{human_size(m.reserve)} stays free for everything else")
        return text

    # -- one archive -----------------------------------------------------

    def walk(self, path: Path) -> bool:
        """Check one archive, print what happened. True if anything was found."""
        self.tally: Counter = Counter()
        self.hits: list[tuple[int, str, str]] = []      # (member number, member, signature)
        self.unchecked: list[tuple[int, str, str]] = [] # (member number, member, reason)
        self.notes: list[str] = []
        self.jobs: list = []                            # scans handed to the pools
        self.batch: list[tuple[int, int, str, int]] = []  # (memfd, number, member, size)
        self.batch_bytes = 0
        self.batch_has_copy = False                     # memory for its clamscan already counted
        self.minder.peak = self.minder.held
        start = time.perf_counter()
        print(f"{printable(path)} ({human_size(path.stat().st_size)})")
        number = 0
        try:
            try:
                for name, size, opener in members_of(path):
                    number += 1
                    self.check_member(number, printable(name), size, opener)
            finally:
                self.send_batch()
                for job in self.jobs:                   # wait for every scan still out
                    job.result()
        except (CantOpen, OSError) as why:      # keep and report what was learned before it broke
            if not self.tally:
                print(f"  could not be opened as an archive: {why}")
                return False
            self.unchecked.append((number + 1, "(rest of the archive)", str(why)))
        self.report(time.perf_counter() - start)
        return bool(self.hits)

    def check_member(self, number: int, name: str, size: int, opener) -> None:
        self.tally["members"] += 1
        self.tally["bytes"] += size
        if size == 0:
            self.tally["empty"] += 1
            return
        try:
            stream = opener()
            if stream is None:
                raise CantOpen("can't be read")
            with stream:
                if size > CLAMAV_CEILING:
                    self.sweep_member(number, name, size, stream)
                elif size < self.clamd_limit:
                    self.to_clamd(number, name, size, stream)
                else:
                    self.to_clamscan(number, name, size, stream)
        except CantOpen as why:
            with self.lock:
                self.unchecked.append((number, name, str(why)))

    def settle(self, number: int, name: str, outcome) -> None:
        with self.lock:
            if outcome.status == ScanStatus.INFECTED:
                self.hits.append((number, name, outcome.threat_name or "Unknown"))
            elif outcome.status == ScanStatus.CLEAN:
                self.tally["checked"] += 1
            else:       # an error, or ClamAV said it did not scan all of it
                self.unchecked.append((number, name, f"ClamAV: {printable(outcome.raw[-120:])}"))

    def failed(self, number: int, name: str, exc: BaseException) -> None:
        """A scan that broke is a member not looked at -- never a silent pass."""
        with self.lock:
            self.unchecked.append((number, name, f"could not be scanned ({type(exc).__name__})"))

    def reserve(self, need: int) -> bool:
        """Count `need` bytes as held, waiting if necessary. Before waiting,
        send off any clamscan batch still being collected: its memory only
        comes back once it has run, and it can't run while it sits here."""
        if self.minder.take(need, wait=False):
            return True
        self.send_batch()
        return self.minder.take(need)

    # -- members under clamd's limit ---------------------------------------

    def to_clamd(self, number: int, name: str, size: int, stream) -> None:
        if not self.reserve(size):
            raise CantOpen("not enough free memory right now")
        try:
            fd = into_memfd(read_member(stream, size))
        except BaseException:
            self.minder.give(size)
            raise

        def scan() -> None:
            try:
                self.settle(number, name, self.client.scan_fd(fd, "member"))
            except Exception as exc:
                self.failed(number, name, exc)
            finally:
                os.close(fd)
                self.minder.give(size)
                self.clamd_slots.release()

        self.clamd_slots.acquire()
        self.jobs.append(self.clamd_pool.submit(scan))

    # -- members up to ClamAV's ceiling: clamscan, several per run ---------

    def to_clamscan(self, number: int, name: str, size: int, stream) -> None:
        # Each clamscan run loads the whole signature database, so members are
        # collected into a batch and scanned together. The memory for that
        # run's signature copy is counted when its batch gets a first member.
        if self.batch and (self.batch_bytes + size > self.batch_target
                           or len(self.batch) >= CLAMSCAN_BATCH_FILES):
            self.send_batch()
        need = size + (0 if self.batch_has_copy else self.clamscan_copy)
        if not self.minder.take(need, wait=False):
            self.send_batch()           # let the waiting batch run: it frees memory when done
            need = size + self.clamscan_copy
            if not self.minder.take(need):
                raise CantOpen("not enough free memory right now")
        self.batch_has_copy = True
        try:
            fd = into_memfd(read_member(stream, size))
        except BaseException:
            self.minder.give(size)      # the signature copy stays counted for the next member
            raise
        self.batch.append((fd, number, name, size))
        self.batch_bytes += size

    def send_batch(self) -> None:
        batch, held = self.batch, self.batch_bytes + (self.clamscan_copy if self.batch_has_copy else 0)
        self.batch, self.batch_bytes, self.batch_has_copy = [], 0, False
        if not batch:
            if held:
                self.minder.give(held)
            return

        def scan() -> None:
            try:
                size = sum(member[3] for member in batch)
                lift = {"max_scantime_ms": 0} if CAN_LIFT_SCAN_TIME else {}
                outcomes = scan_fds_with_clamscan(
                    [fd for fd, *_ in batch], self.limits, run_as=clamscan_user(),
                    timeout=CLAMSCAN_BASE_SECONDS + size / CLAMSCAN_BYTES_PER_SECOND, **lift)
                for fd, number, name, _ in batch:
                    self.settle(number, name, outcomes[fd])
            except Exception as exc:
                for _, number, name, _ in batch:
                    self.failed(number, name, exc)
            finally:
                for fd, *_ in batch:
                    os.close(fd)
                self.minder.give(held)

        self.jobs.append(self.clamscan_pool.submit(scan))

    # -- members over ClamAV's ceiling: swept in slices --------------------

    def sweep_member(self, number: int, name: str, size: int, stream) -> None:
        """Send the member's unpacked bytes to clamd in overlapping slices,
        several at a time. Finds raw byte patterns only."""
        if self.slice_size < 4 * CHUNK:
            raise CantOpen("clamd's size limits are too small to sweep in slices")
        # A sweep holds memory for a long time, so nothing may be left waiting
        # on it: a clamscan batch still being collected is sent off first.
        self.send_batch()
        working = self.slice_size + self.overlap        # the slice being put together
        if not self.reserve(working):
            raise CantOpen("not enough free memory right now")
        self.minder.floor = working
        stop = threading.Event()
        found: list[tuple[int, str]] = []               # (slice number, signature)
        problems = 0
        slices: list = []

        def send(data: bytes) -> bool:
            held = 2 * len(data)        # in memory twice: these bytes, and the file clamd is handed
            if not self.reserve(held):
                return False
            order = len(slices)

            def scan() -> None:
                nonlocal problems
                try:
                    fd = into_memfd([data])
                    try:
                        outcome = self.client.scan_fd(fd, "slice")
                    finally:
                        os.close(fd)
                    with self.lock:
                        if outcome.status == ScanStatus.INFECTED:
                            threat = outcome.threat_name or "Unknown"
                            if threat.startswith(HEURISTIC_PREFIX):
                                self.notes.append(f"{name}: {threat} on a slice "
                                                  f"(heuristic, not counted)")
                            else:
                                found.append((order, threat))
                                stop.set()              # one real hit decides it
                        elif outcome.status != ScanStatus.CLEAN:
                            problems += 1
                except Exception:                       # whatever went wrong, this slice wasn't swept
                    with self.lock:
                        problems += 1
                finally:
                    self.minder.give(held)
                    self.clamd_slots.release()

            self.clamd_slots.acquire()
            slices.append(self.clamd_pool.submit(scan))
            return True

        broken = None
        tail = b""
        pending: list[bytes] = []
        held = 0
        try:
            for block in read_member(stream, size):
                if stop.is_set():
                    break
                pending.append(block)
                held += len(block)
                if held >= self.slice_size - self.overlap - CHUNK:   # keep each slice under clamd's limit
                    if not send(b"".join([tail] + pending)):
                        raise CantOpen("not enough free memory right now")
                    # The end of this slice is repeated at the start of the
                    # next, so a pattern lying across the cut is seen whole.
                    tail = (tail + b"".join(pending))[-self.overlap:]
                    pending, held = [], 0
            if pending and not stop.is_set() and not send(b"".join([tail] + pending)):
                raise CantOpen("not enough free memory right now")
        except CantOpen as why:                         # damaged part-way: keep what was learned
            broken = str(why)
        finally:
            for job in slices:                          # wait for every slice still at clamd
                job.result()
            self.minder.floor = 0
            self.minder.give(working)

        with self.lock:
            if found:
                self.hits.append((number, name, f"{min(found)[1]} (found by sweeping; "
                                                f"over 2 GiB unpacked)"))
            elif broken:
                self.unchecked.append((number, name, broken))
            elif problems:
                self.unchecked.append((number, name, f"{problems} slice(s) could not be swept"))
            else:
                self.tally["swept"] += 1

    # -- the result ----------------------------------------------------------

    def report(self, seconds: float) -> None:
        t = self.tally
        self.hits.sort()
        self.unchecked.sort()
        print(f"  {t['members']} member(s), {human_size(t['bytes'])} unpacked, {seconds:.0f}s, "
              f"most memory held at once {human_size(self.minder.peak)}")
        for _, name, threat in self.hits:
            print(f"  FOUND  {threat}  in member: {name}")
        if not self.hits:
            if self.unchecked:
                done = t["checked"] + t["swept"] + t["empty"]
                print(f"  contents partly scanned: {done} of {t['members']} members looked at, "
                      f"nothing found in those")
            elif t["swept"]:
                print(f"  contents scanned, nothing found: {t['checked']} member(s) checked in "
                      f"full, {t['swept']} over 2 GiB swept for raw byte patterns only")
            else:
                print(f"  contents scanned, nothing found: all {t['checked']} members with "
                      f"content were checked in full by ClamAV")
        if t["empty"]:
            print(f"  ({t['empty']} empty member(s) had nothing to check)")
        if self.unchecked:
            reasons = Counter(why.split(" (")[0] for _, _, why in self.unchecked)
            print(f"  NOT looked at: {len(self.unchecked)} member(s)")
            for why, count in reasons.most_common():
                print(f"    {count:>5}  {why}")
            for _, name, why in self.unchecked[:10]:
                print(f"    - {name}: {why}")
            if len(self.unchecked) > 10:
                print(f"    ... and {len(self.unchecked) - 10} more")
        for note in self.notes[:5]:
            print(f"  note: {note}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Give ClamAV the members of zip and tar "
                                             "archives it can't scan whole.")
    ap.add_argument("archives", nargs="+", type=Path)
    ap.add_argument("--config", metavar="PATH",
                    help="Ensign config to read settings from (default: Ensign's own)")
    ap.add_argument("--memory-percent", type=int, metavar="N", choices=range(5, 76),
                    help="share of RAM this run may hold, 5-75 (default: Ensign's "
                         "clamscan_memory_percent setting)")
    args = ap.parse_args()

    config = Config.load(args.config)
    client = ClamdClient(config.clamd_socket, timeout=1800)
    if not client.ping():
        sys.exit(f"clamd isn't answering on {config.clamd_socket}")
    if not client.supports_fildes():
        sys.exit("this clamd can't receive open files (no FILDES)")
    walker = Walker(client, config, args.memory_percent)
    print(walker.describe() + "\n")

    found = False
    for path in args.archives:
        try:
            found |= walker.walk(path)
        except OSError as exc:
            print(f"{printable(path)}: could not be read ({exc})")
        print()
    return 3 if found else 0


if __name__ == "__main__":
    sys.exit(main())
