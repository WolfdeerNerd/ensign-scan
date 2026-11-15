# Large Files Research

Notes from a set of experiments on files ClamAV can't scan. Nothing described here is part of Ensign yet. The numbers come from one desktop machine and its files, so treat them as a single data point.

The scripts are in [`experiments/large-files/`](../experiments/large-files/).

## The problem

ClamAV can't scan a file over about 2 GiB with any tool or setting. Ensign marks those files **not fully scanned**. The sweep (`--sweep`) reads them in overlapping slices and finds malware bytes sitting in the raw file, but it can't see inside compressed content, and it can't apply whole-file checks.

The question for these experiments: how close to a real verdict can Ensign get on such files, while staying local and never calling a file clean without a real scan?

## Summary

| Experiment | Result | Verdict |
|---|---|---|
| Convert ClamAV's `.ndb` signatures to YARA rules | Accurate, and as fast as the sweep, while covering far fewer signatures | Not worth adopting |
| Census of how big files store their contents | About a quarter stored raw, a tenth openable, the rest opaque or mixed | Shows where effort pays off |
| Archive walker for zip and tar | Every member of four real archives was looked at, almost all with ClamAV's full check | Works; candidate for Ensign |

## Experiment 1: ClamAV signatures as YARA rules

**Idea.** Translate ClamAV's body signatures (`.ndb`) into YARA rules and let yara-x scan the whole file in one pass, with no slicing.

**What was measured**

- 93,018 of 101,910 `.ndb` signatures converted. The rest need content ClamAV normalises first (HTML, text, mail), or were too weak to match safely.
- Accuracy against `clamscan`: 2,000 of 2,000 generated test files agreed on current signatures, and 19,999 of 20,000 on an older set. The one difference came from ClamAV typing a file as text and matching a normalised copy.
- False hits: none across 380 GiB in 67 large files, and none across 170 Windows executables.
- Speed: about 260 MB/s per CPU core on compressed data, about 187 MB/s on database-like data. One 87 GiB file scanned in a single pass.

**Why it was not adopted**

- On the same 9.4 GiB of files, the sweep took about 45 s and the converted rules took 43 s. The sweep applies everything clamd has loaded. The converted rules cover only `.ndb`, which is the small part of the database next to roughly 290,000 logical signatures and about 8 million hash signatures.
- Its two real advantages are narrow: signatures tied to a file offset or to the end of the file, which slicing breaks, and patterns longer than the sweep's overlap.
- It shares the sweep's main blind spot: compressed content.

**Worth keeping from it**

- yara-x handles very large files in one pass, which matters for the planned YARA stage.
- A compiled rule cache on disk holds raw signature bytes, so ClamAV flags the cache file as infected. Rules should be kept as source text and compiled in memory. The script did cache at first and no longer does.
- Signatures tied to a file offset are a known blind spot of the sweep.

## Experiment 2: what is inside files over 2 GiB

**Idea.** Sample each large file and sort it by how its contents are stored, since that decides what any raw-byte check can see.

| Stored as | Meaning | Share by size |
|---|---|---|
| Raw | Contents sit uncompressed. A raw-byte check sees them. | 27% |
| Openable | Packed with a common method (zlib, zstd, zip). Could be unpacked. | 11% |
| Mixed | Part raw, part random-looking. | 16% |
| Opaque | Random-looking with nothing recognisable: encrypted, a game's own compression, or video and audio. | 46% |

That is 65 files and about 373 GiB in a home folder, mostly game data. A second drive held four standard archives (93 GiB) and eight raw project files.

**What follows from it**

- For raw files, a sweep that finds nothing carries real weight.
- Standard archives are the one case where a full verdict on the contents is reachable.
- Opaque files can't be examined by content at all.

## Experiment 3: the archive walker

**Idea.** Open a zip or tar that ClamAV can't scan whole, and hand ClamAV each member as an ordinary file. Each member then gets the full check: all signature types, and ClamAV's own unpacking of anything nested.

**How it works**

- A member is unpacked into memory and passed to ClamAV as an open file. Nothing is written to disk.
- Members under clamd's limit go to clamd. Larger ones, up to about 2 GiB, go to `clamscan` with limits off. Members over about 2 GiB are swept in overlapping slices.
- It uses Ensign's own clamd code as a library, so limits and verdicts are read the same way.
- Memory follows Ensign's rule for `clamscan` runs: a fixed share of RAM (`clamscan_memory_percent`), and only what fits in free memory after a reserve for the rest of the machine.
- Members it can't open are listed with the reason, never assumed fine.

**Results on real archives**

| Archive | Members | Unpacked | Time | Outcome |
|---|---|---|---|---|
| 3.6 GiB `.ova` | 3 | 3.6 GiB | 206 s | 2 checked in full, 1 swept |
| 3.3 GiB zip, all Deflate64 | 24 | 6.3 GiB | 111 s | all checked in full |
| 11.1 GiB zip | 295 | 18.9 GiB | 388 s | 291 checked in full, 4 swept |
| 74.6 GiB zip | 344,556 | 120.6 GiB | 3,596 s | 342,103 checked in full, 5 swept, 2,448 empty |

No member in any of the four was skipped. The `.ova` time is from an early version that sent one slice at a time. Peak memory stayed at or under the cap in every run.

**What it needed along the way**

- **Deflate64.** Windows uses this method for very large files in zips, and Python's zip reader can't unpack it. The `inflate64` library handles it. Each unpacked member is checked against the size and checksum the zip records.
- **ClamAV's scan-time limit.** ClamAV stops scanning any one file after two minutes by default. Large members hit it. `scan_fds_with_clamscan()` now takes an optional `max_scantime_ms` so a caller can lift it.

## Findings that affect Ensign today

- **The two-minute limit applies to Ensign's own large-file scans.** They don't pass `max_scantime_ms`, so a large file that needs longer is recorded as not fully scanned. Whether to lift it there is undecided.
- **clamd remembers results for content it has already scanned.** Repeating test data makes timings look far better than they are. Benchmarks need non-repeating data, or clamd's cache switched off.

## Still not covered

Files and cases that none of the above can check.

**By how the file stores its contents**

- Encrypted archives, and archives using a game's own compression.
- Video and audio containers.
- Game packs with common compression inside (zlib or zstd chunks). They could be carved out and unpacked, but this was not built.

**Archive types the walker does not open**

- 7z and rar archives.
- Single compressed files that are not tars, such as `.gz`, `.xz` or `.zst`.
- Disk images: `.iso`, `.img`, `.vmdk`, `.qcow2`, and the disk inside an `.ova`. The image is swept, and the files inside it are never seen.
- An archive over 2 GiB nested inside another archive. It is swept as raw bytes and never opened.

**Inside archives the walker does open**

- Password-protected members.
- Members using a compression method other than Deflate64 that Python lacks.
- Bytes that sit outside any member, such as data added before or after the archive. The sweep covers these on the raw file.
- The zip index is trusted. A zip built to show different contents to different readers is not detected.
- Members over about 2 GiB get the sweep only: raw byte patterns, with no unpacking and no whole-file checks.

**In the sweep itself**

- Signatures tied to a file offset or to the end of the file.
- Whole-file hash signatures. Whether ClamAV carries any for files over 2 GiB was not measured.

## Open questions before any of this moves into Ensign

- Which status and report wording a walked archive gets. The experiments used "contents scanned" for a full check, and named swept or unopened members separately.
- Whether results are stored per archive, so an unchanged archive is not walked again. The largest test took an hour.
- A progress line, and a way to stop and resume.
- Automated tests. The walker was tested by hand against a real clamd.
- Speed with many small members: the largest archive managed about 95 members per second.
- Whether `inflate64` becomes an optional dependency.
