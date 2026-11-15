# Large files

Four scripts from the experiments described in [`docs/Large_Files_Research.md`](../../docs/Large_Files_Research.md). That document has the results and the reasoning; this page says how to run them.

All four only read the files they are pointed at. None of them touches Ensign's database.

| Script | What it does | Outcome |
|---|---|---|
| `ndb_yara_proto.py` | Converts ClamAV's `.ndb` signatures to YARA rules and scans files with yara-x | Accurate, but no better than the sweep. Not adopted. |
| `check_equivalence.py` | Checks that converter against `clamscan` on generated test files | Used to measure the converter's accuracy |
| `bigfile_census.py` | Samples large files and reports how their contents are stored | Showed which files a raw-byte check can see into |
| `archive_walker_proto.py` | Opens zip and tar archives and hands ClamAV each member | Works. Candidate for Ensign. |

The converter came first. Its result, that matching speed was never the problem and unpacking was, is what led to the census and then to the walker.

## Running them

### The census

Standard library only.

```
python experiments/large-files/bigfile_census.py FILE [FILE ...]
```

### The archive walker

Needs clamd running, `clamscan` installed, and the `ensign_scan` package importable. From the repo root:

```
PYTHONPATH=. python experiments/large-files/archive_walker_proto.py ARCHIVE [ARCHIVE ...]
```

Optional: the `inflate64` library, for zip members packed with Deflate64 (Arch: `python-inflate64`; elsewhere: `pip install inflate64`). Without it those members are listed as not looked at.

It reads clamd's socket and the memory share from your Ensign config. `--memory-percent N` overrides the memory share for one run.

Exit code 3 means something was found, as in Ensign.

### The converter and its check

Both need yara-x (`pip install yara-x`, in a virtual environment on systems that manage Python packages themselves). The check also needs `clamscan`.

```
python experiments/large-files/ndb_yara_proto.py --stats
python experiments/large-files/ndb_yara_proto.py FILE [FILE ...]
python experiments/large-files/check_equivalence.py --sample 2000
```

`--db DIR` points either script at a ClamAV database folder other than `/var/lib/clamav`. `--dump-rules DIR` writes the generated YARA rules as text, to read next to the original signatures.

## Things to know

- A quiet result from any of these is a partial check. Only the walker's "contents scanned … checked in full" means ClamAV examined everything in the file.
- The walker unpacks members into memory. It counts what it holds and stays within a share of RAM, and it waits when other programs need the memory.
- The converter keeps its compiled rules in memory only. A file of compiled rules contains the raw bytes of every signature, and ClamAV reports such a file as infected.
- These were tested by hand against a real clamd. They have no automated tests.
