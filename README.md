# Ensign

Greetings!

Ensign was originally a personal project. I liked clamscan, but I noticed it would keep breaking on certain files in my system — permission denials when clamd's own user couldn't read a path, files rejected outright for exceeding clamd's size limit, broken symlinks pointing at files that no longer exist, and a genuinely bizarre recursive mess with Steam's Proton Z: drive that kept re-scanning snapshots of snapshots of itself (more on that further down). On top of that, temp files have a way of vanishing between one moment and the next — the world of seemingly quantum temp files is terrifying.

I decided to make a logic brain for this madness, Ensign. The idea was for Ensign to walk the entire system and log every file in an SQLAlchemy database. That database file is kept locally on **your** system. The db includes the id, filepath, filename, file hash, file size, modification time (mtime_ns), inode change time (ctime_ns), the version of ClamAV's signature database it was last scanned under, scan status, scan result, threat name, last time file was scanned, file creation time, and 'last updated at time' of each file logged in the db.

The idea was to be as paranoid as possible when designing this. That being said, it is completely possible that someone one else will notice something I missed and that in itself, is okay.

**Status: alpha.** Ensign has so far been tested only by its author, on Arch Linux. Expect rough edges, and read its reports as advice, not verdicts.

## Disclaimer
Ensign is an independent project. It is not affiliated with Ensign InfoSecurity, The Ensign Group, the U.S. Navy or the U.S. Government.

Parts of this repo were written with assistance of Claude. The architecture and design decisions were made by me. Feel free to scrutinize this code, I welcome any flaws that are found. This project is not perfect, the same way I am not. A wise man loves correction, a fool abhors it.

## License

Ensign is released under the MIT License. See the `LICENSE` file.

## Installation

Ensign needs Python 3.11 or newer and ClamAV with its daemon (`clamd`) running.

**With pipx (recommended on Arch):**
```
sudo pacman -S --needed python-pipx clamav
pipx install ensign-scan
```
Arch marks the system Python as externally managed, so a plain `pip install` outside a virtual environment is refused. pipx installs Ensign into its own isolated environment and puts the `ensign-scan` command on your `PATH`. Update it later with `pipx upgrade ensign-scan`.

**With pip, in a virtual environment (any distro):**
```
python3 -m venv ~/.venvs/ensign
~/.venvs/ensign/bin/pip install ensign-scan
~/.venvs/ensign/bin/ensign-scan --help
```

**From a git clone** (to read or change the code, or to run the latest commit before a release):
```
git clone https://github.com/WolfdeerNerd/ensign-scan.git
cd ensign-scan
sudo pacman -S --needed python-sqlalchemy python-rich clamav
python3 main.py --help
```
`main.py` runs straight from the clone with no install step. The Requirements section below has the pip alternative. If you want the `ensign-scan` command from a clone, install it into a virtual environment with `pip install .` from the repo folder.

Either way, read the first-run note under Usage before your first scan.

## Requirements

This section is for running Ensign from a source checkout; an installed copy (above) pulls in its own dependencies.

To get started with Ensign you need Python 3.11 or newer, SQLAlchemy, and rich. Ensign requires Python 3.11+ specifically for the `tomllib` module, used for config parsing.

A `requirements.txt` file is included.

If you have pip installed, the command is:
```
pip install -r requirements.txt
```

If you have pacman installed, the command is:
```
sudo pacman -S --needed python-sqlalchemy python-rich
```

### A note for non-Arch users

Ensign's core scanning, hashing, and database tracking are plain Python + SQLAlchemy + ClamAV — nothing Arch-specific. It should run on any Linux distro with Python 3.11+ and ClamAV installed.

The one exception is `--verify-pacman`, which cross-checks files against `pacman -Qkk`'s own integrity data — that's an Arch-only feature by nature (there's no equivalent on Debian/Fedora/etc.). If `pacman` isn't found on the system, Ensign detects that and skips the check cleanly rather than erroring; every other command works the same regardless of distro.

`setfacl` (used for the permission-fix suggestions) and `notify-send` (desktop notifications) aren't Arch-specific either — both are standard Linux tooling available on most major distros, just under different package names (e.g. Debian/Ubuntu: `acl` and `libnotify-bin`).

## What Ensign Touches, and What It Can't See

### Network

Ensign makes no network connections. It talks to clamd over a local Unix socket (`clamd_socket` in your config) and nothing else. Virus-signature updates come from ClamAV's own `freshclam`, a separate program that you run or schedule yourself. It is the only networked part of the setup, and it is not part of Ensign.

### Programs Ensign runs

| Program | When | What for |
|---|---|---|
| `clamscan` | Only for a file clamd rejects as over its size limit | Scans that one file with the command-line scanner, which has no such limit |
| `pacman -Qkk` | Only with `--verify-pacman` | Read-only integrity check of installed files |
| `pacman -Qo <file>` | When listing infected files | Read-only lookup of which package owns a flagged file |
| `notify-send` | At the end of a run, if installed | Desktop notification |
| `gdbus` | After an infected-files alert | Closes that notification after its timeout |
| `pgrep` | When sending an infected-files alert | Checks whether a Steam game is running (see Alerts) |

Ensign never changes permissions. It prints `setfacl` commands for you to review and run yourself. It also never deletes, quarantines or edits a file: it reports.

### What Ensign can't see

- **Files clamd can't read.** clamd runs as the `clamav` user, so a file that user can't open is not scanned. It is recorded as `error`, or as `classified` when its path looks like a secrets store (see Permissions Setup).
- **Directories Ensign can't enter.** They are skipped, and each run ends with an "UNREADABLE DIRECTORIES" section listing them. The list is rebuilt every run, so nothing about it is stored in the database.
- **Symlinked directories.** They are never walked into (see the Proton note below). Symlinks to individual files are followed and scanned.
- **Excluded paths, and unchanged snapshot subtrees.** Whatever you list under `excludes` is not scanned, and subtrees under `snapshot_roots` are skipped while their modification time is unchanged.
- **Files that vanish mid-scan.** Temp files and browser caches come and go; they are counted as skipped, not as errors.
- **Anything ClamAV has no signature for.** Ensign is a file scanner built on ClamAV. It doesn't look at memory or running processes, and a clean result means "no known signature matched", not "safe".

## Permissions Setup

When building Ensign, I ran into errors concerning file permissions. Turns out that the ClamAV daemon requires permissions, as it operates under the user `clamav`. The daemon needs this whenever it needs to traverse directories.

To solve this I had to run the two following commands:
```
sudo setfacl -R -m g:clamav:rX /path/to/hotspot
sudo setfacl -R -d -m g:clamav:rX /path/to/hotspot
```
- The first command allows the group `clamav` to read the files in the directory.
- The second command makes it default for any new files in the same directory.

**A note on updates:** Permissions can get reset when programs or games update, because an update may replace files or directories with fresh copies that don't carry the ACL you set. If permission errors come back after an update, run the two commands again on the affected folder (`python3 main.py --suggest-fixes` prints the right commands for the current errors).

## Threading & Worker Sizing

Ensign scans files concurrently using a thread pool, since the work per file (hashing, then a clamd socket round-trip) is I/O-bound, not CPU-bound — the Python GIL isn't a bottleneck here the way it would be for CPU-heavy parallel work.

Worker count is either set explicitly (`max_workers` in config) or resolved automatically (`max_workers = 0`, the default): Ensign asks clamd for its own `MaxThreads` limit, subtracts a little headroom so the daemon stays responsive to other clients, and caps the result by your CPU count.

If clamd can't be reached to ask, Ensign falls back to a safe default of 5 workers rather than guessing wildly. And no matter how constrained the machine — single core, a very low `MaxThreads` on clamd — the worker count can never drop below 1. **Ensign will always run, even on modest hardware;** it just scans one file at a time in that case rather than failing or requiring a separate no-threading mode.

## Usage

The examples below are written as `python3 main.py` (running from a checkout). If you installed Ensign, use `ensign-scan` instead: `ensign-scan --help`, `ensign-scan ~/Downloads`, and so on.

**First run: don't use `sudo`.** Run Ensign under your own username the first time. Ensign creates its config, database and log files on first run, and whoever runs it owns them. If the first run is as root, those files end up owned by root and your username can't use them afterwards. If that happens, delete the root-created files (the database in `~/.local/share/ensign/` and the config in `~/.config/ensign/`) and run Ensign once under your own username to recreate them.

**First quick scan:** Before scanning everything, test your setup on one folder.

1. Make sure ClamAV's daemon is running (Ensign tells you if it isn't): `sudo systemctl start clamav-daemon`
2. Run Ensign on a small tree, as your own username: `python3 path/to/main.py ~/Downloads`
3. If you see permission errors, see Permissions Setup above, then run it again.

For a full scan, you only need to run:
```
python3 path/to/main.py
```

This scans everything listed in your config's `scan_targets`, runs the infected/error/stale rescan passes, prints a summary and error breakdown, and sends a desktop notification when it's done (if one is available).

While it runs, the bottom line of the terminal shows live progress: files done out of files to process, a bar and percentage, an estimated time remaining (ETA), how many infected files and errors have turned up so far, and the worker count. Each file's result scrolls past above it. The ETA follows the pace of roughly the last minute, so it tracks the current speed, and it shows `--` for the first few seconds or whenever nothing is finishing. When the scan is done, the ETA is replaced by the total time it took. On a narrow terminal the line drops detail instead of wrapping: the worker count goes first, then the full words shrink to symbols, and only on a very narrow one the ETA. When the output isn't a terminal (a scheduled service, or piped to a file), the line is printed once at the end instead of being redrawn.

### Targeting and behavior flags

| Command | What it does |
|---|---|
| `python3 main.py --help` | Show all available flags and exit |
| `python3 main.py ~/Downloads` | Scan just that one tree instead of everything in config |
| `python3 main.py --no-scan` | Hash and record files, skip ClamAV entirely |
| `python3 main.py --skip-rescans` | Skip the infected/error/stale rescan passes at the end |
| `python3 main.py --config PATH` | Use an alternate config file (default: `~/.config/ensign/config.toml`) |
| `ENSIGN_CONFIG=PATH python3 main.py` | The same as `--config`, set through an environment variable. If both are given, `--config` wins |

### Standalone maintenance commands

These run one job and exit — no full scan.

| Command | What it does |
|---|---|
| `python3 main.py --purge-missing` | Remove DB records for files that no longer exist on disk |
| `python3 main.py --rescan-errors` | Retry only files currently marked `ERROR` |
| `python3 main.py --verify-pacman` | Cross-check installed files against pacman's own checksums, flag mismatches (Arch only, can be slow) |
| `python3 main.py --suggest-fixes` | Print setfacl commands for current permission errors, optionally scoped to given targets |

### Only one run at a time

Before it scans, purges or retries errors, Ensign takes a lock: a small file called `ensign.lock` in your data directory (`~/.local/share/ensign/` unless you've set a custom `data_dir`). If another Ensign already holds it, the new one prints which process has it, exits with code 75 and scans nothing. That way a scheduled run and a manual run can't overlap and scan the same files twice.

- **The lock frees itself.** It belongs to the running process, so it is released when that process ends, even after a crash or `kill -9`. There is never a stale lock to clean up.
- **Leave the file in place.** Deleting `ensign.lock` while a run is using it can let a second run start.
- **Read-only commands skip it.** `--verify-pacman` and `--suggest-fixes` only read the database, so they can run while a scan is going.

### If a suggested fix doesn't seem to work

If you apply a suggested 'setfacl' command and the same error keeps showing up on a later run, the file may have been deleted since Ensign last saw it - common with temp files, downloads that get cleaned up, or build artifacts. A permission fix can't help a file that no longer exists. 

Run: 
    `python3 main.py --purge-missing`
to clear out stale records, then run a normal scan again to re-establish a clean baseline. 


## What Gets Rescanned

After the first full scan, Ensign sends a file to ClamAV again only when something suggests it needs it. A file is rescanned when:

- **Its size or modification time changed.**
- **Its inode change time (ctime) changed.** A program can set a file's modification time back to what it was, but it can't do that to ctime. So a file that was edited and then given its old timestamp back is still caught. The side effect is that `chmod`, `chown` and renaming a file also change ctime, so they trigger a rescan too.
- **It was last scanned clean under an out-of-date signature database.** A file ClamAV called clean yesterday can match a signature released today. `rescan_after_signature_updates` in your config sets how many signature updates behind a clean file can fall before it is scanned again. Updates arrive about once a day, so the number is roughly days: the default `7` re-checks everything about weekly, and `31` about monthly. The allowed range is 7 to 31 (a value outside it is clamped, with a warning), or `0` to turn this off. Each pass sends every out-of-date file through clamd again, which on a machine with millions of files takes a while, so pick the longest interval you are comfortable with.

The first run after upgrading from a version that didn't track ctime or signature versions scans every file once. After that it settles back to scanning only what changed.

## Alerts

When a scan ends with infected files, Ensign sends a critical desktop notification (needs `notify-send`). That alert behaves differently from the normal ones, because an alert that sits on top of a game until you tab out and dismiss it is a nuisance.

- **It closes itself** after `infected_alert_seconds` (default `60`). `0` leaves it up until you dismiss it. KDE Plasma ignores the timeout that `notify-send` sets on critical alerts, so Ensign closes the alert itself over D-Bus with `gdbus`.
- **By default it only does that while a Steam game is running.** With `infected_alert_only_while_gaming = true`, a scan you start yourself in a terminal leaves the alert up for you to come back to, unless a Steam game is running (Ensign looks for Steam's `reaper SteamLaunch AppId=` process). Steam open and idle doesn't count. `false` always auto-closes.
- **Runs with no terminal always auto-close.** A scheduled run (a service or cron job) has nobody to come back to the alert.
- **A new infected alert replaces the previous one** instead of stacking up. Ensign remembers the last alert's ID in `alert_state.json` in the data directory, and only trusts it within the same boot. If that file is root-owned (see the first-run note under Usage), replacement quietly stops working.

## Logs

Errors are written to one log file per run: `<data_dir>/logs/ensign-YYYYMMDD-HHMMSS.log`, which is `~/.local/share/ensign/logs/` unless you've set a custom `data_dir`. A run with no errors leaves no file.

- **Repeats are collapsed.** The first 20 occurrences of each distinct error are logged in full, then only counted, with a one-line total at the end of the run. One repeating problem (Ensign once logged 302,289 "stat failed" lines for broken symlinks) can't fill the disk.
- **Old logs are deleted automatically.** Runs older than `log_keep_days` (default `90`) go first. If the folder is still over `log_max_total_mb` (default `2048`), the oldest go next, so the size limit wins. `0` turns either rule off. Only files named `ensign-*.log` in that folder are ever deleted.
- Older versions wrote one `error_logs.txt` file. It is no longer used and can be deleted.

## Explaining Findings

When a scan finds an infected file, or `--verify-pacman` finds a mismatch, Ensign prints a short `ⓘ` note under it saying what the threat name or mismatch reason generally means. The point is to help you tell a false positive from something worth chasing.

- **Curated notes first.** Ensign ships a small table of researched notes, and you can add your own (see Customizing below).
- **Everything else is decoded from the name.** ClamAV names follow `Platform.Category.Name-SignatureID-Revision`, so for a name with no curated note Ensign describes what the name says. A Windows-only signature on Linux, for example, gets a **Hint** that it is often a false positive. A hint is a pointer, not a verdict.
- **Findings are grouped by threat name,** so a signature that hits many files is explained once. Each file gets a context line: size, last modified date, and whether a pacman package owns it.
- **All local and advisory.** Nothing is looked up online, and the notes never change a scan result.

## Customizing

Three optional sections in your `config.toml` extend Ensign's built-in lists. They are **additive only**: your entries are added, never replace a built-in one, and an entry that collides with a built-in is ignored with a warning.

```
[custom_threats."Win.Malware.Example-1234567-0"]
description = "What this signature generally means."
false_positive_note = "Optional: when it's commonly a false positive."

[custom_pacman_reasons]
"Some new mismatch type" = "What this pacman -Qkk reason means."

[custom_secrets]
high_dirs = ["myvault"]
high_prefixes = [["mywallet_", "wallets"]]
```

- **`[custom_threats]`** adds a note for a threat name. The name must match exactly, including the numbers.
- **`[custom_pacman_reasons]`** adds a note for a `pacman -Qkk` mismatch reason.
- **`[custom_secrets]`** adds paths that look like secrets stores. The keys are `high_dirs`, `high_dir_paths`, `high_filenames`, `high_extensions`, `high_scoped_filenames`, `high_prefixes`, `medium_prefixes` and `medium_extensions`. A HIGH match means a permission-denied file is classified as expected instead of reported as an error, and neither tier will get a `setfacl` fix suggested for it. See `ensign_scan/secrets.py` for what the tiers mean.

The first time you run Ensign it writes a starter `config.toml` with all of these documented as comments. `config.example.toml` in the repo has the same content.

## Querying the Database Directly

Most day-to-day questions are covered by the commands above. But the database is just SQLite, kept locally at the path printed in the `Database:` line when Ensign starts (`~/.local/share/ensign/system.db` unless you've set a custom `data_dir`) — for anything the built-in reports don't cover, `sqlite3` gets you there directly.

The `files` table's `scan_status` column is one of: `clean`, `infected`, `error`, `pending`, `classified`.

See the details behind current errors:
```
sqlite3 ~/.local/share/ensign/system.db "SELECT filepath, scan_result FROM files WHERE scan_status='error';"
```

See what's been classified (permission denied on a path that looks like a secrets store — expected, not chased as an error):
```
sqlite3 ~/.local/share/ensign/system.db "SELECT filepath, scan_result FROM files WHERE scan_status='classified';"
```

The list of paths/filenames/extensions used to make that call isn't arbitrary — see `docs/Classified_Paths_Research.md` for the sourcing behind each entry, and `ensign_scan/secrets.py` for the confidence tiers and how the two different call sites use them.

See infected files and what triggered them:
```
sqlite3 ~/.local/share/ensign/system.db "SELECT filepath, threat_name FROM files WHERE scan_status='infected';"
```

Look up everything Ensign knows about one specific file:
```
sqlite3 ~/.local/share/ensign/system.db "SELECT * FROM files WHERE filepath='/full/path/to/file';"


```

### A note on infected results

ClamAV includes heuristic signatures (like `SVGDynamicFunction`) that can match on legitimate code patterns — for example, JS build tools that generate functions at runtime from template/markup content (Vue's `compiler-sfc`, Vite's dependency cache) can trigger a phishing-heuristic match despite being ordinary framework code. An `infected` status is worth investigating, not treating as an automatic threat. Check what the file actually is and, if it looks like legitimate tooling, search the threat name plus the library name before assuming compromise.

### For Steam users,
### A note on Proton's 'Z:' drive

When developing Ensign, there wasn't anything to stop the walk from wandering and rescanning symlinks since I didn't understand them. You can imagine my surprise when the db was gradually growing in size despite not installing any updates or playing any new games. After some digging I found the culprit. Steam's Z: drive in Proton. The Z: drive allows steam to see and interact with your file system on linux. Nothing wrong with that. What I had failed to understand was that it included the ENTIRE system. INCLUDING ALL THE SNAPSHOTS (system backups)! So as a result, the db was seemingly growing by hundreds of thousands of files as it identifies files by the file paths. Example: ~/Pictures/IMG001.jpg would also show up as ~/.steam/path/to/z:/home/user/Pictures/IMG0001.jpg. A duplicate entry despite being the same file. Now take into account all the usual games that are in a user's steam library and all of those individual files, the walk would take literally days, going onto weeks, just to finish one sweep of the system.

The reason it kept compounding wasn't just that Z: mirrored the whole filesystem — it's that Z: pointing back at `/` meant it also mirrored itself. A snapshot taken of the system would include a copy of the Z: drive, which pointed back at `/`, which contained the Steam compatdata folder, which contained more snapshots, each with their own Z: drive pointing back at `/` again. So the walk wasn't just duplicating files — it was recursively duplicating its own duplicates, with the depth compounding on every snapshot layer. For a time it was quite literally logging backups of the backups of the backups, REGARDLESS OF HOW MANY LAYERS DEEP IT WENT.

Hence why for this build, I've opted to set followlinks to False in the walk function itself:

`for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):`

That way there's no endless cascade of walking a single directory. Symlinked directories are skipped entirely now — the walk sees them but never descends in. Individual files that happen to be symlinks (like a shortcut to a document) are still followed and scanned through to their real target, same as before — it's only symlinked directories that stopped getting wandered into.


### Last Note
This readme will be updated when needed. IE. FAQ questions that keep getting asked, or something needs further explanation. 
