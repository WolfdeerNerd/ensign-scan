<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/WolfdeerNerd/ensign-scan/main/assets/ensign-logo-dark.svg">
  <img src="https://raw.githubusercontent.com/WolfdeerNerd/ensign-scan/main/assets/ensign-logo-light.svg" alt="Ensign" width="470">
</picture>

**A local-first ClamAV file scanner for Linux.**

[Install](#installation) · [Usage](#usage) · [Roadmap](https://github.com/WolfdeerNerd/ensign-scan/blob/main/ROADMAP.md) · [Security](https://github.com/WolfdeerNerd/ensign-scan/blob/main/SECURITY.md) · [Contributing](https://github.com/WolfdeerNerd/ensign-scan/blob/main/CONTRIBUTING.md) · [Report a bug](https://github.com/WolfdeerNerd/ensign-scan/issues/new/choose)

</div>

---

Greetings!

Ensign was originally a personal project. I liked clamscan, but I noticed it would keep breaking on certain files in my system — permission denials when clamd's own user couldn't read a path, files rejected outright for exceeding clamd's size limit, broken symlinks pointing at files that no longer exist, and a genuinely bizarre recursive mess with Steam's Proton Z: drive that kept re-scanning snapshots of snapshots of itself (more on that further down). On top of that, temp files have a way of vanishing between one moment and the next — the world of seemingly quantum temp files is terrifying.

I decided to make a logic brain for this madness, Ensign. The idea was for Ensign to walk the entire system and log every file in an SQLAlchemy database. That database file is kept locally on **your** system. The db includes the id, filepath, filename, file hash (left blank for credential files, which Ensign never reads), file size, modification time (mtime_ns), inode change time (ctime_ns), the version of ClamAV's signature database it was last scanned under, scan status, scan result, threat name, last time file was scanned, file creation time, and 'last updated at time' of each file logged in the db.

The idea was to be as paranoid as possible when designing this. That being said, it is completely possible that someone one else will notice something I missed and that in itself, is okay.

**Status: alpha.** Ensign has so far been tested only by its author, on Arch Linux. Expect rough edges, and treat its reports as advice: you make the final call.

## Disclaimer
Ensign is an independent project. It is not affiliated with Ensign InfoSecurity, The Ensign Group, the U.S. Navy or the U.S. Government.

Most of the code in this repo was written by Claude, working under my direction. The architecture and design decisions are mine. Every change goes through testing before it's merged, and before each release we sweep the code for bugs repeatedly and patch most, if not all, of what turns up. Feel free to scrutinize this code, I welcome any flaws that are found. This project is not perfect, the same way I am not. A wise man loves correction, a fool abhors it.

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

This also installs yara-x, the engine for the sweep's YARA pass on files too large for ClamAV (see Large files). Already have Ensign from before 0.10.0? Upgrading brings yara-x with it:
```
pipx upgrade ensign-scan
```

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

**Upgrading from before 0.8.1:** Ensign's folders were renamed from `ensign` to `ensign-scan`, matching the package and the command, so they can't collide with another program's folder. On its first run, 0.8.1 moves the old folders (`~/.config/ensign/` and `~/.local/share/ensign/`) to the new names itself and says so. It only does this when it's clearly safe:
- the new folder doesn't exist yet;
- the old folder holds only files Ensign creates (so it's never another program's);
- no other Ensign run is going;
- nothing names the old paths (`--config`, `$ENSIGN_CONFIG` or `data_dir`);
- and the folder can be renamed in one step (same filesystem; nothing is ever copied).

If any check fails, Ensign keeps using the old folder, and each run prints a notice at the start and the end saying why and how to move it by hand:
```
mv ~/.config/ensign ~/.config/ensign-scan
mv ~/.local/share/ensign ~/.local/share/ensign-scan
```
Do that while no Ensign run or scheduled scan is going. Either way, if a script or timer names an old path, update it. If you never had the old folders, there's nothing to do.

### Uninstalling

```
sudo ensign-scan --uninstall
```
This deletes everything Ensign made, yours and root's:
- your config and data: `~/.config/ensign-scan`, `~/.local/share/ensign-scan`, and the pre-0.8.1 `ensign` folders if they hold only Ensign's files;
- in a `data_dir` your config moved elsewhere, only Ensign's own files (and the folder, if that leaves it empty);
- root's: `/etc/ensign-scan` and `/var/lib/ensign-scan`, which hold root's config and data and every user's protected-mode copies.

It lists every path and its size first, offers to save your decisions (allowances, allowed folders, acknowledged startup entries) to a JSON file in your home, and goes ahead only when you type `uninstall`. `--yes` doesn't skip that, and it refuses without a terminal. It also refuses while a run is going. Under `sudo`, your files are deleted by a process running as you, never as root, so a symlink in your home can't turn it against anything else. Without `sudo`, only your own files go, and it says what of root's is left.

What stays, and is only pointed out: the program itself (the end of the output says how to remove it, for the way it was installed: `pipx uninstall ensign-scan`, a venv, a checkout, or a package), ClamAV, which you installed separately (Ensign never installs it; the output says how to remove it if you only had it for Ensign), and any timer, service or cron job you set up to run Ensign. The saved decisions file can't be imported yet; it's there to look up what you allowed.

## Requirements

This section is for running Ensign from a source checkout; an installed copy (above) pulls in its own dependencies.

To get started with Ensign you need Python 3.11 or newer, SQLAlchemy, rich and yara-x. Ensign requires Python 3.11+ specifically for the `tomllib` module, used for config parsing.

A `requirements.txt` file is included.

If you have pip installed, the command is (yara-x included):
```
pip install -r requirements.txt
```

If you have pacman installed, the command is:
```
sudo pacman -S --needed python-sqlalchemy python-rich
```

pacman has no yara-x, the engine for the sweep's YARA pass (see Large files), and Arch refuses a plain `pip install` outside a virtual environment. Without it, everything works except that pass, and each sweep says it's off. To have it, run the checkout from a virtual environment:
```
python3 -m venv --system-site-packages .venv   # keeps pacman's sqlalchemy and rich
.venv/bin/pip install yara-x
.venv/bin/python main.py --help
```
Under `sudo`, use the same interpreter: `sudo .venv/bin/python main.py ...`.

### A note for non-Arch users

Ensign's core scanning, hashing, and database tracking are plain Python + SQLAlchemy + ClamAV — nothing Arch-specific. It should run on any Linux distro with Python 3.11+ and ClamAV installed.

The one exception is package verification: `--verify-packages`, the "owned by package …" context line under infected files, and the "Likely false positive" label. These ask your package manager which package owns a file and whether it still matches what the package installed. Ensign picks the package manager from `/etc/os-release` (setting: `package_verification`, default `"auto"`). It supports pacman (Arch and derivatives), dpkg (Debian, Ubuntu and derivatives) and rpm (Fedora, RHEL and its rebuilds, openSUSE). On any other distribution, package verification is skipped cleanly with a note saying why, and every other command works the same. dpkg's records are MD5 checksums: good for catching accidental or careless changes, not an attacker who deliberately builds a file with a matching checksum.

`notify-send` (desktop notifications) isn't Arch-specific either — it's standard Linux tooling available on most major distros, just under a different package name (e.g. Debian/Ubuntu: `libnotify-bin`).

## What Ensign Touches, and What It Can't See

### Network

Ensign makes no network connections. It talks to clamd over a local Unix socket (`clamd_socket` in your config) and nothing else. Virus-signature updates come from ClamAV's own `freshclam`, a separate program that you run or schedule yourself. It is the only networked part of the setup, and it is not part of Ensign.

### Programs Ensign runs

| Program | When | What for |
|---|---|---|
| `clamscan` | Only for files larger than clamd scans (see Large files) | Scans them, in batches, with the size limits switched off. Under `sudo`, as the `clamav` user; a file that user can't read is given to it on stdin |
| `pacman -Qkk` / `dpkg --verify` / `rpm -Va` | Only with `--verify-packages` (whichever matches your distribution) | Read-only integrity check of installed files |
| `pacman -Qo` / `dpkg-query -S` / `rpm -qf` `<file>` | When listing infected files (whichever matches your distribution) | Read-only lookup of which package owns a flagged file |
| `pacman -Qo` + `pacman -Qkk <package>` / `dpkg-query -S` + `dpkg --verify <package>` / `rpm -qa` + `rpm -V <package>` | At the end of a scan with flagged files, and for `--clamav-report` | Read-only check of whether a package installed a flagged file and it's unchanged: the "Likely false positive" label (see False Positives) |
| `pacman -Qo` + `pacman -Qkk <package>` / `dpkg-query -S` + `dpkg --verify <package>` / `rpm -qa` + `rpm -V <package>` | Only with `--persistence`, for new or changed startup entries outside your home folder | Read-only check of whether a package installed the entry, and whether it still matches (see Persistence Audit) |
| `notify-send` | At the end of a run, if installed | Desktop notification |
| `gdbus` | After an infected-files alert | Closes that notification after its timeout |
| `pgrep` | When sending an infected-files alert | Checks whether a Steam game is running (see Alerts) |

Ensign never changes permissions on your files, and never asks you to. It also never deletes, quarantines or edits a file: it reports. The one thing it deletes is its own files, when you ask with `--uninstall` (see Uninstalling). The only permissions it sets are on its own files, when you run `sudo ensign-scan --protect` (see Protected mode).

### What Ensign can't see

- **Files you can't read.** Ensign opens each file as you, so a file your user can't open isn't scanned.
- **Directories Ensign can't enter.** They are skipped, and each run ends with an "UNREADABLE DIRECTORIES" section listing them. The list is rebuilt every run, so nothing about it is stored in the database.
- **Symlinked directories.** They are never walked into (see the Proton note below). Symlinks to individual files are followed and scanned.
- **Excluded paths, and unchanged snapshot subtrees.** Whatever you list under `excludes` is not scanned, and under `snapshot_roots`, the files in a folder are not looked at again while nothing has been added to, removed from or renamed in it (its modification and change times are the same as last run). Every folder is still checked, so a new file anywhere in a snapshot is found. A file edited in place doesn't change its folder, so between rescans it isn't noticed; the stale and signature rescans read it again.
- **Files that vanish mid-scan.** Temp files and browser caches come and go; they are counted as skipped, not as errors.
- **Most of what's inside files over about 2 GiB.** No ClamAV tool can scan a file that large, so Ensign marks it **not fully scanned**. With the sweep on, it still checks the raw bytes in slices, plus a YARA pass for the signatures slices miss, but nothing inside compressed or encrypted content (see Large files).
- **Anything ClamAV has no signature for.** Ensign is a file scanner built on ClamAV. It doesn't look at memory or running processes, and a clean result only means "no known signature matched". It doesn't prove a file is safe.

### Malware running as you

Your config and your database belong to you, so only you (and root) can change them. That also means anything running as your user can change them, malware included. Here is what it could do, and what notices:

| It changes | Effect | What notices |
|---|---|---|
| `excludes` or `scan_targets` in your config | Its folder is never scanned, and nothing says so | Nothing in your own runs. In protected mode it can't change your config |
| `clamd_socket` in your config, pointed at a fake clamd it runs itself | Every file is reported clean | Ensign refuses a clamd running as you (see How clamd Reads Your Files). In protected mode it can't change your config |
| An allowance (its file's hash, signature name and engine) | That hit is reported as "allowed by you" for as long as the file stays the same | The "Allowed by you" count at the end of each run, and `--list-allowed`. In protected mode it can't add one |
| An acknowledged startup entry | The persistence audit stops listing its entry | `persistence_acknowledged.log`, which sits in the same folder, so it could edit that too. In protected mode it can't acknowledge one |
| The Steam watch's records, or an acknowledgment | A Workshop item or an update isn't listed | Nothing in your own runs. In protected mode it can't acknowledge one, but the watch's record of each game stays in your database |
| A file's record, set to clean | The file isn't sent to ClamAV again until the next signature rescan (`rescan_after_signature_updates`) | The signature rescan, unless your config was also changed to switch it off. A record claiming a newer signature version than clamd has is rescanned at once |
| Ensign itself, if it's installed where you can write (a checkout, a venv in your home, `pip install --user`), or the command you type: an alias, a `PATH` entry, or a variable like `LD_PRELOAD` or `PYTHONPATH` set in your shell's startup files, which could also run an older copy of Ensign that doesn't know protected mode | Anything, protected mode included. Under `sudo`, the changed code runs as root | Nothing Ensign can do. Install it where only root can write if this matters to you. A change to your shell's startup files shows up in the persistence audit |

**The independent check is a run with `sudo`.** Root keeps its own config, database and persistence baseline, which only root can change (see Running with `sudo`), so none of the changes to your config or database reach it. It only helps if Ensign itself is installed where only root can write: a copy you can change runs your changes as root. A run with `sudo` now and then scans everything by its own record, and its persistence audit compares against its own baseline.

### Protected mode

Protected mode keeps your config and your decisions (allowances, folder allowances and acknowledged startup entries) where only root can write them, so nothing running as you can change them. It's optional, and nothing changes until you turn it on:

```bash
sudo ensign-scan --protect
```

It shows your config and asks before changing anything. Then:

- **Your config** is copied to `/etc/ensign-scan/users/<your uid>/config.toml`. Your runs use that copy from then on, and never read `~/.config/ensign-scan/config.toml`. Change it with `sudoedit /etc/ensign-scan/users/<your uid>/config.toml`. `--config` and `$ENSIGN_CONFIG` are refused: if a run says one was set and you didn't set it, find out what did.
- **Your decisions** are kept in `/var/lib/ensign-scan/users/<your uid>/decisions.db`. It **starts empty**: the allowances and acknowledgments in your own database aren't carried over, since root never reads a file you can write, and anything running as you could have added to them. Your user can't change them: `--allow`, `--allow-folder`, `--acknowledge` and the rest are refused when you run them as yourself. Change them with `sudo` and `--protected` instead (below).
- **Your verdicts** (each file's last scan result) stay in your own database. Something running as you could still mark a file clean there, but only until the next signature rescan checks it again. A file marked allowed with no allowance behind it counts as infected: in `--list-infected` and `--list-allowed` straight away, and in its record from the start of your next run.
- **Only you can read root's copies.** Each file is root's (mode 600), with an ACL entry that lets your user read it and nothing else. This needs a filesystem with ACL support, as ext4, btrfs and xfs have. Without it, `--protect` refuses and changes nothing. The folders above are mode 711: anyone can pass through, nobody can list them.
- **Every run checks root's copies first,** the way runs with `sudo` check their own: owned by root, and in folders only root can change. If a check fails (a file replaced, made writable by others, or unreadable because its ACL was lost in a restore), the run stops and says why. It never falls back to your own config.

**Changing your decisions** takes `sudo` and `--protected`, which says you mean your protected decisions, not root's own:

```bash
sudo ensign-scan --protected --allow PATH
sudo ensign-scan --protected --allow-folder FOLDER --signature NAME
sudo ensign-scan --protected --persistence          # list what's new against your baseline
sudo ensign-scan --protected --acknowledge PATH     # or --acknowledge-all
```

`--unallow` and `--unallow-folder` work the same way. Without `--protected`, `sudo` changes root's own decisions, as before.

When a new version of Ensign changes how decisions are stored, your runs can't upgrade root's file, so they stop and say so. Any `sudo ensign-scan` command upgrades every protected user's file in place, keeping its owner, mode and ACL.

- **The evidence is root's own scan.** Root never reads your database, so a file can be allowed only if root's own records say it was flagged: scan it with `sudo` first (`sudo ensign-scan PATH`). It's hashed again before it's allowed, as always, so only the content root saw flagged can be allowed.
- **Root's runs keep flagging it.** Root's decisions stay separate, so a run with `sudo` is still an independent check. Your own runs mark the file allowed on their next pass.
- **Acknowledgments** are checked against your protected baseline, and logged in a log only root can read, next to the decisions file.

**Undo it** with `sudo ensign-scan --unprotect`. Your runs then use your own config and database again, as they are at that moment, so check them.

**What it doesn't cover:**
- A copy of Ensign you can write to, or the command you type (see the table above).
- Your own database being made to attack Ensign as it reads it. Your runs still parse a file you can write, and a file crafted against SQLite could change what that run does. It can't reach root's copies or a run with `sudo`.
- Root's own runs. They keep their own config and decisions, as before, so a run with `sudo` stays an independent check.
- `sudo`'s remembered password. By default sudo remembers it for a few minutes in the terminal you used, and a program started from that terminal in that time can use it without asking you. Run `sudo -k` after changing settings to make sudo forget it.


## How clamd Reads Your Files

clamd runs as its own unprivileged user, `clamav`, not as you. Ensign doesn't ask clamd to open your files. It opens each file itself, as you, and passes clamd the already-open file over the local socket (clamd's `FILDES` command; `clamdscan --fdpass` does the same thing). The kernel checks *your* permission when Ensign opens the file, and clamd gets a handle to that one file for that one scan, with no permission on anything else. So:

- **No permission setup is needed.** Earlier versions suggested `setfacl` commands granting the `clamav` group read access to whole directory trees. That's no longer needed, and Ensign no longer suggests it: a recursive grant gave `clamav` standing access to everything under a directory, including files created later, which is far more than a scan needs. If you applied those grants before, you can remove them with `sudo setfacl -R -x g:clamav <dir>` and `sudo setfacl -R -d -x g:clamav <dir>`.
- **The hash and the verdict are for the same file.** Ensign hashes the file and clamd scans it through the same open handle, so the file can't be swapped in between.
- **Ensign refuses a clamd running as root.** clamd parses untrusted files, and ClamAV advises against running it as root. If yours does, Ensign stops before scanning anything and tells you how to fix it (`User clamav` in `clamd.conf`).
- **Ensign also refuses a clamd running as you** (under `sudo`, as the user who ran it). A real clamd runs as its own account, `clamav`. One running as you is most likely a stand-in: any program running as you could start one that answers "OK" for every file, and point `clamd_socket` at it. Ensign stops before scanning anything and tells you how to see what owns the socket.
- **A clamd without `FILDES`** (rare; it needs a local socket and a build with descriptor passing) makes Ensign fall back to asking clamd to open files itself. The run warns you, and files the `clamav` user can't read are recorded as errors.

**Credential files are scanned, and no hash of them is stored.** A file whose path matches a high-confidence credential pattern (SSH and GPG private keys, password-manager vaults, crypto wallets, cloud credentials; see `ensign_scan/secrets.py`) is scanned like any other file. A name is whatever the file's creator picked, so it can't decide whether a file is scanned: before 0.8.6 these files were never opened, and a payload named `invoice.kdbx` or `wallet.dat` anywhere on disk went unscanned. What the match changes is what Ensign keeps: the database holds the file's path, verdict and threat name, and no hash of it, since a hash of a short secret (a `.netrc` password, say) can be confirmed by guessing. A file found infected does get its hash stored, because it's malware then and `--allow` needs it, and so does an executable, which holds no secret. The hash is still worked out in memory for each scan. clamd reads the file through the handle Ensign passes it, on this machine, and by default writes nothing about clean files to its log and deletes the temporary files it unpacks. If clamd.conf turns on a setting that keeps what clamd reads after the scan (`LeaveTemporaryFiles`, `ForceToDisk`, `GenerateMetadataJson`, `LogClean`, `Debug` or `ExtendedDetectionInfo`), the run says which, at the start. Ensign never edits clamd.conf.

- **`~/.ssh/authorized_keys`, `authorized_keys2`, `config` and `rc` are scanned and watched**, and keep their hash. They hold no secrets, but they decide who can log in and what runs, so an intruder edits them to get back in. If one changes between runs, or appears where it didn't exist before, the run ends with an "SSH FILES CHANGED SINCE LAST RUN" section. A change you made yourself shows up there too; it's there so no change goes unnoticed.

The first run of 0.8.6 scans, once, the files earlier versions recorded as `classified` without opening them.

**`never_open_credentials` (off by default) leaves some credential files unscanned.** Set it to `true` in the config if you'd rather an application's own credential files were never hashed or scanned. A file is left alone only if all of these hold: it's at that application's usual place (an SSH key in `~/.ssh`, a Chromium, Chrome or Brave `Login Data`, Firefox's `key4.db`, gcloud's `credentials.db` or `access_tokens.db`, or `/etc/krb5.keytab`), it's owned by the user running Ensign (under `sudo` that's root, so files in your home are scanned), it isn't executable, it hasn't been found infected before, and its first bytes are that format's fixed start (only those are read). It's recorded as `classified`. Everything else is scanned as usual, including KeePass vaults and PuTTY keys, which have no usual place. The trade-off: anything running as you can write to those places, so a file left unscanned there could be malware wearing the right header. The run says so at the start while it's on. Turned off again, the files it left unscanned are scanned at the next run.

**A credential name on a file that isn't that credential is reported.** Some credential formats always start the same way: KeePass databases (`.kdbx`, `.kdb`), PuTTY keys (`.ppk`), SSH private keys (`id_rsa`, `id_ed25519` and the like), Kerberos keytabs (`.keytab`), and the SQLite stores browsers and gcloud keep passwords and tokens in (`Login Data`, `key4.db`, `credentials.db`, `access_tokens.db`). For a file with one of those names, Ensign reads its first 32 bytes while it has the file open for the scan. Those bytes are the format's fixed start and hold nothing secret. If they don't match, the run ends with a "NAMED LIKE A CREDENTIAL FILE, BUT ISN'T ONE" section listing the file, why, and clamd's verdict, and the file keeps its hash like any other. Malware borrows names like these to look harmless (MITRE ATT&CK T1036.008), so it's worth checking where each one came from; a file you know may just be misnamed. The section is shown every run until the file changes. Plaintext formats with no fixed start (`.netrc`, `.git-credentials`, cloud config files) aren't checked, since their first bytes can be the secret itself, and neither are formats whose layout couldn't be confirmed (`wallet.dat`, Electrum, KDE Wallet). A matching start doesn't prove a file is harmless, since a header can be copied, but clamd still scans the whole file.

The first run of 0.3.0, after upgrading from 0.2.x or earlier, removes the hashes older versions stored for credential files (overwriting them on disk, not just deleting the rows) and rescans files that were permission errors before. A backup or filesystem snapshot of the database taken earlier still holds the old hashes. Don't run an older Ensign against the same database afterwards: it hashes every file it scans, credential files included, and would store those hashes again.

## Threading & Worker Sizing

Ensign scans files concurrently using a thread pool, since the work per file (hashing, then a clamd socket round-trip) is I/O-bound, not CPU-bound — the Python GIL isn't a bottleneck here the way it would be for CPU-heavy parallel work.

Worker count is either set explicitly (`max_workers` in config) or resolved automatically (`max_workers = 0`, the default): Ensign asks clamd for its own `MaxThreads` limit, subtracts a little headroom so the daemon stays responsive to other clients, and caps the result by your CPU count, at 12, and by `cpu_share`.

`cpu_share` (default 50) is how much of your CPU a scan may use, in percent of its threads, so you can keep using the machine while it runs. The scan workers and any `clamscan` runs share it: a `clamscan` starts only if it fits alongside the workers busy at that moment, though one always runs so large files still get scanned. Set it to 100 to let a scan have the whole machine. When clamd's `MaxThreads` is what holds Ensign below that share, the start of a scan suggests the `MaxThreads` that would reach it. Ensign never changes clamd's settings itself.

If clamd can't be reached to ask, Ensign falls back to a safe default of 5 workers (fewer if `cpu_share` allows fewer), and the `Workers:` line says it's the fallback. clamd's own default `MaxThreads` is 10, which gives 8 workers unless `cpu_share` or your CPU count is lower. And no matter how constrained the machine — single core, a very low `MaxThreads` on clamd — the worker count can never drop below 1. **Ensign will always run, even on modest hardware;** it just scans one file at a time in that case rather than failing or requiring a separate no-threading mode.

## Usage

The examples below are written as `python3 main.py` (running from a checkout). If you installed Ensign, use `ensign-scan` instead: `ensign-scan --help`, `ensign-scan ~/Downloads`, and so on.

**Running with `sudo`:** runs as root keep their own config and database, which only root can change: `/etc/ensign-scan/config.toml` and `/var/lib/ensign-scan/`. They never read your config or write into your folders. If they did, anything running as you (malware included) could edit the config to hide from the root scan, or plant a symlink that root would follow and overwrite a system file. The first run as root copies your config there once, and says so; after that the two are independent, so to change a setting for sudo runs, edit the copy with `sudo`. Check the copy after that first run, its `excludes` in particular, since it holds whatever your config said at that moment. As root, Ensign refuses to start if its config file or data folder (including a custom `data_dir` or `--config`) is owned by another user or can be changed by one.

Files Ensign creates (the data folder, database, logs, config and reports) are readable only by their owner, since the database lists every file it has seen, including where your credential files are. Folders and files that already exist keep the permissions they have.

**First quick scan:** Before scanning everything, test your setup on one folder.

1. Make sure ClamAV's daemon is running (Ensign tells you if it isn't): `sudo systemctl start clamav-daemon`
2. Run Ensign on a small tree, as your own username: `python3 path/to/main.py ~/Downloads`
3. If some files couldn't be scanned, the end of the run says which and what usually causes it: "FILES ENSIGN COULD NOT OPEN" for files your user can't read (often ones owned by root), and "FILES CLAMD COULD NOT READ" for files clamd was refused (often AppArmor or SELinux confining clamd).

For a full scan, you only need to run:
```
python3 path/to/main.py
```

This scans everything listed in your config's `scan_targets`, runs the infected/error/stale rescan passes, prints a summary and error breakdown, and sends a desktop notification when it's done (if one is available).

While it runs, the bottom line of the terminal shows live progress: files done out of files to process, a bar and percentage, an estimated time remaining (ETA), how many infected files and errors have turned up so far, and the worker count. Each file's result scrolls past above it. The ETA follows the pace of roughly the last minute, so it tracks the current speed, and it shows `--` for the first few seconds or whenever nothing is finishing. When the scan is done, the ETA is replaced by the total time it took. On a narrow terminal the line keeps to the progress itself instead of wrapping: the infected and error counts and the worker count drop out together, leaving the bar, percentage and ETA, and only on a very narrow one does the ETA go too. Nothing is lost by that: infected files and errors still show in color in the per-file lines above it, and in the summary at the end. When the output isn't a terminal (a scheduled service, or piped to a file), the line is printed once at the end instead of being redrawn.

### Commands

From 0.11.0, every job has a short command, like pipx's or git's: `ensign-scan allow PATH` is the same run as `ensign-scan --allow PATH`. The original options in the two tables below keep working, so older scripts and notes don't change. `ensign-scan help` lists the commands, and `ensign-scan help COMMAND` (or `ensign-scan COMMAND --help`) explains one.

| Command | The same as |
|---|---|
| `ensign-scan` or `ensign-scan scan [PATH ...]` | a scan (with no PATH, of everything in your config) |
| `ensign-scan rescan-errors` / `purge-missing` / `update-rules` | `--rescan-errors` / `--purge-missing` / `--update-rules` |
| `ensign-scan list infected [PATH ...]` | `--list-infected [PATH ...]` |
| `ensign-scan list allowed` / `list allowed --all` | `--list-allowed` / `--list-allowed-all` |
| `ensign-scan report PATH` | `--clamav-report PATH` |
| `ensign-scan allow PATH` / `unallow PATH` | `--allow PATH` / `--unallow PATH` |
| `ensign-scan allow-folder FOLDER --signature NAME` / `unallow-folder ...` | `--allow-folder` / `--unallow-folder` |
| `ensign-scan persistence` | `--persistence` |
| `ensign-scan acknowledge PATH` / `acknowledge --all` | `--acknowledge PATH` / `--acknowledge-all` |
| `ensign-scan steam` | `--steam` |
| `ensign-scan acknowledge-steam ID` / `acknowledge-steam --all` | `--acknowledge-steam ID` / `--acknowledge-steam-all` |
| `ensign-scan verify-packages` / `suggest-fixes [PATH ...]` / `diagnostics` | `--verify-packages` / `--suggest-fixes` / `--diagnostics` |
| `sudo ensign-scan protect` / `unprotect` / `uninstall` | `--protect` / `--unprotect` / `--uninstall` |

Options such as `--yes`, `--protected` and `--config` go before or after the command: `sudo ensign-scan --protected allow PATH`. From a checkout, `python3 main.py allow PATH` works the same.

**Command or path.** The first word that isn't an option is read as a command if it is one, and as a path otherwise, so `ensign-scan ~/Downloads` still scans that folder. If the word is a command and there's also a file or folder by that name where you are, Ensign doesn't guess: it stops and shows both ways to say what you meant, `ensign-scan ./allow` for the folder and the original option (`ensign-scan --allow PATH`) for the command. In a script that passes paths it didn't choose (a list of downloads, say), put them after `scan --`: `ensign-scan scan -- "$path"`. Then no file name can ever be read as a command.

### Targeting and behavior flags

| Command | What it does |
|---|---|
| `python3 main.py --help` | Show all available flags and exit |
| `python3 main.py --version` | Show the installed version and exit |
| `python3 main.py ~/Downloads` | Scan just that one tree instead of everything in config |
| `python3 main.py --no-scan` | Hash and record files, skip ClamAV entirely |
| `python3 main.py --skip-rescans` | Skip the infected/error/stale rescan passes at the end |
| `python3 main.py --sweep` | After the scan, sweep files too large for ClamAV in slices (see Large files) |
| `python3 main.py --config PATH` | Use an alternate config file (default: `~/.config/ensign-scan/config.toml`; as root, `/etc/ensign-scan/config.toml`) |
| `ENSIGN_CONFIG=PATH python3 main.py` | The same as `--config`, set through an environment variable. If both are given, `--config` wins |

### Standalone maintenance commands

These run one job and exit — no full scan.

| Command | What it does |
|---|---|
| `python3 main.py --purge-missing` | Remove DB records for files that no longer exist on disk |
| `python3 main.py --rescan-errors` | Retry only files currently marked `ERROR` |
| `python3 main.py --verify-packages` | Cross-check installed files against the package manager's own checksums, flag mismatches (can be slow, and has no time limit: Ctrl+C stops it; `--verify-pacman` still works as the old name) |
| `python3 main.py --suggest-fixes` | List files clamd could not read, grouped by directory, optionally scoped to given targets |
| `python3 main.py --diagnostics` | Print versions, settings and counts for a bug report. Contains no paths, usernames, hostnames or file names, and writes nothing |
| `python3 main.py --allow PATH` | Mark a file ClamAV flagged as a false positive (see False Positives). Asks to confirm; `--yes` skips the question |
| `python3 main.py --unallow PATH` | Undo `--allow`: the file counts as infected again |
| `python3 main.py --allow-folder FOLDER --signature NAME` | Allow every file under a folder that one signature flags right now (see False Positives). Asks once to confirm; `--yes` skips the question |
| `python3 main.py --unallow-folder FOLDER --signature NAME` | Undo `--allow-folder`: those files count as infected again |
| `python3 main.py --list-allowed` | List what you've allowed: each folder once (its signatures, how many files each allowed, and any file there that's infected now and not allowed), then each file once with its signatures and SHA-256 |
| `python3 main.py --list-allowed-all` | The same, plus the files inside each allowed folder, listed one level in |
| `python3 main.py --list-infected [PATH ...]` | List the infected files from past scans, all of them or only under the paths given, without scanning. Each shows the SHA-256 of the flagged content, to look up on VirusTotal (a lookup sends only the hash; don't upload files from your personal folders) |
| `python3 main.py --update-rules` | Rebuild the YARA rules the sweep uses from ClamAV's current signatures (see Large files). Runs by itself before a sweep when freshclam has changed the signatures |
| `python3 main.py --persistence` | List startup entries that are new, changed or gone since you acknowledged them (see Persistence Audit). Changes nothing |
| `python3 main.py --acknowledge PATH` | Accept one startup entry the persistence audit lists, as it is now. Asks to confirm; `--yes` skips the question |
| `python3 main.py --acknowledge-all` | Show the persistence audit, then accept everything it lists. Asks to confirm |
| `python3 main.py --steam` | List what the Steam watch found: Workshop items carrying code, game updates worth a look, renamed games (see Steam Watch). Changes nothing |
| `python3 main.py --acknowledge-steam ID` | Mark one Steam watch finding as looked at, by the ID it's listed with. Asks to confirm; `--yes` skips the question |
| `python3 main.py --acknowledge-steam-all` | Show the Steam watch, then mark everything it lists as looked at. Asks to confirm |
| `sudo python3 main.py --protect` | Keep your config and decisions where only root can change them (see Protected mode). Shows your config and asks first |
| `sudo python3 main.py --unprotect` | Undo `--protect`: your runs use your own config and database again. Asks first |
| `sudo python3 main.py --uninstall` | Delete everything Ensign made, yours and root's, after listing it and asking you to type `uninstall` (see Uninstalling). Without `sudo`, only yours |
| `sudo python3 main.py --protected --allow PATH` | In protected mode, change your decisions: goes with `--allow`, `--unallow`, `--allow-folder`, `--unallow-folder`, `--persistence`, `--acknowledge`, `--acknowledge-all` and `--acknowledge-steam ID` |
| `python3 main.py --clamav-report PATH` | Prepare a false-positive report for ClamAV about a flagged file (see False Positives). Nothing is sent: you submit it |

### Only one run at a time

Before it scans, purges or retries errors, Ensign takes a lock: a small file called `ensign.lock` in your data directory (`~/.local/share/ensign-scan/` unless you've set a custom `data_dir`). If another Ensign already holds it, the new one prints which process has it, exits with code 75 and scans nothing. That way a scheduled run and a manual run can't overlap and scan the same files twice.

- **The lock frees itself.** It belongs to the running process, so it is released when that process ends, even after a crash or `kill -9`. There is never a stale lock to clean up.
- **Leave the file in place.** Deleting `ensign.lock` while a run is using it can let a second run start.
- **Read-only commands skip it.** `--verify-packages`, `--suggest-fixes` and `--diagnostics` only read the database, so they can run while a scan is going.

A scan's exit code says how it went, so a script or a scheduled run can act on it:

| Code | Meaning |
|---|---|
| 0 | Finished, nothing infected |
| 3 | Finished, and infected files are present: found this run, or found before and still on disk. One you've deleted no longer counts. This outranks code 1 |
| 1 | Finished, but some results couldn't be saved to the database (a full disk, say). Those results are still reported and alerted on, listed at the end under "scanned but not saved" |
| 5 | Finished, nothing infected and nothing unsaved, and the Steam watch lists something you haven't acknowledged (see Steam Watch). Codes 3 and 1 outrank it |
| 75 | Another Ensign is running; nothing was scanned |

`--persistence` has one more: **4** when startup entries are new, changed or gone since you last acknowledged them (0 when there are none). Entries it couldn't read without root don't count, so a run without sudo doesn't report them every time. `--acknowledge-all` exits 0 once it has acknowledged everything, and 4 if you answered no. `--steam` exits **5** when something is listed and 0 when nothing is; `--acknowledge-steam-all` exits 0 once everything is acknowledged.

### Large files

clamd skips any file larger than its `MaxFileSize` or `MaxScanSize` setting (100 MiB and 400 MiB by default), and still answers "OK" for it. Ensign doesn't take that answer. It reads the limits from clamd's config and sends larger files to `clamscan` instead, with the limits switched off. `clamscan` comes with ClamAV. Each `clamscan` run loads its own copy of the signatures, which takes seconds and about as much memory as clamd uses. So Ensign scans large files in batches of up to 32 files or 8 GiB, whichever comes first, alongside the files clamd scans. Several batches run at once when there's memory for it, within two limits checked before each one starts:

- **A fixed budget.** All of them together use at most `clamscan_memory_percent` of your RAM (default 25%, allowed 5–75), however much happens to be free. On 16 GB that's 4 GB, about two copies of the signatures.
- **What's free right now.** Another copy must also fit in free memory with a reserve left over (the larger of 2 GiB or 10% of RAM), so starting a game mid-scan stops it adding more.

One always runs, so large files are always scanned. `max_clamscans` caps how many run at once (0 = auto: as many as `cpu_share` and memory allow, at most 8).

Faster still: raise these together in clamd.conf and restart clamd. Ensign reads the new limits, and clamd, which already has the signatures loaded and scans with several threads, handles those files itself:

```
MaxFileSize 2000M
MaxScanSize 4000M
PCREMaxFileSize 2000M
```

`PCREMaxFileSize` matters too: signatures that use regular expressions are skipped for files past it (100M by default), and clamd still answers "OK". Ensign counts it as one of clamd's limits, and switches it off for `clamscan`. Large files you scanned with Ensign 0.4.0 or older were never really checked, so they are rescanned once.

ClamAV has a time limit as well: it stops scanning any single file after two minutes (`MaxScanTime`) and leaves the rest of it unscanned. Ensign switches that off for `clamscan` too, because a large file can need longer. A `clamscan` run that hangs is still ended, after a time allowance based on the size of its files, and whatever it didn't finish is recorded as an error, never as clean. Files that Ensign 0.6.0 or older cut off at two minutes are scanned again once.

ClamAV can't scan files over about 2 GiB at all, with any tool or setting. This is a limit in ClamAV itself, and its developers have said so. Ensign marks those files **not fully scanned** and lists them at the end of each run, never as clean. They are hashed and tracked, so a changed one is looked at again.

**The sweep.** For those files, Ensign can do the next best thing: read the file in overlapping slices and pass each one to clamd like an ordinary file. It's on by default; turn it off with `sweep_huge_files = false` in your config (then `--sweep` runs it for a single scan). The first sweep of a big game library or VM images takes a while, roughly an hour for a few hundred GiB, and the run says how much it has to read before it starts. If you set Ensign up before the sweep was on by default, your config file still has `sweep_huge_files = false` from the old example: change it to `true` to turn the sweep on.

- **What it finds:** malware bytes sitting anywhere in the file. If a slice matches a signature, the whole file is flagged as infected, and the report says which bytes matched. Slices overlap, so a signature cut in two by a slice boundary is still found.
- **What it can't find:** anything ClamAV only sees by unpacking or understanding the whole file. That means what's inside compressed archives, whole-file hash signatures, and file-structure checks. So a sweep that finds nothing leaves the file **not fully scanned**, never clean. Heuristic hits (`Heuristics.*`) on a slice are noted on the file but don't flag it: a slice isn't a real file, and those checks misfire on fragments.
- **What it costs:** it reads each file once more, only when the file is new or has changed, or when it is due for a re-sweep: after the signatures have moved 30 versions on (`resweep_after_signature_updates`) or 30 days have passed (`resweep_after_days`), whichever comes first. That is longer than the `rescan_after_signature_updates` interval for ordinary files, since a re-sweep reads every large file in full again. Slices go to clamd through memory, never as a copy on disk, and are sized to fit clamd's limits (at most 256 MiB). Raising clamd's `MaxFileSize` to `2000M` means fewer, bigger slices.
- **Sweep results are left alone by the normal rescans,** which can't see what the sweep saw and would wipe its verdict. A sweep result changes only when the file changes, or when the file is re-swept.

**YARA, for what the slices miss.** A slice has its own start and end, so two kinds of ClamAV signature can't match in one: those tied to a position (a byte offset, a distance from the end of the file, an executable's entry point or sections), and patterns that can stretch further than the slices overlap (1 MiB). When a YARA engine is installed, the sweep also runs those signatures over the whole file in one pass, after the slices. Ensign translates them from ClamAV's own databases into YARA rules; everything else stays with the slices. A hit flags the file infected like a slice hit, and the report says YARA found it. A file with no hit is still **not fully scanned**: the YARA pass covers what the slices miss, nothing more.

- **Engine:** yara-x, VirusTotal's rewrite of YARA in Rust, installed with Ensign since 0.10.0. The original YARA only gets bug fixes now, and yara-x is memory-safe, which matters for an engine that parses untrusted files inside Ensign's own process. Without it, the sweep runs as before and the run says the YARA pass is off.
- **Kept current with freshclam:** before any run that sweeps, Ensign compares ClamAV's databases with the ones the rules were made from, and rebuilds the rules if freshclam has changed them. `python3 main.py --update-rules` rebuilds them on demand and shows what was translated and what was skipped.
- **Checked every time:** a rebuild that fails (an unreadable or damaged database, say), or one that suddenly yields fewer than half the rules it did last time, is shown in red at the top of the run, before scanning starts. The previous rules stay in use, and the run tries again next time. A new yara-x version also triggers a rebuild. The rules must also pass a self-test each time they load, or they aren't used. A drop in the count you know is real (ClamAV retired signatures) is accepted by running `--update-rules`.
- **Runs in its own process:** yara-x reads a file by mapping it into memory, and if another program makes the file shorter mid-read (a game update, say), the kernel stops the reading process outright. So the YARA pass runs in a separate process that gets the file Ensign already has open: if it is stopped, the run goes on, and the file is noted as changed during the YARA pass and stays not fully scanned. It runs as the same user as Ensign (so as root under `sudo`), and it leaves no core dump when it is stopped: its memory holds pieces of the files it scans, so a dump would copy them to disk (and set off your desktop's crash alert). A file YARA can't finish within an hour is noted as timed out, and isn't tried again until it changes or the signatures move on.
- **Where they live:** `yara/` in your data directory, as plain YARA source text, never compiled, since a file of compiled rules holds every signature's raw bytes and ClamAV flags it. Your own rules, for hunting payloads hidden in ordinary files, are planned separately and will have their own folder.
- **Accuracy:** the translation was checked against `clamscan` on the same files (see [`docs/Large_Files_Research.md`](docs/Large_Files_Research.md)); a signature that can't be translated exactly is skipped and counted, never approximated. Signatures from unofficial databases keep ClamAV's `.UNOFFICIAL` suffix, so `--allow` and `--clamav-report` see the same name clamd would give.

`clamscan` unpacks archives in `/var/tmp` rather than `/tmp`, which on many systems (Arch among them) is held in RAM. Ensign hands `clamscan` the files it has already opened, named by descriptor (`/proc/self/fd/N`). `clamscan` turns that back into the file's current path and opens it again, so it needs read permission on the file. Run under `sudo`, Ensign starts `clamscan` as the `clamav` user, not as root: like clamd, it parses untrusted files, and a crafted file that hits a bug in one of its parsers would otherwise get root. The `clamav` user can't read your private files (mode 600, say), so those come back "Access denied". Each of them is then scanned again on its own, fed to `clamscan` on stdin from Ensign's open file, still as `clamav`. `clamscan` copies stdin to a temporary file in `/var/tmp` first; Ensign makes sure only `clamav` can read that copy, and `clamscan` deletes it when done. Each such file takes its own `clamscan` run, which loads the signatures again.

`AlertExceedsMax yes` in clamd.conf is worth setting. Without it, clamd also says "OK" for an archive that unpacks to more than `MaxScanSize`, and Ensign can't tell from the file's size. With it, clamd flags these, and Ensign rescans them with `clamscan` (it doesn't count them as infected).

Filenames that aren't valid UTF-8 (common in old archives, Wine/Proton folders and files from Windows) are tracked like any other: they're stored as their original bytes and shown with those bytes as `\xNN`, e.g. `caf\xe9.txt`.

### If clamd still can't read some files

Since clamd reads files through the handle Ensign passes it, a "could not read" result usually means something outside Ensign is stopping clamd: most often an AppArmor or SELinux policy confining it, which can refuse even a handle that was handed over. Check the kernel log during a scan (`journalctl -k | grep -i -e apparmor -e avc`). Once it's fixed, retry with `python3 main.py --rescan-errors`.

If the listed files no longer exist (temp files, cleaned-up downloads, build artifacts), they're stale records. Run:
    `python3 main.py --purge-missing`


## Persistence Audit

Malware that wants to come back after a reboot has to leave something in a place that starts programs by itself. `--persistence` checks those places:

| Category | Where |
|---|---|
| systemd (system and user) | Units, timers, drop-ins, `.wants` links and generators in `/etc/systemd`, `/usr/lib/systemd`, `/usr/local/lib/systemd`, `~/.config/systemd/user` and `~/.local/share/systemd/user` |
| Shell startup | `~/.bashrc`, `~/.profile`, the zsh and fish files, `~/.xprofile`/`~/.xinitrc`, `~/.config/environment.d`, `/etc/profile` and `/etc/profile.d`, `/etc/environment`, and root's own startup files |
| Desktop autostart | `~/.config/autostart`, `/etc/xdg/autostart`, and KDE Plasma's `env` and `shutdown` scripts |
| cron | `/etc/crontab`, `/etc/anacrontab`, `/etc/cron.*`, `/var/spool/cron` |
| `ld.so.preload` | `/etc/ld.so.preload`, which normally doesn't exist |
| pacman hooks | `/etc/pacman.d/hooks`, `/usr/share/libalpm/hooks` |

Ensign doesn't judge these entries. It compares each one with how it was when you acknowledged it, and lists what is new, changed or gone. An entry is its content (a SHA-256 hash), or the target of a symlink, plus its permissions and owner. Only the hash is stored. Credential-looking files aren't opened here: the audit only fingerprints entries, it doesn't scan them. Their size, modification time and change time stand in for the hash, so editing one and setting its modification time back still shows as a change. (From 0.8.6, the first audit lists such entries as changed once, because the change time is new to their fingerprint.)

**The first run** lists everything, since nothing is acknowledged yet. To keep that list readable, entries a package installed that still match what the package installed are counted per folder ("319 in /usr/lib/systemd/system came from packages and match what the package installed"). Ensign asks your package manager about them. Everything else is listed one by one: entries no package owns (the `.wants` links `systemctl enable` creates are among them), entries that differ from their package, and everything in your home folder. Read through it, then set the baseline:

```
python3 main.py --acknowledge-all
```

After that, a run lists only what changed. Accept an entry you recognize with `--acknowledge PATH`, or everything listed with `--acknowledge-all`. A package update changes the units it ships, so expect a short list after one.

**Without root,** a few places can't be read (`/var/spool/cron`, root's own startup files). They are listed under "COULDN'T CHECK", and entries you acknowledged inside them aren't reported as gone. `sudo python3 main.py --persistence` includes them. Runs with sudo keep their own baseline, in root's data folder (see Running with `sudo`), so the first one lists every entry as new, including ones you already acknowledged as yourself; acknowledge them again with `sudo`.

**Every acknowledgment is logged** to `persistence_acknowledged.log` in your data directory: one line per entry, with the time, the path, and the hash or link target, separated by tabs.

**The limit to know about:** your baseline lives in your data directory, which you own. Malware running as you can write there too, so it could acknowledge its own entry. The log makes such a change visible, but it sits in the same folder. A sudo run's baseline is kept where only root can write, so `sudo python3 main.py --persistence` isn't fooled by such a change (see Malware running as you).

## Steam Watch

Steam's record of a game says where a file came from, not whether it's safe (see False Positives): games have shipped malware inside their official Steam builds, often as a clean game first and a malicious update later (BlockBlasters), or an older game renamed and then updated (Beyond The Dark). Workshop items are uploaded by anyone, and malicious ones have been found (Wallpaper Engine, Project Zomboid, People Playground). So every scan of everything in your config (a scan of chosen paths skips it) also reads Steam's files and, when something needs a look, ends with a section listing it:

| Listed | When |
|---|---|
| **Workshop item carries code** | An item in `steamapps/workshop/content/<appid>/<item>` has programs (`.exe`, `.dll`, ...), scripts (`.bat`, `.ps1`, `.vbs`, `.js`, `.py`, ...) or a password-protected zip in it. Static content (wallpapers, maps, music) shouldn't need any. Lua on its own doesn't count: some games run Lua mods by design |
| **Update worth a look** | A game's build changed since the last scan, and a small update (5 files or fewer added or changed) adds a program or script or changes a program, or the update adds scripts |
| **Game renamed** | A game's name changed since the last scan |

These were measured before they were chosen: across 80 legitimate updates on one gaming machine, the three update rules fired 0, 2 and 3 times. "An update changes a program" fired 25 times, so it isn't one of them.

A Workshop item is listed with its folder, its Workshop page address (as text: Ensign doesn't open it, and the page shows the item's name, which Steam keeps on its servers, not on your disk) and the day Steam last updated it, then its programs and scripts one per line.

Each finding has an ID, which says exactly what it's about: the build's manifest, the item's current files, the game's new name. It's listed until you acknowledge it (`ensign-scan acknowledge-steam ID`, or `--all`), and anything that changes after that gets a new ID and is listed again. `ensign-scan steam` shows the list without scanning. In protected mode, acknowledging needs `sudo --protected`, and the list prints the command to paste.

**What it never does:** change, delete or move anything of Steam's, unsubscribe from or disable an item, start or stop a game, or contact Steam. It reads Steam's text files and manifests and lists folders; it hashes nothing. `steam_watch = false` turns it off.

**What it can't do:** the first time it sees a game it only records it, since there's nothing to compare with yet. A game that's malicious from its first build gives no "update" (the scan and the Steam line under a hit still apply). And like the rest of Ensign's records, the watch's own record of each game is in your database, where malware running as you could change it (see Malware running as you).

## What Gets Rescanned

After the first full scan, Ensign sends a file to ClamAV again only when something suggests it needs it. A file is rescanned when:

- **Its size or modification time changed.**
- **Its inode change time (ctime) changed.** A program can set a file's modification time back to what it was, but it can't do that to ctime. So a file that was edited and then given its old timestamp back is still caught. The side effect is that `chmod`, `chown` and renaming a file also change ctime, so they trigger a rescan too.
- **It was last scanned clean (or allowed by you) under an out-of-date signature database.** A file ClamAV called clean yesterday can match a signature released today. `rescan_after_signature_updates` in your config sets how many signature updates behind a clean file can fall before it is scanned again. Updates arrive about once a day, so the number is roughly days: the default `7` re-checks everything about weekly, and `31` about monthly. The allowed range is 7 to 31 (a value outside it is clamped, with a warning), or `0` to turn this off. Each pass sends every out-of-date file through clamd again, which on a machine with millions of files takes a while, so pick the longest interval you are comfortable with.

**A check that fails never clears a hit.** If a flagged file (infected, or allowed by you) is checked again and the check ends in an error (clamd stopped answering, the file couldn't be read), the earlier verdict stands as long as the file's content is unchanged, or couldn't be read to tell. The infected list shows the error under the file as "Last check", and the next run checks it again. The same goes for the sweep of files too large for ClamAV: a re-sweep that couldn't finish the part that found the hit leaves it in place (and a YARA pass that timed out is tried again on the usual re-sweep schedule, not every run).

The first run after upgrading from a version that didn't track ctime or signature versions scans every file once. After that it settles back to scanning only what changed.

## Alerts

When a scan ends with infected files, Ensign sends a critical desktop notification (needs `notify-send`). That alert behaves differently from the normal ones, because an alert that sits on top of a game until you tab out and dismiss it is a nuisance.

- **It closes itself** after `infected_alert_seconds` (default `60`). `0` leaves it up until you dismiss it. KDE Plasma ignores the timeout that `notify-send` sets on critical alerts, so Ensign closes the alert itself over D-Bus with `gdbus`.
- **By default it only does that while a Steam game is running.** With `infected_alert_only_while_gaming = true`, a scan you start yourself in a terminal leaves the alert up for you to come back to, unless a Steam game is running (Ensign looks for Steam's `reaper SteamLaunch AppId=` process). Steam open and idle doesn't count. `false` always auto-closes.
- **Runs with no terminal always auto-close.** A scheduled run (a service or cron job) has nobody to come back to the alert.
- **A new infected alert replaces the previous one** instead of stacking up. Ensign remembers the last alert's ID in `alert_state.json` in the data directory, and only trusts it within the same boot. If that file is root-owned (see the first-run note under Usage), replacement quietly stops working.

## Logs

Errors are written to one log file per run: `<data_dir>/logs/ensign-YYYYMMDD-HHMMSS.log`, which is `~/.local/share/ensign-scan/logs/` unless you've set a custom `data_dir`. A run with no errors leaves no file.

- **Repeats are collapsed.** The first 20 occurrences of each distinct error are logged in full, then only counted, with a one-line total at the end of the run. One repeating problem (Ensign once logged 302,289 "stat failed" lines for broken symlinks) can't fill the disk.
- **Old logs are deleted automatically.** Runs older than `log_keep_days` (default `90`) go first. If the folder is still over `log_max_total_mb` (default `2048`), the oldest go next, so the size limit wins. `0` turns either rule off. Only files named `ensign-*.log` in that folder are ever deleted.
- Older versions wrote one `error_logs.txt` file. It is no longer used and can be deleted.

## Explaining Findings

When a scan finds an infected file, or `--verify-packages` finds a mismatch, Ensign prints a short `ⓘ` note under it saying what the threat name or mismatch reason generally means. The point is to help you tell a false positive from something worth chasing.

- **Curated notes first.** Ensign ships a small table of researched notes, and you can add your own (see Customizing below).
- **Everything else is decoded from the name.** ClamAV names follow `Platform.Category.Name-SignatureID-Revision`, so for a name with no curated note Ensign describes what the name says. A Windows-only signature on Linux, for example, gets a **Hint** that it is often a false positive. A hint is only a pointer: check the file before you decide.
- **Findings are grouped by threat name,** so a signature that hits many files is explained once. Each file gets a context line: size, last modified date, and whether a package owns it.
- **All local and advisory.** Nothing is looked up online, and the notes never change a scan result.

## False Positives

ClamAV includes heuristic signatures (like `SVGDynamicFunction`) that can match on legitimate code patterns — for example, JS build tools that generate functions at runtime from template/markup content (Vue's `compiler-sfc`, Vite's dependency cache) can trigger a phishing-heuristic match despite being ordinary framework code. Treat an `infected` status as a reason to look closer: it doesn't prove the file is malicious. Check what the file actually is and, if it looks like legitimate tooling, search the threat name plus the library name before assuming compromise.

**If you're sure it's a false positive**, `--allow PATH` tells Ensign so, and you can do two more things besides:

- **Report it to ClamAV,** so the signature gets fixed for everyone. `--clamav-report PATH` prepares the report for you:
  - it hashes the file again, so the report is about the exact content that was flagged;
  - it scans the file again with your current signatures. If ClamAV no longer flags it, the false positive has already been fixed and there's nothing to report;
  - a signature whose name ends in `.UNOFFICIAL` doesn't come from ClamAV but from a third-party signature set, so Ensign tells you to report it to whoever provides that set instead;
  - otherwise it writes a short report to `clamav-reports/` in your data directory (under `sudo`, root's: `/var/lib/ensign-scan/clamav-reports/`, readable only with `sudo`): the signature name, SHA-256 and MD5, size, file type and ClamAV versions. It contains no file name, path, username or hostname;
  - it then tells you how to submit it, through ClamAV's form at <https://www.clamav.net/reports/fp> or with ClamAV's `clamsubmit` tool. ClamAV needs the file itself, so the file to attach is named on screen. It's never copied anywhere, because if the detection were real, the copy would be a second piece of malware.

  Ensign never submits anything itself. Submitting sends the whole file to Cisco (ClamAV's owner), so don't submit anything private; Ensign warns you if the file is in a personal folder like Documents or Downloads. A file the sweep flagged can't be reported this way: ClamAV can't scan a file that large, so it can't reproduce the detection.
- **Allow it in Ensign** with `--allow PATH`. Ensign first hashes the file again, so you can only allow the exact content that was flagged, then asks you to confirm. An allowance is deliberately narrow:
  - it covers that exact content (its SHA-256), flagged by that exact signature, found by that exact engine. Identical copies elsewhere are covered too, since they're the same false positive. If the file changes, a different signature flags it, or another engine finds it, it's flagged again;
  - the sweep's YARA pass (see Large files) counts as its own engine, `clamav-yara`, and `--allow` says which engine found the file. Allowances made before 0.10.0 are ClamAV's, so a large file the YARA pass flagged, and that you allowed then, is flagged once more after the upgrade: check it, then allow it again;
  - allowed files don't count as infected for alerts or the exit code, but they're never hidden: every run ends with the folders and files you allowed within what it scanned (the `--list-allowed` layout, up to 10 files), and `--list-allowed` shows them all;
  - they're still rescanned when the signatures update, so once ClamAV fixes the false positive the file simply turns clean;
  - `--unallow PATH` undoes it.
- **Allow a whole folder's worth** with `--allow-folder FOLDER --signature NAME`, when one signature flags many files in one place (a large text dataset, say, where the pieces of a signature turn up by chance across gigabytes of text). It allows every file under the folder, subfolders included, that this signature flags right now, with one confirmation. Leave out `--signature` to see which signatures are flagged there.
  - **It's a snapshot.** Each file gets the same allowance `--allow` gives, tied to its own content. Nothing is allowed for being in the folder, so a file that appears there later, or an allowed file that changes, is flagged as infected again;
  - **Ensign tells you what to do next.** When that happens, the run lists those files under "NEW IN FOLDERS YOU ALLOWED" with the two commands for allowing them: the folder command again, or `--allow` for one file. Ensign runs neither. Check the files first;
  - **Files that can run code are left out.** A file in a format that can run code the moment a program loads it (`.pkl`, `.pickle`, `.pt`, `.pth`, `.ckpt`, `.bin`, `.joblib`) is never part of a folder allow, and neither is a file with the very same content as one. Each needs its own `--allow PATH`;
  - **A file that changed since its last scan is left out** until it has been scanned again;
  - `--unallow-folder FOLDER --signature NAME` undoes it for everything allowed under that folder, or allowed from it, for that signature.

**A second opinion from your package manager.** At the end of each scan, Ensign asks the package manager (pacman, dpkg or rpm; see `package_verification`) about every flagged file. Under the file, the report then says:

- **Likely false positive** when a package installed the file and it's still exactly what the package put there. A package is not a guarantee: an AUR package is a script anyone can publish. So the file stays flagged until you decide;
- **Package** when a package owns it but the file differs from what it installed (worth a closer look), or couldn't be compared.

**A second opinion from Steam.** For a flagged file in a Steam game folder (`steamapps/common/<game>/...`), Ensign also looks it up in Steam's own record of that game: the depot manifests in Steam's `depotcache` folder, which list every file of the build you have installed with its SHA-1 (what "Verify integrity of game files" checks against). Nothing is downloaded and nothing is sent; Ensign reads those files and hashes only the flagged file. Under the file, the report then says:

- **Matches Steam's build** when Steam's record has the file with exactly these bytes. That shows where the file came from, not that it's safe: games have shipped malware inside their official Steam builds (PirateFi, Chemia, BlockBlasters, Beyond The Dark), and those files matched Steam's record. The record is also in your home folder, where anything running as you could change it along with the file. So it's never called a likely false positive, and the file stays flagged until you decide;
- **Warning** instead, when the file matches Steam's build but ClamAV names a known malware family (Vidar, Lumma, StealC, DarkKomet and others): real malware has shipped exactly this way. Investigation required;
- **Steam** when Steam's record lists the file with other contents. Some games rewrite their own files, so on its own this isn't a warning: the game may have changed it, or something else did;
- **Workshop** for Steam Workshop content (`steamapps/workshop/content/...`): uploaded by community members and not reviewed like a game's own build, and malicious items have been found before (Wallpaper Engine, Project Zomboid, People Playground). Items carrying programs, scripts or password-protected archives deserve the most suspicion.

A file the record doesn't list gets no line, and neither does anything in a Proton prefix (`compatdata`), the shader cache, or files a game's own launcher downloaded: those are where a malicious game's later stages land, and no record of Steam's covers them. Files outside Steam (a Wine prefix of your own, say) aren't covered either.

The answer is kept with the content it was checked against, so once the file changes it's no longer shown. It never changes a verdict, and it's left out of the report sent to ClamAV except for one line: when the package manager vouches for the file, `--clamav-report` names the package, which helps ClamAV find the file. (Steam's answer isn't in that report.)

Allowances live in Ensign's own database. Ensign doesn't touch ClamAV or its signatures, so nothing else that uses clamd is affected. (ClamAV's own allow lists, `.sfp` and `.ign2` files in its database folder, work for every program using clamd. See ClamAV's documentation if that's what you want.)

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
- **`[custom_secrets]`** adds paths that look like secrets stores. The keys are `high_dirs`, `high_dir_paths`, `high_filenames`, `high_extensions`, `high_scoped_filenames`, `high_prefixes`, `medium_prefixes` and `medium_extensions`. Folder entries match whole folder names, in order (`myapp/keys` matches `~/myapp/keys/`, not `~/myapp-old/keys/`). A HIGH match means the file is scanned but no hash of it is stored (see How clamd Reads Your Files); a MEDIUM match changes nothing yet. See `ensign_scan/secrets.py` for what the tiers mean.

The first time you run Ensign it writes a starter `config.toml` with all of these documented as comments. `config.example.toml` in the repo has the same content.

## Querying the Database Directly

Most day-to-day questions are covered by the commands above. But the database is just SQLite, kept locally at the path printed in the `Database:` line when Ensign starts (`~/.local/share/ensign-scan/system.db` unless you've set a custom `data_dir`) — for anything the built-in reports don't cover, `sqlite3` gets you there directly.

The `files` table's `scan_status` column is one of: `clean`, `infected`, `allowed` (flagged, and you allowed it), `incomplete` (not fully scanned, see Large files), `error`, `pending`, `classified` (from earlier versions, until that file is scanned).

See the details behind current errors:
```
sqlite3 ~/.local/share/ensign-scan/system.db "SELECT filepath, scan_result FROM files WHERE scan_status='error';"
```

See which clean files Ensign treats as credential files (scanned, no hash kept):
```
sqlite3 ~/.local/share/ensign-scan/system.db "SELECT filepath FROM files WHERE scan_status='clean' AND file_hash='';"
```

The list of paths/filenames/extensions used to make that call isn't arbitrary — see `docs/Classified_Paths_Research.md` for the sourcing behind each entry, and `ensign_scan/secrets.py` for the confidence tiers and how `hash_not_stored()` uses them.

See infected files and what triggered them:
```
sqlite3 ~/.local/share/ensign-scan/system.db "SELECT filepath, threat_name FROM files WHERE scan_status='infected';"
```

Each hit is also kept as a finding (which engine, which signature, which content, and whether it's open, allowed, or gone because a later scan found nothing or the file changed), and second opinions are in `evidence`:
```
sqlite3 ~/.local/share/ensign-scan/system.db "SELECT f.filepath, x.engine, x.signature, x.state FROM findings x JOIN files f ON f.id = x.file_id;"
```

Look up everything Ensign knows about one specific file:
```
sqlite3 ~/.local/share/ensign-scan/system.db "SELECT * FROM files WHERE filepath='/full/path/to/file';"
```

## Reporting Bugs and Security Issues

**Security vulnerabilities:** please don't open a public issue. Report them privately through the repository's **Security** tab (Advisories → Report a vulnerability). `SECURITY.md` explains what counts as a security bug for Ensign and what to expect after you report one.

**Bugs, false positives and feature ideas:** open an issue and pick the matching form. The bug and detection forms ask for the output of:
```
ensign-scan --diagnostics
```
It reports versions, settings and counts only: no paths, usernames, hostnames or file names. Anything else you paste (output, tracebacks) can contain those, so please redact them first, and never attach a scanned file or your Ensign database.

If a flagged file's threat name doesn't end in `.UNOFFICIAL`, the signature is ClamAV's own, and only ClamAV can fix it. The issue page links to their report forms.

## For Steam users: a note on Proton's 'Z:' drive

When developing Ensign, there wasn't anything to stop the walk from wandering and rescanning symlinks since I didn't understand them. You can imagine my surprise when the db was gradually growing in size despite not installing any updates or playing any new games. After some digging I found the culprit. Steam's Z: drive in Proton. The Z: drive allows steam to see and interact with your file system on linux. Nothing wrong with that. 

What I had failed to understand was that it included the ENTIRE system. INCLUDING ALL THE SNAPSHOTS (system backups)! So as a result, the db was seemingly growing by hundreds of thousands of files as it identifies files by the file paths. Example: ~/Pictures/IMG001.jpg would also show up as ~/.steam/path/to/z:/home/user/Pictures/IMG0001.jpg. A duplicate entry despite being the same file. Now take into account all the usual games that are in a user's steam library and all of those individual files, the walk would take literally days, going onto weeks, just to finish one sweep of the system.

The reason it kept compounding wasn't just that Z: mirrored the whole filesystem — it's that Z: pointing back at `/` (The root directory, where everything exists beneath it) also mirrored itself. A snapshot taken of the system would include a copy of the Z: drive, which pointed back at `/`, which contained the Steam compatdata folder, which contained more snapshots, each with their own Z: drive pointing back at `/` again. So the walk wasn't just duplicating files — it was recursively duplicating its own duplicates, with the depth compounding on every snapshot layer. For a time it was quite literally logging backups of the backups of the backups, REGARDLESS OF HOW MANY LAYERS DEEP IT WENT.

Hence why for this build, I've opted to set followlinks to False in the walk function itself:

`for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):`

That way there's no endless cascade of walking a single directory. Symlinked directories are skipped entirely now — the walk sees them but never descends in. Individual files that happen to be symlinks (like a shortcut to a document) are still followed and scanned through to their real target, same as before — it's only symlinked directories that stopped getting wandered into.

## Transparency
Ensign tries to be upfront about what it can and can't do. Files it couldn't fully scan are reported as such and are never called clean, and its known limits, such as malware running as your own user, are written down in [What Ensign Touches, and What It Can't See](#what-ensign-touches-and-what-it-cant-see). If you find a gap that isn't documented, please open an issue, or report it privately if it's a security problem.

## Last Note
This readme will be updated when needed. IE. FAQ questions that keep getting asked, or something needs further explanation. 
