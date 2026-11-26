# Changelog

What changed in each release of Ensign, newest first. Each entry is written in the pull request that bumps the version. Releases before 0.10.0 are described on the [GitHub releases page](https://github.com/WolfdeerNerd/ensign-scan/releases).

Versions follow `major.minor.patch`: a new feature bumps the middle number, a fix or a cosmetic change the last one.

## Unreleased

### Added
- The Steam watch: every scan reads Steam's files and lists what needs a look, until you acknowledge it. **Workshop items carrying code** (programs, scripts or password-protected zips; static content shouldn't need any), **updates worth a look** (a small update that adds a program or script or changes a program, or an update that adds scripts) and **renamed games**. New commands `ensign-scan steam` and `ensign-scan acknowledge-steam ID | --all` (`--steam`, `--acknowledge-steam`, `--acknowledge-steam-all`), and exit code 5 when something is listed. In protected mode, acknowledging needs `sudo --protected`. `steam_watch = false` turns it off. Reads only: it never changes anything of Steam's.
- A second opinion from Steam: a flagged file in a Steam game folder is looked up in Steam's own record of that game (the depot manifests in `depotcache`, which list every file of your installed build with its SHA-1). When the record has the file with exactly these bytes, the report says it **matches Steam's build**: where it came from, not that it's safe, since games have shipped malware inside their official Steam builds. When ClamAV also names a known malware family (Vidar, Lumma, StealC, DarkKomet...), that line is a **warning** instead. When the record lists the file with other contents, the report says so. Steam Workshop content gets its own caveat, and Proton prefixes and the shader cache get no line. Local and read-only: nothing is downloaded, and only the flagged file is hashed. It never changes a verdict.

## 0.11.0

### Added
- **Commands, in the style of pipx or git.** `ensign-scan allow PATH`, `ensign-scan list infected`, `ensign-scan uninstall` and the rest: each is the same run as its original option (`--allow PATH`, `--list-infected`, `--uninstall`), and every original option keeps working. `ensign-scan help` lists them, grouped, and `ensign-scan help COMMAND` explains one. A first word that's a command is the command, unless a file or folder by that name is where you are: then Ensign asks which you meant, and shows `./NAME` for the folder and the original option for the command.

### Changed
- `--help` shows the commands first, then the options in groups (scanning, results, decisions, checks, setup).
- The commands Ensign suggests in its output use the new form: `ensign-scan allow PATH`, `ensign-scan list infected`, `sudo ensign-scan --protected unallow PATH`. The original options they stand for still work.
- The README's disclaimer now says plainly that most of the code was written by Claude under the author's direction, and a short Transparency section points to Ensign's documented limits.

### Fixed
- Under `sudo`, the commands Ensign suggests start with `sudo`, so pasting one acts on root's records and decisions, the ones that run used. In protected mode, the hint for listing a folder's infected files no longer adds `--protected`, which that command refuses.
- A run given `--config` now includes it in the commands it suggests, so pasting one acts on the same config and database.
- `uninstall`, in a `data_dir` that isn't Ensign's alone (your home, say), could delete a folder of yours by its name: a `logs`, `yara` or `clamav-reports` folder, or a `system.db` some other program made. There it now deletes only files Ensign is known to write (`logs/ensign-*.log`, its YARA rules, its reports), and the database and the files beside it only when the database is Ensign's. A folder goes only if that leaves it empty.
- `uninstall` with `sudo` no longer saves other users' protected decisions into your home when you ask it to save yours: only root's own and your own.
- `uninstall` points out an Ensign folder that is a link to somewhere else, and leaves it, rather than skipping it without a word.
- `uninstall` given `--config` (or `$ENSIGN_CONFIG`) also removes Ensign's files from that config's `data_dir`, and names the config file itself, which it leaves for you.
- `uninstall`, in a shared `data_dir`, no longer removes an empty `logs`, `yara` or `clamav-reports` folder that never held Ensign's files: only folders that its own deletions emptied.
- `uninstall` with `sudo` no longer skips root's `data_dir` when its name only starts like `/var/lib/ensign-scan` (`/var/lib/ensign-scan2`, say). And when `/var/lib/ensign-scan` isn't root's (so it's left alone), the decisions in it aren't offered for saving either.
- File names with Unicode that reorders or breaks a line without showing anything (right-to-left override, the directional isolates and marks, the line and paragraph separators) are now written out as `\u202e` and so on, everywhere Ensign shows a name: the terminal, the log, notifications. `invoice<U+202E>fdp.exe` can no longer pass itself off as `invoiceexe.pdf` in a report.
- A command Ensign suggests for a file whose name has a control character or such Unicode in it can be pasted again: the name is written in the shell's `$'...'` form, which bash and zsh turn back into the exact name.
- `rescan_after_days` set very high (a million days, say) crashed the run at the end of the scan; now nothing is stale. Set to 0, it rescanned every file on every run; now 0 turns it off, like the other settings. The example config now explains it.

## 0.10.0

### Added
- **Findings and engines.** Every hit now records which engine found it (ClamAV, or the sweep's YARA pass, `clamav-yara`), for which content, and whether it's open, allowed or gone. An allowance covers only the engine it was made for, so a hit from another engine is flagged.
- **A second opinion from your package manager.** At the end of a scan, Ensign asks pacman, dpkg or rpm about each flagged file. One a package installed, still unchanged, is labelled "Likely false positive" under the file; it stays flagged until you decide. `--clamav-report` names the package.
- **`ensign-scan --uninstall`.** Deletes everything Ensign made (with `sudo`, root's files too), after listing it and asking you to type `uninstall`. Offers to save your decisions to a file first, and says how to remove the program itself.

### Changed
- **yara-x is installed with Ensign,** for the sweep's YARA pass. `pipx upgrade ensign-scan` adds it to an existing install; `ensign-scan[yara]` still works.
- **A check that fails never clears a hit.** An error on a flagged file whose content hasn't changed keeps its verdict, shown as "Last check" in the infected list. A re-sweep that couldn't recheck the part that found a hit leaves it in place.
- The README has a "False Positives" section of its own, and its end is reordered.

### Fixed
- An allowance table rebuild interrupted by a crash could lose every allowance. It's now one transaction.
- The protected decisions file, and configs Ensign writes, could be left half written by a crash. They're now complete or not there.
- A large-file sweep that couldn't finish cleared an earlier hit.

### Upgrading
- On the first start, the database is upgraded once. Any `sudo ensign-scan` command upgrades protected users' decisions files.
- A large file the sweep's YARA pass flagged, and that you allowed before 0.10.0, is flagged once more: old allowances are ClamAV's. Check it, then allow it again.
