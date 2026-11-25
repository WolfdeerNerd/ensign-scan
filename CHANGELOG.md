# Changelog

What changed in each release of Ensign, newest first. Each entry is written in the pull request that bumps the version. Releases before 0.10.0 are described on the [GitHub releases page](https://github.com/WolfdeerNerd/ensign-scan/releases).

Versions follow `major.minor.patch`: a new feature bumps the middle number, a fix or a cosmetic change the last one.

## Unreleased

### Added
- **Commands, in the style of pipx or git.** `ensign-scan allow PATH`, `ensign-scan list infected`, `ensign-scan uninstall` and the rest: each is the same run as its original option (`--allow PATH`, `--list-infected`, `--uninstall`), and every original option keeps working. `ensign-scan help` lists them, grouped, and `ensign-scan help COMMAND` explains one. A first word that's a command is the command, unless a file or folder by that name is where you are: then Ensign asks which you meant, and shows `./NAME` for the folder and the original option for the command.

### Changed
- `--help` shows the commands first, then the options in groups (scanning, results, decisions, checks, setup).
- The commands Ensign suggests in its output use the new form: `ensign-scan allow PATH`, `ensign-scan list infected`, `sudo ensign-scan --protected unallow PATH`. The original options they stand for still work.

### Fixed
- Under `sudo`, the commands Ensign suggests start with `sudo`, so pasting one acts on root's records and decisions, the ones that run used. In protected mode, the hint for listing a folder's infected files no longer adds `--protected`, which that command refuses.

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
