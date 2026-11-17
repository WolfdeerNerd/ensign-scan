# Roadmap

Where Ensign is headed. There are no dates, and plans can change. Details live in GitHub issues; this page stays short.

Want something that isn't here? [Open a feature request](https://github.com/WolfdeerNerd/ensign-scan/issues/new/choose).

## What won't change

Every feature has to fit these criteria:

- **Everything stays local.** No file, hash or result leaves your machine. Ensign never uploads anything or looks anything up online.
- **Ensign only advises.** It never changes permissions, config files or anything else on your system. It tells you what it found and what you could do.
- **Fewer false positives over wider coverage.** A warning should mean something. Ensign would rather miss a borderline case than cry wolf.
- **Never "clean" without a real scan.** A file that couldn't be scanned fully is reported as such, never as clean.

## Next

Decided, and coming next:

- **Your own YARA rules.** Custom rules, written from scratch, for payloads hidden inside ordinary files, checked on every file as a second check alongside ClamAV. They will use yara-x, which the sweep already uses for files too large for ClamAV.

## Planned

Decided, no order yet:

- **More persistence checks.** udev rules, `modules-load.d`, `sudoers.d` and PAM, in the persistence audit (`--persistence`). Later, the audit as part of every run, once it's quiet.
- **Reports for Ensign's own mistakes.** A scrubbed report for Ensign's GitHub detection form, like `--clamav-report` does for ClamAV.
- **clamd.conf suggestions.** One section with settings worth changing in clamd's config and why, such as `MaxThreads` or `TemporaryDirectory`. Advice only, as always.
- **A steadier ETA.** The time estimate still swings a lot during large-file scanning.
- **Scheduled scans.** A service that runs Ensign regularly, without a flood of alerts, especially while you're gaming.
- **Status history.** A record of each file's status changes over time, so you can see which files or threats come up most often.
- **AUR package.**

## Ideas

Not decided. Discussion welcome:

- **Name the provider of `.UNOFFICIAL` signatures** in `--clamav-report`, by finding which signature file the name comes from.
- **NSRL hashes.** NIST's National Software Reference Library, as a local second opinion on flagged files.
- **Hidden payloads.** Spotting data tucked inside ordinary files, such as an image with something appended.
- **Folder-level secrets detection.** Treat a folder as a secrets store when most of its files look like credentials.
- **The sweep on by default,** once it has proven itself.
- **Looking inside archives over 2 GiB.** Open zip and tar archives ClamAV can't scan whole, and hand it each member. An experiment showed it works; see [`docs/Large_Files_Research.md`](docs/Large_Files_Research.md).
- **A graphical interface,** if people want one, in a way that honors ClamTk.
  - **Scan from your file manager:** a small button in your file manager (Dolphin, Nautilus and the like) that scans the folder you have open.

## Not planned

These come up, but don't fit the rules above:

- **Online lookups** (VirusTotal, MalwareBazaar and the like): they send data off your machine.
- **Ensign fixing things itself,** such as permissions. A separate, optional tool that uses Ensign may do this one day, but Ensign itself will keep only advising.
- **Becoming a general-purpose antivirus.** Ensign grows step by step, where a real gap shows up.

## Requested by users

Open feature requests: [issues labelled `enhancement`](https://github.com/WolfdeerNerd/ensign-scan/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement).
