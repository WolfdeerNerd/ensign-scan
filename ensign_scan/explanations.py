"""Curated, human-readable explanations for scan findings.

Same two-tier shape as secrets.py: a built-in dict shipped in code, plus
an additive-only extension loaded once from the user's config.toml via
load_custom(). Nothing here does a network lookup or signature-database
query -- these are hand-curated notes, not a live threat feed, aimed at
helping tell a real finding apart from a known-noisy false positive.

Curated entries are matched EXACTLY against ClamAV's `threat_name` column.
Unlike secrets.py's prefix/substring matching, there's no scoping to get
wrong here. A name with no curated entry falls back to decode_threat_name(),
a purely structural reading of the name (still fully offline).
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ThreatExplanation:
    description: str
    false_positive_note: str | None = None
    # True when produced by decode_threat_name() (a structural reading of
    # the name) rather than a curated entry. Reports label the note as a
    # hint instead of a "known false positive".
    decoded: bool = False


# Seed entries for signatures already known to misfire -- see the
# README's note on ClamAV heuristics. Add more as you hit them, or via
# [custom_threats] in config.toml (see config.example.toml).
_BUILTIN_THREATS: dict[str, ThreatExplanation] = {
    "SVGDynamicFunction": ThreatExplanation(
        description="Heuristic match for JS that builds functions at runtime from "
                     "template/markup content -- a phishing-style pattern.",
        false_positive_note="Common in legitimate build tooling (Vue's compiler-sfc, "
                             "Vite's dependency cache) that generates code this way. "
                             "Check what the file actually is before assuming compromise.",
    ),
    # The two below are alerts ClamAV raises on purpose when the matching
    # clamd.conf option is on (AlertExceedsMax / AlertOLE2Macros); names
    # and meanings are from the clamd.conf / clamscan man pages.
    "Heuristics.Limits.Exceeded": ThreatExplanation(
        description="Not a malware finding. The file exceeded a scan limit "
                    "(MaxFileSize, MaxScanSize or MaxRecursion), so ClamAV flagged it "
                    "because it could not be fully scanned.",
        false_positive_note="Large archives, disk images and game data trigger this "
                            "routinely. It means 'unscanned', not 'infected'.",
    ),
    "Heuristics.OLE2.ContainsMacros": ThreatExplanation(
        description="Not a malware signature. The Office (OLE2) file contains VBA "
                    "macros and your clamd has AlertOLE2Macros enabled.",
        false_positive_note="Plenty of legitimate spreadsheets and documents contain "
                            "macros. Worth a look only if you did not expect any.",
    ),
    "Win.Exploit.CVE_2015_2503-1": ThreatExplanation(
        description="ClamAV exploit signature for CVE-2015-2503, a Microsoft Office "
                    "elevation-of-privilege vulnerability fixed in bulletin MS15-116.",
    ),
    "Win.Malware.Aotera-10060486-0": ThreatExplanation(
        description="ClamAV signature named 'Aotera' (usually a malware family name), "
                    "classed only as general Windows malware. Signature 10060486, "
                    "original revision. No public write-up of what it matches was found.",
    ),
}

# Covers every reason string _MISMATCH_RE can currently produce (see
# pacman.py). A gap here just means a reason prints with no explanation
# line, not an error.
_BUILTIN_PACMAN_REASONS: dict[str, str] = {
    "Size mismatch":
        "File size differs from what pacman recorded at install time.",
    "Modification time mismatch":
        "Timestamp differs from install time -- common after any edit or "
        "package update; says nothing about the file's content.",
    "UID mismatch":
        "Owning user differs from what the package expects.",
    "GID mismatch":
        "Owning group differs from what the package expects.",
    "Permissions mismatch":
        "File mode differs from what the package expects.",
    "Symlink path mismatch":
        "Symlink target differs from what the package expects.",
    "SHA256 checksum mismatch":
        "File content itself differs from what pacman installed -- "
        "the one actually worth a closer look.",
    "Permission denied":
        "pacman couldn't open this file or directory, so it was not checked. "
        "Usually means pacman wasn't run as root.",
    "failed to calculate SHA256 checksum":
        "pacman couldn't read the file to verify it (permissions, or the "
        "file is gone).",
}

# dpkg and rpm report differences with the same test letters (see
# pkgdb/verifyfmt.py); these are the reasons that parser produces.
_BUILTIN_PACKAGE_REASONS: dict[str, str] = {
    "Size mismatch":
        "File size differs from the package's record.",
    "Mode mismatch":
        "File type or permissions differ from what the package installed.",
    "Checksum mismatch":
        "File content itself differs from what the package installed -- "
        "the one actually worth a closer look.",
    "Device number mismatch":
        "A device file's numbers differ from the package's record.",
    "Symlink path mismatch":
        "Symlink target differs from what the package installed.",
    "Owner mismatch":
        "Owning user differs from what the package expects.",
    "Group mismatch":
        "Owning group differs from what the package expects.",
    "Modification time mismatch":
        "Timestamp differs from install time -- common after any edit or "
        "package update; says nothing about the file's content.",
    "Capabilities mismatch":
        "The file's Linux capabilities (fine-grained root powers) differ "
        "from what the package set.",
    "File missing":
        "The package installed this file, but it isn't there now.",
    "Could not read file":
        "The package manager couldn't open this file, so its content was not "
        "checked. Usually means the check wasn't run as root.",
}

# Module-level tables load_custom() extends in place. Everything else
# reads from these, never from the _BUILTIN_* dicts directly.
THREAT_EXPLANATIONS: dict[str, ThreatExplanation] = dict(_BUILTIN_THREATS)
PACMAN_REASON_EXPLANATIONS: dict[str, str] = dict(_BUILTIN_PACMAN_REASONS)

_CUSTOM_THREATS_ENTRY_KNOWN_KEYS = {"description", "false_positive_note"}



# --- Structural decoding of ClamAV names (fallback for uncurated names) ---
#
# ClamAV names look like {platform}.{category}.{name}-{signature id}-{revision}
# (docs.clamav.net, "Signature Names"). Reading that structure needs no
# lookup and no database, so it works offline for any name. It only says
# what the NAME says; it never claims to know what the signature matches.

_NAME_RE = re.compile(r"^(?P<body>.+?)(?:-(?P<sig>\d+)-(?P<rev>\d+)|-(?P<single>\d+))?$")
_CVE_RE = re.compile(r"CVE_(\d{4})_(\d{4,})")

# Only prefixes I'm confident about; an unknown one is shown as-is.
# What each signature is for, said as "This signature is for ...".
_PLATFORMS = {
    "Win": "Windows programs and files", "Dos": "DOS programs",
    "Unix": "Unix/Linux programs", "Osx": "macOS programs", "Andr": "Android apps",
    "Ios": "iOS apps", "Js": "JavaScript", "Html": "web pages (HTML)",
    "Java": "Java programs", "Doc": "Word documents", "Xls": "Excel spreadsheets",
    "Pdf": "PDF files", "Email": "email (messages and their attachments)",
    "Lnk": "Windows shortcut (.lnk) files",
}
_NON_NATIVE_PLATFORMS = {"Win", "Dos"}  # cannot run natively on Linux
# What the signature looks for, said as "a pattern it uses for ...": the
# thing, then what it does in plain words.
_CATEGORIES = {
    "Exploit": "an exploit: code that attacks a flaw in another program",
    "Malware": "malware in general (ClamAV gives no more specific type)",
    "Trojan": "a trojan: malware posing as something legitimate",
    "Backdoor": "a backdoor: code that lets someone control the computer remotely",
    "Downloader": "downloader code: code that fetches more malware from the internet once it runs",
    "Dropper": "a dropper: code that installs other malware it carries inside it",
    "Ransomware": "ransomware: malware that encrypts files and demands payment",
    "Infostealer": "an information stealer: malware that collects passwords, cookies or files",
    "Keylogger": "a keylogger: malware that records what you type",
    "Coinminer": "a cryptocurrency miner: software that uses the computer to mine coins",
    "Adware": "adware: software that pushes ads at you",
    "Spyware": "spyware: software that watches what you do",
    "Rootkit": "a rootkit: malware that hides itself or other malware from the system",
    "Packed": ("a packed program: one compressed or scrambled to hide what it does. "
               "Legitimate software does this too"),
    "Packer": "a packer: a tool for compressing or scrambling programs",
    "Phishing": "phishing: a message or page made to trick you into giving away logins or money",
    "Macro": "a malicious macro: code hidden in an Office document",
    "Test": "a test file, such as the harmless EICAR file",
}


def decode_threat_name(threat_name: str | None) -> ThreatExplanation | None:
    """Explain a ClamAV name from its structure alone. None if the name
    doesn't have a recognizable shape."""
    if not threat_name:
        return None
    m = _NAME_RE.match(threat_name)
    body, sig, rev, single = m["body"], m["sig"], m["rev"], m["single"]
    parts = body.split(".")

    if parts[0] == "Heuristics" and len(parts) >= 2:
        return ThreatExplanation(
            description=f"Heuristic detection '{body}'. Heuristics flag suspicious "
                        f"behaviour or structure; they are not a match against a "
                        f"known malware sample.",
            false_positive_note="Heuristic detections misfire more often than "
                                "signature matches. Check what the file is before "
                                "assuming compromise.",
            decoded=True)

    pua = parts[0] == "PUA"
    if pua:
        parts = parts[1:]
    if len(parts) < 3:
        return None
    platform, category, family = parts[0], parts[1], ".".join(parts[2:])
    if category not in _CATEGORIES and platform not in _PLATFORMS:
        return None  # nothing recognizable; stay silent rather than guess

    looks_for = _CATEGORIES.get(category, f"'{category}' (a category Ensign has no description for)")
    made_for = _PLATFORMS.get(platform, f"'{platform}' files")
    sentences = []
    if pua:
        sentences.append("Flagged as a Possibly Unwanted Application: not necessarily "
                         "malicious (bundled tools, adware, packers).")
    sentences.append(f"ClamAV matched a pattern it uses for {looks_for}.")
    sentences.append(f"This signature is for {made_for}.")
    if family == "Generic":
        sentences.append("Family name: Generic, ClamAV's catch-all name rather than one specific strain.")
    else:
        sentences.append(f"Family name: {family}.")
    cve = _CVE_RE.search(family)
    if cve:
        sentences.append(f"It refers to CVE-{cve[1]}-{cve[2]}, a known vulnerability.")
    if sig is not None:
        sentences.append(f"Signature number {sig}, revision {rev}.")
    elif single is not None:
        sentences.append(f"The -{single} at the end is the signature's revision.")
    hint = None
    if platform in _NON_NATIVE_PLATFORMS and category != "Test":
        hint = ("Windows/DOS-targeted signature. That payload can't run natively on "
                "Linux, so on Arch this is often a false positive or inert cargo "
                "(installers, game assets, Wine prefixes). Still check where the "
                "file came from.")
    return ThreatExplanation(" ".join(sentences), hint, decoded=True)



def explain_threat(threat_name: str | None) -> ThreatExplanation | None:
    """Curated entry (built-in or config) if one exists, else a structural
    decode of the name, else None."""
    if not threat_name:
        return None
    return THREAT_EXPLANATIONS.get(threat_name) or decode_threat_name(threat_name)


def explain_pacman_reason(reason: str) -> str | None:
    return PACMAN_REASON_EXPLANATIONS.get(reason)


def explain_package_reason(reason: str) -> str | None:
    """Notes for dpkg and rpm findings (their reasons share one wording)."""
    return _BUILTIN_PACKAGE_REASONS.get(reason)


def load_custom(config) -> None:
    """Merge config.custom_threats / config.custom_pacman_reasons into the
    module-level tables.

    Additive only: a name that collides with a built-in entry is left
    alone (warned, not overwritten) -- a config typo can't silently
    suppress a curated warning the way it could if overrides were
    allowed. Malformed entries are warned about and skipped individually
    rather than failing the whole load.
    """
    for name, raw in (config.custom_threats or {}).items():
        if name in THREAT_EXPLANATIONS:
            print(f"[ensign] Warning: custom_threats.{name!r} is already built in -- "
                  f"ignored (additive-only; built-in entries can't be overridden)")
            continue
        if not isinstance(raw, dict):
            print(f"[ensign] Warning: custom_threats.{name!r} must be a table with a "
                  f"'description' key -- ignored")
            continue
        for key in raw.keys() - _CUSTOM_THREATS_ENTRY_KNOWN_KEYS:
            print(f"[ensign] Warning: unknown key custom_threats.{name!r}.{key!r} ignored")
        description = raw.get("description")
        if not isinstance(description, str) or not description:
            print(f"[ensign] Warning: custom_threats.{name!r} missing 'description' -- ignored")
            continue
        false_positive_note = raw.get("false_positive_note")
        if false_positive_note is not None and not isinstance(false_positive_note, str):
            print(f"[ensign] Warning: custom_threats.{name!r}.false_positive_note must be "
                  f"a string -- ignored")
            false_positive_note = None
        THREAT_EXPLANATIONS[name] = ThreatExplanation(description, false_positive_note)

    for reason, blurb in (config.custom_pacman_reasons or {}).items():
        if reason in PACMAN_REASON_EXPLANATIONS:
            print(f"[ensign] Warning: custom_pacman_reasons.{reason!r} is already built in "
                  f"-- ignored (additive-only; built-in entries can't be overridden)")
            continue
        if not isinstance(blurb, str) or not blurb:
            print(f"[ensign] Warning: custom_pacman_reasons.{reason!r} has no text -- ignored")
            continue
        PACMAN_REASON_EXPLANATIONS[reason] = blurb
