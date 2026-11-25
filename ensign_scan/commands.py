"""Ensign's commands, in the style of pipx or git: `ensign-scan allow PATH`.

Each command is a short name for one of Ensign's original options, which
all keep working: `ensign-scan allow PATH` and `ensign-scan --allow PATH`
are the same run. translate() rewrites a command line that starts with a
command into the original options, and argparse in cli.py does the rest,
so there is exactly one place that decides what a run does.

A command is the first word that isn't an option. Any other first word is
a path, as before, so `ensign-scan ~/Downloads` still scans that folder.
When the word is a command and also names a file or folder where you are,
Ensign doesn't guess: it stops and shows both ways to say it (`./allow`
for the folder, the original option for the command). A script that passes
paths it didn't choose puts them after `scan --`, where no word is a
command.
"""
from __future__ import annotations

import os
import shlex
import shutil
import sys
import textwrap
from dataclasses import dataclass, field

PROG = "ensign-scan"


@dataclass(frozen=True)
class Command:
    name: str
    args: str          # what follows the name, as usage shows it
    summary: str
    group: str
    flag: str | None   # the original option it stands for
    takes: str = ""    # "paths": PATHs become targets; "each": --flag PATH per PATH; "one": --flag VALUE
    needs: bool = False            # at least one PATH or VALUE
    also: tuple[str, ...] = field(default=())   # other options that make sense with it


GROUPS = ("Scanning", "Results", "Decisions", "Checks", "Setup")

COMMANDS: tuple[Command, ...] = (
    Command("scan", "[PATH ...]", "Scan everything in your config, or only the PATHs given "
            "(the same as giving no command)", "Scanning", None, takes="paths",
            also=("--no-scan", "--skip-rescans", "--sweep")),
    Command("rescan-errors", "", "Retry only the files marked as errors", "Scanning",
            "--rescan-errors"),
    Command("purge-missing", "", "Remove the records of files that no longer exist", "Scanning",
            "--purge-missing"),
    Command("update-rules", "", "Rebuild the sweep's YARA rules from ClamAV's signatures",
            "Scanning", "--update-rules"),
    Command("list", "infected [PATH ...] | allowed [--all]",
            "List infected files (all, or under the PATHs), or what you've allowed "
            "(--all: with the files inside allowed folders)", "Results", None),
    Command("report", "PATH ...", "Prepare a false-positive report for ClamAV (nothing is sent)",
            "Results", "--clamav-report", takes="each", needs=True),
    Command("allow", "PATH ...", "Mark a flagged file as a false positive (asks first)",
            "Decisions", "--allow", takes="each", needs=True, also=("--yes", "--protected")),
    Command("unallow", "PATH ...", "Undo allow", "Decisions", "--unallow", takes="each",
            needs=True, also=("--protected",)),
    Command("allow-folder", "FOLDER --signature NAME",
            "Allow every file under FOLDER that one signature flags now (asks first)",
            "Decisions", "--allow-folder", takes="one", needs=True,
            also=("--signature", "--yes", "--protected")),
    Command("unallow-folder", "FOLDER --signature NAME", "Undo allow-folder", "Decisions",
            "--unallow-folder", takes="one", needs=True, also=("--signature", "--protected")),
    Command("persistence", "", "List startup entries that are new, changed or gone (changes nothing)",
            "Decisions", "--persistence", also=("--protected",)),
    Command("acknowledge", "PATH ... | --all",
            "Accept startup entries the persistence check lists (asks first)", "Decisions",
            "--acknowledge", takes="each", also=("--yes", "--protected")),
    Command("verify-packages", "", "Check installed files against the package manager's records "
            "(can be slow)",
            "Checks", "--verify-packages"),
    Command("suggest-fixes", "[PATH ...]", "List the files clamd couldn't read, by folder",
            "Checks", "--suggest-fixes", takes="paths"),
    Command("diagnostics", "", "Print versions, settings and counts for a bug report "
            "(no paths or names)", "Checks", "--diagnostics"),
    Command("protect", "", "With sudo: keep your config and decisions where only root can "
            "change them (shows your config and asks first)", "Setup", "--protect"),
    Command("unprotect", "", "With sudo: undo protect (asks first)", "Setup", "--unprotect"),
    Command("uninstall", "", "Delete everything Ensign made (with sudo: root's files too); the "
            "program itself is removed with your installer", "Setup", "--uninstall"),
)
BY_NAME = {c.name: c for c in COMMANDS}


_CONFIG: str | None = None   # --config, if this run was given one (cli.py)


def remember_config(path: str | None) -> None:
    global _CONFIG
    _CONFIG = path


def config_part() -> str:
    """" --config PATH" when this run was given one, so that a pasted hint
    acts on the same config and database; else nothing."""
    return f" --config {shlex.quote(_CONFIG)}" if _CONFIG else ""


def prefix() -> str:
    """How a hint starts: under sudo, with sudo, so that pasting it acts on
    root's records and decisions (the ones this run used), not yours; and
    with this run's --config, if it had one."""
    return (f"sudo {PROG}" if os.geteuid() == 0 else PROG) + config_part()


class UsageError(Exception):
    """A command used wrongly: the message, then its usage line."""


def usage(command: Command) -> str:
    return f"usage: {PROG} {command.name} {command.args}".rstrip()


def overview() -> str:
    """The command list, for --help and `ensign-scan help`."""
    width = max(n for n in (len(f"{c.name} {c.args}".rstrip()) for c in COMMANDS) if n <= 28)
    columns = min(shutil.get_terminal_size((80, 24)).columns, 100) - 2
    lines = ["commands (each also has its original --option form, which keeps working):"]
    for group in GROUPS:
        lines.append(f"  {group}")
        for c in COMMANDS:
            if c.group != group:
                continue
            head = f"{c.name} {c.args}".rstrip()
            indent = " " * (4 + width + 2)
            summary = textwrap.wrap(c.summary, max(30, columns - len(indent)))
            if len(head) > width:
                lines.append(f"    {head}")
                lines += [indent + part for part in summary]
            else:
                lines.append(f"    {head:{width}}  {summary[0]}")
                lines += [indent + part for part in summary[1:]]
    lines.append("")
    lines += textwrap.wrap(f"With no command, {PROG} scans everything in your config, and "
                           f"{PROG} PATH scans PATH. In a script, put paths after "
                           f"'{PROG} scan --', so that no file name is read as a command. Help "
                           f"on one command: {PROG} help COMMAND, or {PROG} COMMAND --help.", columns)
    return "\n".join(lines)


def _original_form(name: str) -> str:
    """The command written with its original options, which no file name
    can be mistaken for."""
    if name == "help":
        return f"{PROG} --help"
    if name == "scan":
        return f"{PROG}   (no command: a scan of everything in your config)"
    if name == "list":
        return f"{PROG} --list-infected   or   {PROG} --list-allowed"
    if name == "acknowledge":
        return f"{PROG} --acknowledge PATH   or   {PROG} --acknowledge-all"
    command = BY_NAME[name]
    tail = " PATH" if command.takes == "each" else " FOLDER" if command.takes == "one" else ""
    return f"{PROG} {command.flag}{tail}" + (" --signature NAME" if command.takes == "one" else "")


def _ambiguous(word: str) -> UsageError:
    path = shlex.quote(f"./{word}")
    return UsageError(
        f"{word!r} is a command, and there's also a file or folder called {word} here. "
        f"Which did you mean?\n"
        f"  the file or folder:  {PROG} {path}\n"
        f"  the command:         {_original_form(word)}")


def _help_for(command: Command) -> str:
    lines = [usage(command), "", command.summary + "."]
    if command.flag:
        same = f"{PROG} {command.flag}" + (" PATH" if command.takes == "each" else
                                           " VALUE" if command.takes == "one" else "")
        lines.append(f"The same as: {same}")
    if command.name == "scan":
        lines.append(f"The same as: {PROG} [PATH ...]. In a script, put paths after "
                     f"'{PROG} scan --', so that no file name is read as a command.")
    if command.name == "list":
        lines.append(f"The same as: {PROG} --list-infected [PATH ...], --list-allowed, "
                     f"--list-allowed-all")
    if command.name == "acknowledge":
        lines.append(f"acknowledge --all is the same as: {PROG} --acknowledge-all")
    if command.also:
        lines.append(f"Goes with: {', '.join(command.also)} (see {PROG} --help)")
    return "\n".join(lines)


# The original options that pick a job. A command line that already names
# one is in the original form, and is passed on exactly as before: there,
# `ensign-scan --list-infected allow` lists what's infected under a folder
# called allow, as it always did.
JOB_OPTIONS = frozenset({c.flag for c in COMMANDS if c.flag} | {
    "--list-infected", "--list-allowed", "--list-allowed-all", "--acknowledge-all", "--verify-pacman"})


# The command each original option is shown as, in the hints Ensign prints.
_SHOWN_AS = {c.flag: c.name for c in COMMANDS if c.flag} | {
    "--list-infected": "list infected", "--list-allowed": "list allowed",
    "--list-allowed-all": "list allowed --all", "--acknowledge-all": "acknowledge --all"}


def shown_as(option: str) -> str:
    """The command an original option is shown as in a hint: "--allow" is
    "allow", "--list-allowed-all" is "list allowed --all". Anything else
    (--yes, --protected) is shown as it is."""
    return _SHOWN_AS.get(option, option)


def _matches(token: str, options: set[str] | frozenset[str]) -> bool:
    """Whether an option on the command line is one of `options`, written
    out or shortened (argparse accepts --conf for --config)."""
    name = token.split("=", 1)[0]
    if name in options:
        return True
    return name.startswith("--") and len(name) > 3 and any(o.startswith(name) for o in options)


def _takes(token: str, takes_value: set[str]) -> bool:
    return "=" not in token and _matches(token, takes_value)


def _split(argv: list[str], takes_value: set[str]) -> tuple[list[str], list[str]]:
    """Options (with their values) and the words that aren't options."""
    options, words = [], []
    i = 0
    while i < len(argv):
        token = argv[i]
        if token == "--":
            words += argv[i + 1:]
            break
        if token.startswith("-") and token != "-":
            options.append(token)
            if _takes(token, takes_value) and i + 1 < len(argv):
                options.append(argv[i + 1])
                i += 1
        else:
            words.append(token)
        i += 1
    return options, words


def _first_word(argv: list[str], takes_value: set[str]) -> int | None:
    i = 0
    while i < len(argv):
        token = argv[i]
        if token == "--":
            return None   # everything after -- is a path
        if token.startswith("-") and token != "-":
            if _matches(token, JOB_OPTIONS):
                return None   # the original form: leave it exactly as it is
            if _takes(token, takes_value):
                i += 1
        else:
            return i
        i += 1
    return None


def translate(argv: list[str], takes_value: set[str], out=print) -> list[str]:
    """argv with a command rewritten into the original options. Raises
    UsageError for a command used wrongly, and SystemExit(0) after printing
    help that was asked for."""
    at = _first_word(argv, takes_value)
    if at is None:
        return argv
    word = argv[at]
    before, rest = argv[:at], argv[at + 1:]
    if any(t in ("-h", "--help", "--version") or _matches(t, {"--help", "--version"}) for t in before):
        return argv   # asked for help or the version first: argparse answers that, as before
    if word in BY_NAME and ("-h" in rest or "--help" in rest):
        out(_help_for(BY_NAME[word]))   # help runs nothing, so there's nothing to clarify
        raise SystemExit(0)
    if (word == "help" or word in BY_NAME) and os.path.lexists(word):
        raise _ambiguous(word)   # clarify, never guess
    if word == "help":
        wanted = [w for w in rest if not w.startswith("-")]
        if not wanted or wanted[0] == "help":
            out(overview())
        elif wanted[0] in BY_NAME:
            out(_help_for(BY_NAME[wanted[0]]))
        else:
            raise UsageError(f"there's no command called {wanted[0]!r}. {PROG} help lists them.")
        raise SystemExit(0)
    command = BY_NAME.get(word)
    if command is None:
        return argv   # a path, as before
    options, words = _split(rest, takes_value)
    all_flag = "--all" in options
    options = [o for o in options if o != "--all"]
    if all_flag and command.name not in ("list", "acknowledge"):
        raise UsageError(f"--all goes with {PROG} list allowed or {PROG} acknowledge.\n"
                         + usage(command))

    if command.name == "list":
        kind, paths = (words[0], words[1:]) if words else (None, [])
        if kind == "infected" and not all_flag:
            return before + ["--list-infected", *options, *paths]
        if kind == "allowed" and not paths:
            return before + ["--list-allowed-all" if all_flag else "--list-allowed", *options]
        raise UsageError("say what to list: infected [PATH ...], or allowed [--all].\n"
                         + usage(command))
    if command.name == "acknowledge" and all_flag:
        if words:
            raise UsageError(f"acknowledge takes PATHs or --all, not both.\n{usage(command)}")
        return before + ["--acknowledge-all", *options]
    if command.needs and not words:
        raise UsageError(f"{command.name} needs "
                         f"{'a FOLDER' if command.takes == 'one' else 'at least one PATH'}.\n"
                         + usage(command))
    if command.name == "acknowledge" and not words:
        raise UsageError(f"acknowledge needs at least one PATH, or --all.\n{usage(command)}")
    if command.takes == "one" and len(words) > 1:
        raise UsageError(f"{command.name} takes one FOLDER.\n{usage(command)}")
    if not command.takes and words:
        raise UsageError(f"{command.name} takes no PATH (got {words[0]!r}).\n{usage(command)}")

    if command.takes == "paths":
        flag = [command.flag] if command.flag else []
        # A path that starts with "-" (given after --) must stay a path.
        return before + flag + options + (["--"] if any(w.startswith("-") for w in words) else []) + words
    if command.takes == "each":
        # --flag=PATH, so that a PATH starting with "-" stays a PATH.
        return before + [f"{command.flag}={w}" for w in words] + options
    if command.takes == "one":
        return before + [f"{command.flag}={words[0]}", *options]
    return before + [command.flag, *options]


def fail(error: UsageError) -> None:
    """Print a usage error the way argparse does, and exit 2."""
    print(f"{PROG}: error: {error}", file=sys.stderr)
    raise SystemExit(2)
