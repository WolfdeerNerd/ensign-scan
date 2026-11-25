"""Commands (`ensign-scan allow PATH`) and the original options
(`ensign-scan --allow PATH`) must mean exactly the same run.

Every command is checked against its options form by comparing what
argparse makes of each; then the rule for paths (a first word that's a
command is the command; anything else is a path), wrong uses (exit 2 with
the command's usage) and help (exit 0).

    python3 tests/commands_test.py
"""
from __future__ import annotations

import sys as _sys_path
from pathlib import Path as _Path

# Run against THIS checkout, never an installed copy of Ensign.
ROOT = _Path(__file__).resolve().parent.parent
_sys_path.path.insert(0, str(ROOT))

import contextlib  # noqa: E402
import io  # noqa: E402

from ensign_scan import cli, commands  # noqa: E402


def parsed(argv: list[str]) -> dict:
    return vars(cli.parse_args(argv))


def outcome(argv: list[str]) -> tuple[int, str]:
    """(exit code, what was printed) for a command line that exits."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            cli.parse_args(argv)
        except SystemExit as exc:
            return int(exc.code or 0), out.getvalue() + err.getvalue()
    raise AssertionError(f"{argv} didn't exit")


SAME = [
    # (command form, original options form)
    ([], []),
    (["scan"], []),
    (["scan", "/data", "/games"], ["/data", "/games"]),
    (["scan", "--sweep", "--skip-rescans", "/data"], ["--sweep", "--skip-rescans", "/data"]),
    (["rescan-errors"], ["--rescan-errors"]),
    (["purge-missing"], ["--purge-missing"]),
    (["update-rules"], ["--update-rules"]),
    (["list", "infected"], ["--list-infected"]),
    (["list", "infected", "/data", "/games"], ["--list-infected", "/data", "/games"]),
    (["list", "allowed"], ["--list-allowed"]),
    (["list", "allowed", "--all"], ["--list-allowed-all"]),
    (["report", "/a", "/b"], ["--clamav-report", "/a", "--clamav-report", "/b"]),
    (["allow", "/a"], ["--allow", "/a"]),
    (["allow", "/a", "/b", "--yes"], ["--allow", "/a", "--allow", "/b", "--yes"]),
    (["unallow", "/a"], ["--unallow", "/a"]),
    (["allow-folder", "/f", "--signature", "Sig.X"], ["--allow-folder", "/f", "--signature", "Sig.X"]),
    (["allow-folder", "/f", "--signature=Sig.X", "--yes"], ["--allow-folder", "/f", "--signature", "Sig.X", "--yes"]),
    (["unallow-folder", "/f", "--signature", "Sig.X"], ["--unallow-folder", "/f", "--signature", "Sig.X"]),
    (["persistence"], ["--persistence"]),
    (["acknowledge", "/etc/x"], ["--acknowledge", "/etc/x"]),
    (["acknowledge", "--all", "--yes"], ["--acknowledge-all", "--yes"]),
    (["verify-packages"], ["--verify-packages"]),
    (["suggest-fixes", "/data"], ["--suggest-fixes", "/data"]),
    (["diagnostics"], ["--diagnostics"]),
    (["protect"], ["--protect"]),
    (["unprotect"], ["--unprotect"]),
    (["uninstall"], ["--uninstall"]),
    # options before the command, and --protected either side of it
    (["--config", "/c.toml", "allow", "/a"], ["--config", "/c.toml", "--allow", "/a"]),
    (["--protected", "allow", "/a"], ["--protected", "--allow", "/a"]),
    (["allow", "/a", "--protected"], ["--protected", "--allow", "/a"]),
    (["--protected", "acknowledge", "--all"], ["--protected", "--acknowledge-all"]),
]
for command_form, options_form in SAME:
    assert parsed(command_form) == parsed(options_form), (command_form, options_form)
print(f"{len(SAME)} commands match their options form test passed ✓")

# Every command is listed in the help, and stands for an option that exists.
help_text = outcome(["--help"])[1]
for c in commands.COMMANDS:
    assert f"    {c.name}" in help_text, f"{c.name} missing from --help"
    if c.flag:
        assert c.flag in help_text, f"{c.name} stands for {c.flag}, which --help doesn't list"
print("every command is in --help test passed ✓")

# The rule for paths: a first word that's a command is the command, any
# other word is a path, and a folder named like a command can still be scanned.
assert parsed(["/home/user/Downloads"])["targets"][0].endswith("Downloads")
assert parsed(["Downloads"])["targets"] == ["Downloads"]
assert parsed(["allow", "/a"])["allow"] == ["/a"]
assert parsed(["scan", "allow"])["targets"] == ["allow"], "scan PATH scans a folder named allow"
assert parsed(["./allow"])["targets"] == ["./allow"]
assert parsed(["--", "allow"])["targets"] == ["allow"], "after --, every word is a path"
assert parsed(["/data", "allow"])["targets"] == ["/data", "allow"], "only the first word can be a command"
assert parsed(["--allow", "scan"])["allow"] == ["scan"], "an option's value is never a command"
assert parsed(["scan", "--", "-odd"])["targets"] == ["-odd"], "a path starting with - stays a path"
# The original form is passed on exactly as before, even when a path has a
# command's name: these meant a folder called allow, and still do.
assert parsed(["--list-infected", "allow"])["targets"] == ["allow"]
assert parsed(["--suggest-fixes", "list"])["targets"] == ["list"]
assert parsed(["--list-inf", "allow"])["targets"] == ["allow"], "a shortened option, as argparse allows"
# A shortened option's value is still its value, never a command.
assert parsed(["--conf", "allow", "scan", "/d"])["config"] == "allow"
assert parsed(["allow-folder", "/f", "--sig", "S"])["signature"] == "S"
# PATHs that start with "-", after --, stay PATHs for commands that take them.
assert parsed(["allow", "--", "-odd"])["allow"] == ["-odd"]
assert parsed(["allow-folder", "--signature", "S", "--", "-odd"])["allow_folder"] == "-odd"
assert parsed(["allow", "--", "-h"])["allow"] == ["-h"], "after --, -h is a path, not a help request"
got = parsed(["list", "infected", "--", "-odd"])
assert got["list_infected"] and got["targets"] == ["-odd"], "a path starting with - stays a path"
# A command that's also a file or folder where you are: never a guess.
import os  # noqa: E402
import tempfile  # noqa: E402

here = os.getcwd()
with tempfile.TemporaryDirectory() as d:
    os.chdir(d)
    try:
        os.mkdir("allow")
        open("purge-missing", "w").close()
        open("help", "w").close()
        for argv, original in ((["allow", "/x"], "ensign-scan --allow PATH"),
                               (["purge-missing"], "ensign-scan --purge-missing"),
                               (["--yes", "allow"], "ensign-scan --allow PATH"),
                               (["help"], "ensign-scan --help")):
            code, text = outcome(argv)
            assert code == 2 and "also a file or folder" in text and original in text, (argv, text)
            assert f"ensign-scan ./{argv[-1] if argv[0] != 'allow' else 'allow'}" in text, text
        # Both ways it suggests work, and so do the other ways around it.
        assert parsed(["./allow"])["targets"] == ["./allow"]
        assert parsed(["--allow", "/x"])["allow"] == ["/x"]
        assert parsed(["--purge-missing"])["purge_missing"] is True
        assert parsed(["scan", "--", "allow"])["targets"] == ["allow"]
        # Only the first word is checked: a folder named like a later word is just a path.
        assert parsed(["scan", "allow"])["targets"] == ["allow"]
        # Help on a command runs nothing, so it's shown even then.
        code, text = outcome(["allow", "--help"])
        assert code == 0 and "usage: ensign-scan allow" in text, text
        # A command with nothing by its name here is still the command.
        assert parsed(["unallow", "/x"])["unallow"] == ["/x"]
    finally:
        os.chdir(here)
print("command or path test passed ✓")

# Wrong uses: exit 2, saying what's wrong and showing the command's usage.
WRONG = [
    (["allow"], "needs at least one PATH"),
    (["report"], "needs at least one PATH"),
    (["allow-folder"], "needs a FOLDER"),
    (["allow-folder", "/a", "/b", "--signature", "S"], "takes one FOLDER"),
    (["list"], "say what to list"),
    (["list", "everything"], "say what to list"),
    (["list", "allowed", "/data"], "say what to list"),
    (["list", "infected", "--all"], "say what to list"),
    (["acknowledge"], "or --all"),
    (["acknowledge", "/x", "--all"], "not both"),
    (["protect", "/x"], "takes no PATH"),
    (["uninstall", "--all"], "--all goes with"),
    (["help", "nope"], "no command called"),
]
for argv, words in WRONG:
    code, text = outcome(argv)
    assert code == 2 and words in text, (argv, code, text)
    if argv[0] != "help":
        assert f"usage: ensign-scan {argv[0]}" in text, (argv, text)
# The original options' own checks still apply after a command.
code, text = outcome(["unallow-folder", "/f"])
assert code == 2 and "needs --signature" in text, text
print("wrong uses test passed ✓")

# Help: the overview, and one command's help, both exit 0.
code, text = outcome(["help"])
assert code == 0 and "commands (each also has" in text and "allow-folder" in text, text
for argv in (["help", "allow"], ["allow", "--help"], ["allow", "-h"], ["list", "--help"]):
    code, text = outcome(argv)
    assert code == 0 and f"usage: ensign-scan {argv[-1] if argv[0] == 'help' else argv[0]}" in text, (argv, text)
code, text = outcome(["help", "allow"])
assert "The same as: ensign-scan --allow PATH" in text, text
code, text = outcome(["help", "help"])
assert code == 0 and "commands (each also has" in text, text
code, text = outcome(["help", "scan"])
assert "The same as: ensign-scan [PATH ...]" in text and "scan --" in text, text
code, text = outcome(["help"])
assert "put paths after 'ensign-scan scan --'" in " ".join(text.split()), text
code, text = outcome(["--help"])
assert code == 0 and text.index("commands (") < text.index("options: scanning"), \
    "--help shows the commands before the options"
# Help or the version asked for first wins, as before, whatever follows.
for argv in (["-h", "allow"], ["--help", "list"], ["--he", "allow"]):
    code, text = outcome(argv)
    assert code == 0 and "commands (each also has" in text, (argv, text)
code, text = outcome(["--version", "allow"])
assert code == 0 and text.startswith("ensign-scan "), text
print("help test passed ✓")

# Every hint Ensign prints (commands.shown_as) is a command line that means
# the same as the option it stands for.
for option, shown in commands._SHOWN_AS.items():
    value = ["/x"] if option in ("--allow", "--unallow", "--clamav-report", "--acknowledge",
                                 "--allow-folder", "--unallow-folder") else []
    extra = ["--signature", "S"] if option in ("--allow-folder", "--unallow-folder") else []
    hint = shown.split() + value + extra
    assert parsed(hint) == parsed([option, *value, *extra]), (option, hint)
    if option in ("--allow", "--unallow", "--allow-folder", "--unallow-folder", "--persistence",
                  "--acknowledge", "--acknowledge-all"):
        # The protected-mode hints: sudo ensign-scan --protected <command>
        assert parsed(["--protected", *hint]) == parsed(["--protected", option, *value, *extra]), option

# In protected mode, hints that change decisions start with
# `sudo ensign-scan --protected`; hints that only read never take
# --protected, which would be refused. Under sudo, every hint has sudo.
import os  # noqa: E402

from ensign_scan import allowlist  # noqa: E402

saved = allowlist._COMMAND
try:
    allowlist.show_protected_commands()
    read = allowlist._command("--list-infected", "/f")
    change = allowlist._command("--unallow", "/f")
    assert change.startswith("sudo ensign-scan --protected unallow"), change
    assert "--protected" not in read and read.endswith("list infected /f"), read
    for hint in (read, change):
        words = hint.split()
        words = words[words.index("ensign-scan") + 1:]
        cli.parse_args(words)   # parses (exits if not)
finally:
    allowlist._COMMAND = saved
assert commands.prefix() == ("sudo ensign-scan" if os.geteuid() == 0 else "ensign-scan")
# A run given --config: its hints carry it, so they act on the same database.
commands.remember_config("/tmp/my configs/alt.toml")
try:
    hint = allowlist._command("--unallow", "/f")
    assert "--config '/tmp/my configs/alt.toml' unallow /f" in hint, hint
    import shlex as _shlex  # noqa: E402
    words = _shlex.split(hint)
    assert parsed(words[words.index("ensign-scan") + 1:])["config"] == "/tmp/my configs/alt.toml"
    assert commands.prefix().endswith("--config '/tmp/my configs/alt.toml'")
finally:
    commands.remember_config(None)
assert commands.prefix() == ("sudo ensign-scan" if os.geteuid() == 0 else "ensign-scan")
assert allowlist._READ == commands.prefix()
print("every printed hint parses test passed ✓")

print("\nAll command tests passed ✓")
