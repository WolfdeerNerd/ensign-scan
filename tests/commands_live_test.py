"""Every command and its original option give the same run, end to end.

Each pair (`ensign-scan allow PATH` and `ensign-scan --allow PATH`, and so
on for every command) runs through the installed command on its own copy of
one database, made by a real scan. The two must exit the same, print the
same (times and temporary paths aside) and leave the database the same.
tests/commands_test.py checks that argparse reads both forms alike; this
checks the whole run.

Skipped unless ENSIGN_CLI points at an installed `ensign-scan` and
ENSIGN_TEST_CLAMD_SOCKET at a real clamd that knows the EICAR test file
(as in CI's live job):

    ENSIGN_CLI=... ENSIGN_TEST_CLAMD_SOCKET=... python3 tests/commands_live_test.py
"""
import difflib
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

CLI = os.environ.get("ENSIGN_CLI")
SOCKET = os.environ.get("ENSIGN_TEST_CLAMD_SOCKET")
if not CLI or not SOCKET:
    print("command parity test skipped (set ENSIGN_CLI and ENSIGN_TEST_CLAMD_SOCKET to run it)")
    sys.exit(0)

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
SIGNATURE = "Ensign.Test.EICAR-Body.UNOFFICIAL"   # the test clamd's one signature
ENV = {**os.environ, "NO_COLOR": "1", "TERM": "dumb"}

base = Path(tempfile.mkdtemp(prefix="ensign_parity_"))
tree = base / "tree"
(tree / "sub").mkdir(parents=True)
# Different content, so allowing one doesn't allow the other as a copy.
(tree / "bad.dat").write_bytes(EICAR + b"\n1")
(tree / "sub" / "bad2.dat").write_bytes(EICAR + b"\n2")
(tree / "batch").mkdir()
(tree / "batch" / "part.dat").write_bytes(EICAR + b"\n3")
(tree / "ok.txt").write_text("fine")


def config_for(data: Path) -> Path:
    config = data.parent / "config.toml"
    config.write_text(f'data_dir = "{data}"\nclamd_socket = "{SOCKET}"\n'
                      f"signature_max_age_days = 0\nmax_workers = 2\n"
                      f'scan_targets = ["{tree}"]\nsweep_huge_files = false\n')
    return config


# One database for every run to start from: a scan, one file allowed, and
# one folder allowed (so that "list allowed --all" has files to add).
seed = base / "seed" / "data"
seed.mkdir(parents=True)
first = subprocess.run([CLI, "--config", str(config_for(seed))], capture_output=True, text=True, env=ENV)
assert first.returncode == 3, first.stdout[-2000:]
subprocess.run([CLI, "--config", str(config_for(seed)), "--allow", str(tree / "sub" / "bad2.dat"), "--yes"],
               capture_output=True, check=True, env=ENV)
subprocess.run([CLI, "--config", str(config_for(seed)), "--allow-folder", str(tree / "batch"),
                "--signature", SIGNATURE, "--yes"], capture_output=True, check=True, env=ENV)

# What changes from one run to the next on its own: times, durations,
# log names, the temporary folders and process ids.
NOISE = [r"\d{4}-\d\d-\d\d[ T][\d:.]+( UTC)?", r"took \S+", r"Execution time: [\d.]+ seconds",
         r"ensign-\d{8}-\d{6}\.log", r"run\d+", r"\d+\.\d+ s", r"\(pid \d+\)", r"\d+ ms"]


def normalized(text: str) -> str:
    for pattern in NOISE:
        text = re.sub(pattern, "#", text)
    return text


def state(data: Path) -> dict:
    """What a run can change in the database."""
    conn = sqlite3.connect(data / "system.db")
    tables = {}
    for table, columns in (("files", "filepath, scan_status, threat_name"),
                           ("allowances", "file_hash, threat_name, engine"),
                           ("allowed_folders", "folder, threat_name, engine"),
                           ("findings", "engine, signature, state")):
        tables[table] = sorted(conn.execute(f"SELECT {columns} FROM {table}").fetchall())
    conn.close()
    return tables


runs = 0


def run(argv: list[str]) -> tuple[int, str, dict]:
    """Run argv on a fresh copy of the seed database."""
    global runs
    runs += 1
    data = base / f"run{runs}" / "data"
    shutil.copytree(seed, data)
    config = config_for(data)
    argv = [a.replace("@T", str(tree)) for a in argv]
    result = subprocess.run([CLI, "--config", str(config), *argv], capture_output=True, text=True,
                            timeout=300, input="", env=ENV)
    out = (result.stdout + result.stderr).replace(str(data), "DATA").replace(str(config), "CONFIG")
    # Line breaks fall where the paths' lengths put them (run9 against
    # run10), so each paragraph is compared with its breaks folded into spaces.
    paragraphs = re.split(r"\n\s*\n", normalized(out))
    return result.returncode, "\n".join(" ".join(p.split()) for p in paragraphs), state(data)


PAIRS = [
    (["scan"], []),
    (["scan", "@T/sub"], ["@T/sub"]),
    (["rescan-errors"], ["--rescan-errors"]),
    (["purge-missing"], ["--purge-missing"]),
    (["list", "infected"], ["--list-infected"]),
    (["list", "infected", "@T/sub"], ["--list-infected", "@T/sub"]),
    (["list", "allowed"], ["--list-allowed"]),
    (["list", "allowed", "--all"], ["--list-allowed-all"]),
    (["report", "@T/bad.dat"], ["--clamav-report", "@T/bad.dat"]),
    (["allow", "@T/bad.dat", "--yes"], ["--allow", "@T/bad.dat", "--yes"]),
    (["allow", "@T/bad.dat"], ["--allow", "@T/bad.dat"]),   # no terminal, no --yes: asks, changes nothing
    (["unallow", "@T/sub/bad2.dat"], ["--unallow", "@T/sub/bad2.dat"]),
    (["allow-folder", "@T", "--signature", SIGNATURE, "--yes"],
     ["--allow-folder", "@T", "--signature", SIGNATURE, "--yes"]),
    (["allow-folder", "@T"], ["--allow-folder", "@T"]),
    (["unallow-folder", "@T", "--signature", SIGNATURE], ["--unallow-folder", "@T", "--signature", SIGNATURE]),
    (["persistence"], ["--persistence"]),
    (["acknowledge", "--all", "--yes"], ["--acknowledge-all", "--yes"]),
    (["suggest-fixes"], ["--suggest-fixes"]),
    (["diagnostics"], ["--diagnostics"]),
    (["protect"], ["--protect"]),       # without sudo: both refuse the same way
    (["unprotect"], ["--unprotect"]),
]
# A full package check takes longer than Ensign's 10-minute limit on a
# machine with thousands of packages, such as GitHub's runner image, which
# sets ENSIGN_SKIP_FULL_VERIFY for that reason (see cli_live_test.py).
if not os.environ.get("ENSIGN_SKIP_FULL_VERIFY"):
    PAIRS.append((["verify-packages"], ["--verify-packages"]))
differ = 0
try:
    for command, option in PAIRS:
        a, b = run(command), run(option)
        same = a == b
        print(f"{'same' if same else 'DIFFERENT'}  {' '.join(command) or '(no command)'}  (exit {a[0]})")
        if not same:
            differ += 1
            print("\n".join(list(difflib.unified_diff(b[1].splitlines(), a[1].splitlines(),
                                                      "option", "command", lineterm=""))[:30]))
            if a[2] != b[2]:
                print("  and the database differs")
finally:
    shutil.rmtree(base, ignore_errors=True)
assert differ == 0, f"{differ} command(s) give a different run from their original option"
print(f"\nAll {len(PAIRS)} commands give the same run as their original option ✓")
