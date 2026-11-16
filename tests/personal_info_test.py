"""The personal-info check (.github/scripts/check_personal_info.py).

A home-directory path naming a real account must fail, whether it is in a
file or in a pull request's title, description or commit messages;
stand-in names and forms with no name in them must pass; and the check's
own output must never repeat the path, since the logs of a public
repository's Actions runs are public too.

The account name below is made up, and the paths are built from pieces so
this file never contains one whole (the check reads this file too).

Run: python3 tests/personal_info_test.py
"""
from __future__ import annotations

import sys as _sys_path
from pathlib import Path as _Path

# Run against THIS checkout, never an installed copy of Ensign.
ROOT = _Path(__file__).resolve().parent.parent
_sys_path.path.insert(0, str(ROOT))

import importlib.util  # noqa: E402
import json  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402
import tempfile  # noqa: E402
from pathlib import Path  # noqa: E402

SCRIPT = ROOT / ".github" / "scripts" / "check_personal_info.py"
sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location("check_personal_info", SCRIPT)
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)

NAME = "mx" + "quill"                      # a made-up account name
HOME, USERS, WIN = "/ho" + "me/", "/Us" + "ers/", "C:\\Us" + "ers\\"

# --- what counts ---------------------------------------------------------------
flagged = [
    f"{HOME}{NAME}/Documents/notes.txt",
    f"Traceback: File \"{HOME}{NAME}/.local/lib/python3.12/site.py\", line 3",
    f"{USERS}{NAME}/Library/x",
    f"{WIN}{NAME}\\Desktop\\x.txt",
    f"path={HOME}{NAME}",
    f"{HOME}{NAME}.",                       # ends a sentence
    f"{HOME}first.last/x",                  # a dot inside the name
    f"{HOME}claude/ensign-scan",            # a sandbox account is still an account
]
for text in flagged:
    assert check.lines_with_paths(text) == [1], f"should be flagged: {text!r}"

passes = [
    f"{HOME}user/Downloads", f"{HOME}USER/x", f"{HOME}you/x", f"{HOME}w/my_docs/a.exe",
    f"it lives in {HOME}user.", f"{USERS}username/x", f"{WIN}you\\x",
    "~/Documents/GitHub/ensign-scan", "$HOME/.config/ensign", f"{HOME}$USER/x",
    f"{HOME}<name>/x", f"homes outside {HOME[:-1]})", f"{HOME}", "nothing here", "", None,
]
for text in passes:
    assert check.lines_with_paths(text) == [], f"should pass: {text!r}"

assert check.lines_with_paths(f"one\n{HOME}user/a\n{HOME}{NAME}/b\nfour\n{USERS}{NAME}") == [3, 5]
print("personal-info patterns test passed ✓")

# --- files -----------------------------------------------------------------------
def run(*args: str) -> tuple[int, str]:
    result = subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True)
    return result.returncode, result.stdout + result.stderr


with tempfile.TemporaryDirectory() as d:
    root = Path(d, "repo")
    (root / "pkg").mkdir(parents=True)
    (root / "README.md").write_text(f"Config lives in {HOME}user/.config.\n")
    (root / "pkg" / "ok.py").write_text("x = 1\n")
    (root / "pkg" / "blob.bin").write_bytes(b"\xff\xfe\x00 not text \x80")
    (root / "__pycache__").mkdir()
    (root / "__pycache__" / "junk.txt").write_text(f"{HOME}{NAME}/cache\n")   # skipped folder
    code, out = run("--files", str(root))
    assert code == 0 and "No home-directory paths" in out, out

    (root / "pkg" / "leak.py").write_text(f"# ok\n# ok\nLOG = '{HOME}{NAME}/log.txt'\n")
    code, out = run("--files", str(root))
    assert code == 1, out
    assert "pkg/leak.py, line 3" in out and "::error::" in out, out
    assert NAME not in out, "the check must not print the name it found"
    assert "README.md" not in out and "junk.txt" not in out, out

    # In a git checkout, only tracked files count: an untracked local file
    # (a log, a virtualenv) can't fail the check.
    if shutil.which("git"):
        git = ["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@example.com"]
        subprocess.run([*git, "init", "-q"], check=True)
        subprocess.run([*git, "add", "README.md", "pkg/ok.py"], check=True)
        subprocess.run([*git, "commit", "-q", "-m", "x"], check=True)
        code, out = run("--files", str(root))
        assert code == 0, f"leak.py is untracked, so it isn't checked: {out}"
        subprocess.run([*git, "add", "pkg/leak.py"], check=True)
        code, out = run("--files", str(root))
        assert code == 1 and "pkg/leak.py, line 3" in out, out
    print("personal-info files test passed ✓")

    # --- pull request text ---------------------------------------------------------
    def pr_files(title, body, messages):
        pr, commits = Path(d, "pr.json"), Path(d, "commits.json")
        pr.write_text(json.dumps({"title": title, "body": body}))
        commits.write_text(json.dumps([[{"sha": str(i) * 40, "commit": {"message": m}}
                                        for i, m in enumerate(messages, 1)]]))
        return str(pr), str(commits)

    code, out = run(*pr_files("Fix a crash", f"Tested under {HOME}user and ~.", ["Fix a crash"]))
    assert code == 0, out
    code, out = run(*pr_files("Fix a crash", None, ["Fix a crash"]))
    assert code == 0, f"an empty description is fine: {out}"
    code, out = run(*pr_files(f"Fix {HOME}{NAME} crash",
                              f"Output:\n\n  File \"{HOME}{NAME}/x.py\"\n",
                              ["Fix a crash", f"More\n\nSeen in {USERS}{NAME}/x"]))
    assert code == 1, out
    assert "PR title" in out and "PR description, line 3" in out, out
    assert "commit 222222222222, message line 3" in out and "commit 111111111111" not in out, out
    assert NAME not in out, "the check must not print the name it found"
    print("personal-info pull request test passed ✓")

    code, out = run()
    assert code == 2 and "usage" in out, out

# --- this repository itself is clean ----------------------------------------------
found = check.file_findings(str(ROOT))
assert not found, "home-directory paths in the repository:\n  " + "\n  ".join(found)
print("repository is clean ✓")

print("\nAll personal-info tests passed ✓")
