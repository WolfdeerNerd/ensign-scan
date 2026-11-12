"""What the reports look like when copied out of a terminal.

  * A path is never broken across lines, however long: a broken path is
    broken when pasted (into --allow, say). The terminal still wraps it on
    screen; Rich doesn't insert line breaks into it.
  * Notes (the ↳ and › lines) aren't padded with spaces to the window edge.
  * Signature descriptions decoded from a name read as plain sentences: what
    ClamAV looks for, what the signature is for, the family, the number.

    python3 tests/output_test.py
"""
from __future__ import annotations

import sys as _sys_path
from pathlib import Path as _Path

# Run against THIS checkout, never an installed copy of Ensign.
ROOT = _Path(__file__).resolve().parent.parent
_sys_path.path.insert(0, str(ROOT))

import contextlib  # noqa: E402
import io  # noqa: E402
import tempfile  # noqa: E402
from pathlib import Path  # noqa: E402

from sqlalchemy.orm import Session  # noqa: E402

from ensign_scan import allowlist, reports  # noqa: E402
from ensign_scan.db import make_engine  # noqa: E402
from ensign_scan.explanations import explain_threat  # noqa: E402
from ensign_scan.models import Allowance, FileRecord, ScanStatus, utcnow  # noqa: E402


def captured(fn, *args, **kwargs) -> str:
    with contextlib.redirect_stdout(io.StringIO()) as buf:
        fn(*args, **kwargs)
    return buf.getvalue()


with tempfile.TemporaryDirectory() as d:
    engine = make_engine(f"sqlite:///{d}/system.db")
    # Made-up paths, long enough that a terminal would have to wrap them.
    deep = Path(d, "cache", "example-org___sample_corpus", "default", "0.0.0",
                "0123456789abcdef0123456789abcdef01234567",
                "sample_corpus-train-00002-of-00005.arrow")
    huge = Path(d, "games", "common", "Example Game Title", "ExampleGame", "Content",
                "Paks", "pakchunk0-Windows-with-a-much-longer-name-than-fits-on-a-line.ucas")
    allowed = Path(d, "data", "archive_old", "a-rather-long-training-file-name-for-a-dataset-split.txt")
    with Session(engine) as session:
        session.add_all([
            FileRecord(filepath=str(deep), filename=deep.name, file_hash="a" * 64, file_size=1,
                       scan_status=ScanStatus.INFECTED.value, threat_name="Js.Downloader.Jsdownloader-6260766-0",
                       scan_result="clamscan: Js.Downloader.Jsdownloader-6260766-0 FOUND", last_scanned=utcnow()),
            FileRecord(filepath=str(huge), filename=huge.name, file_hash="b" * 64, file_size=17 * 2**30,
                       scan_status=ScanStatus.INCOMPLETE.value,
                       threat_name="Heuristics.Limits.Exceeded.MaxFileSize",
                       scan_result="clamscan: Heuristics.Limits.Exceeded.MaxFileSize FOUND"),
            FileRecord(filepath=str(allowed), filename=allowed.name, file_hash="c" * 64, file_size=1,
                       scan_status=ScanStatus.ALLOWED.value, threat_name="Email.Phishing.DblDom-16",
                       scan_result="clamscan: Email.Phishing.DblDom-16 FOUND"),
            Allowance(file_hash="c" * 64, threat_name="Email.Phishing.DblDom-16", filepath=str(allowed),
                      allowed_at=utcnow()),
        ])
        session.commit()

    outputs = {
        "list_infected": captured(reports.list_infected, engine),
        "incomplete_report": captured(reports.incomplete_report, engine),
        "allowed_report": captured(allowlist.allowed_report, engine),
        "list_allowed": captured(allowlist.list_allowed, engine),
    }
    for where, path in (("list_infected", deep), ("incomplete_report", huge),
                        ("allowed_report", allowed), ("list_allowed", allowed)):
        out = outputs[where]
        assert str(path) in out, f"{where}: the path must come out in one piece:\n{out}"
    print("unbroken paths test passed ✓")

    # Padding means a run of spaces to the window edge. (Word-wrapped prose
    # ends each line on the one space it broke at; that's harmless.)
    for where, out in outputs.items():
        padded = [line for line in out.splitlines() if line.endswith("  ")]
        assert not padded, f"{where}: lines padded with trailing spaces: {padded[:3]!r}"
    print("no trailing padding test passed ✓")

    # Each flagged file is its own block: details indented under the path.
    lines = outputs["list_infected"].splitlines()
    at = next(i for i, line in enumerate(lines) if line.startswith("  File: "))
    block = lines[at + 1:at + 4]
    assert block[0].startswith("      Scanned: ") and block[0].endswith(" UTC"), block
    assert block[1].startswith("      Details: clamscan: "), block
    assert block[2].startswith("      › Context: "), block
    print("file blocks test passed ✓")

d = explain_threat("Email.Downloader.Generic-5657809-0").description
assert d == ("ClamAV matched a pattern it uses for downloader code: code that fetches more malware "
             "from the internet once it runs. This signature is for email (messages and their "
             "attachments). Family name: Generic, ClamAV's catch-all name rather than one specific "
             "strain. Signature number 5657809, revision 0."), d
d = explain_threat("Email.Phishing.DblDom-16").description
assert "for phishing:" in d and "The -16 at the end is the signature's revision." in d, d
d = explain_threat("Win.Exploit.CVE_2020_1234-1").description
assert "for an exploit:" in d and "It refers to CVE-2020-1234, a known vulnerability." in d, d
assert "Family name: Generic, ClamAV's catch-all" not in explain_threat("Js.Downloader.Foo-1-0").description
d = explain_threat("Win.Weird.Thing-5-0").description
assert "'Weird' (a category Ensign has no description for)" in d, "an unknown category is said, not guessed"
for name in ("Email.Downloader.X-1-0", "Html.Phishing.X-1-0", "Ios.Trojan.X-1-0", "Andr.Spyware.X-1-0"):
    assert not explain_threat(name).description.startswith(("A ", "An ")), "no article to get wrong"
print("plain descriptions test passed ✓")

print("\nAll output tests passed ✓")
