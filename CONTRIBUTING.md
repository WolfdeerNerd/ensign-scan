# Contributing to Ensign

Thanks for wanting to help. Ensign is a small project run by one person, so reviews are best-effort and there's no fixed timeline.

## Before you start

Every change has to fit the four rules in the [roadmap](ROADMAP.md#what-wont-change):

- **Everything stays local.** No file, hash or result leaves the machine.
- **Ensign only advises.** It never changes permissions, config files or anything else on the system.
- **Fewer false positives over wider coverage.**
- **Never "clean" without a real scan.**

For anything bigger than a small fix, open an issue first, so we can agree on the approach before you spend time on code. Check the [roadmap](ROADMAP.md) and the open issues to see whether it's already planned or ruled out.

## Reporting problems

- **Security problems:** use [private vulnerability reporting](https://github.com/WolfdeerNerd/ensign-scan/security/advisories/new), never a public issue. See [SECURITY.md](SECURITY.md).
- **Bugs, false positives and false negatives:** use the [issue forms](https://github.com/WolfdeerNerd/ensign-scan/issues/new/choose). Run `ensign-scan --diagnostics` and paste its output; it contains no paths, usernames or hostnames.
- **Never paste anything personal:** file paths with your username, hostnames, the contents of flagged files, or anything from a credential file. Replace them with placeholders.

## Setting up

```
git clone https://github.com/WolfdeerNerd/ensign-scan
cd ensign-scan
python3 -m venv --system-site-packages .venv
.venv/bin/pip install -r requirements.txt yara-x ruff
```

You need ClamAV (clamd and clamscan) for the live tests. The others use a fake clamd.

## Running the tests

```
.venv/bin/ruff check .
for t in tests/*_test.py; do echo "== $t"; .venv/bin/python "$t" < /dev/null || break; done
sudo .venv/bin/python tests/clamscan_sudo_test.py
```

Each test file runs on its own and prints what passed. Tests that need something you don't have (root, clamscan, a package manager) skip themselves and say why. CI runs all of them on Python 3.11 to 3.13, in Arch, Debian and Fedora containers, and against a real clamd. A pull request is merged only when "Tests passed" is green.

A change that fixes a bug comes with a test that fails without the fix.

## Pull requests

- Keep each pull request to one change, and explain what it does and why in plain words: people and agents both read them.
- Update the README when behaviour, a setting or a command changes. `config.example.toml` and the copy in `ensign_scan/config.py` must stay identical (a test checks this).
- **No personal or system details** in code, tests, commits or the PR text: no home-directory paths with a real name, no hostnames, no email addresses. CI checks for home-directory paths.
- **No links to AI chat sessions or conversations** in commits or PR descriptions. Using AI tools to help is fine; say so in the PR if you did, and make sure you understand and have tested what you submit.
- Don't bump the version; releases are done separately.

## License

By contributing, you agree your contribution is released under the project's [MIT license](LICENSE).
