# Security Policy

## Supported Versions

Ensign is in alpha. Only the latest release of `ensign-scan` on PyPI receives security fixes. Please confirm an issue still reproduces on the latest release before reporting.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public issues, discussions, or pull requests.**

Use GitHub's private vulnerability reporting instead:

1. Go to the **Security** tab of this repository.
2. Select **Advisories**, then **Report a vulnerability**.

Only the maintainer can see private reports, so you can share details safely there.

## What to Include

- The affected `ensign-scan` version
- Steps to reproduce (a proof of concept)
- The impact: what an attacker could do, or what data could be exposed

Redact your own usernames, hostnames, and file paths. **Never send real credential files or your Ensign database.** A minimal, made-up reproduction is always preferred.

## Scope

Ensign is built on three rules: it stays local, it is advisory-only, and it prefers precision over coverage. Anything that breaks the first two is a security bug.

**In scope**, anything that causes Ensign to:

- send file data, hashes, or metadata off the machine
- change permissions or system state on its own, instead of only printing recommendations
- expose its database, logs, or notifications to other users on the system
- execute code, or follow attacker-controlled paths or symlinks unsafely, while scanning hostile files or filenames

**Out of scope:**

- False positives or misses caused by ClamAV's own signatures. Please report these to ClamAV.
- Vulnerabilities in ClamAV itself. Please report these to the ClamAV project.
- Ordinary false positives in Ensign's own checks. Please use the detection issue form instead.

## What to Expect

Ensign is maintained by one volunteer, so responses are best-effort and come without a guaranteed timeline. Every report will be read. If a report seems stuck, add a comment to the advisory to nudge it.

If a report is declined (for example, because it is out of scope or cannot be reproduced), you will get an explanation of why.

Once a fix is ready, it will be disclosed through a GitHub Security Advisory, with a CVE requested where appropriate. Reporters are credited unless they prefer otherwise.

## Release Integrity

Releases are published to PyPI from this repository's GitHub Actions workflow using PyPI Trusted Publishing. No manually uploaded builds are used.
