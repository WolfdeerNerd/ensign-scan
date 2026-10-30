#!/usr/bin/env python3
"""Run Ensign from a source checkout: python3 main.py

The real entry point is ensign_scan.cli:main, which is also what the
installed `ensign-scan` command runs. This file only exists so that
`python3 main.py` keeps working without installing the package.
"""
from ensign_scan.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
