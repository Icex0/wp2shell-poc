#!/usr/bin/env python3
"""Standalone launcher — equivalent to `python3 -m wp2shell`."""

import sys

from wp2shell.cli import main

if __name__ == "__main__":
    sys.exit(main())
