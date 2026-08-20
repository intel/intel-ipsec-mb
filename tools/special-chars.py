#!/usr/bin/env python3

"""
**********************************************************************
  Copyright(c) 2026, Intel Corporation All rights reserved.

  SPDX-License-Identifier: BSD-3-Clause
**********************************************************************
"""

"""
special-chars.py - check or replace special characters in source files.

Modes:
  --check  Scan files; print errors and exit 1 if any are found.
  --fix    Replace/remove each special character.

Usage:
  special-chars.py --check PATH...
  special-chars.py --fix   PATH...

PATH may be a file or a directory (directories are walked recursively).
"""

import argparse
import os
import sys


# =============================================================================
# SECTION 1: Constants
# =============================================================================
EXTENSIONS = {".asm", ".c", ".h", ".inc", ".cpp", ".md", ".txt", ".cmake", ".sh", ".py", ".pl"}

# (unicode char, ascii replacement, label)
CHARS = [
    ("\u2014", "-",   "Em dash (U+2014)"),
    ("\u2013", "-",   "En dash (U+2013)"),
    ("\u2192", "->",  "Right arrow (U+2192)"),
    ("\u00a0", " ",   "Non-breaking space (U+00A0)"),
    ("\u200b", "",    "Zero-width space (U+200B)"),
    ("\ufeff", "",    "BOM (U+FEFF)"),
    ("\u201c", '"',   "Left double quote (U+201C)"),
    ("\u201d", '"',   "Right double quote (U+201D)"),
    ("\u2018", "'",   "Left single quote (U+2018)"),
    ("\u2019", "'",   "Right single quote (U+2019)"),
    ("\u2026", "...", "Ellipsis (U+2026)"),
]


# =============================================================================
# SECTION 2: File collection
# =============================================================================
def iter_files(paths):
    """Yield files to process, walking any directories recursively."""
    for path in paths:
        if os.path.isfile(path):
            yield path
        elif os.path.isdir(path):
            for root, _, files in os.walk(path):
                for name in sorted(files):
                    if os.path.splitext(name)[1] in EXTENSIONS:
                        yield os.path.join(root, name)
        else:
            raise RuntimeError("path not found: {}".format(path))


# =============================================================================
# SECTION 3: Check and fix logic
# =============================================================================
def check(paths):
    """Scan files for special characters; return True if none found."""
    found = False
    for path in iter_files(paths):
        try:
            with open(path, encoding="utf-8", errors="replace", newline="") as fh:
                text = fh.read()
        except OSError as exc:
            print("WARNING: {}: {}".format(path, exc), file=sys.stderr)
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for ch, _, label in CHARS:
                if ch in line:
                    print("ERROR: {}:{}: {}".format(path, lineno, label))
                    found = True
    if not found:
        print("PASS: no special characters found.")
    return not found


def fix(paths):
    """Replace special characters in-place; print the names of changed files."""
    for path in iter_files(paths):
        try:
            with open(path, encoding="utf-8", errors="replace", newline="") as fh:
                text = fh.read()
        except OSError as exc:
            print("WARNING: {}: {}".format(path, exc), file=sys.stderr)
            continue
        fixed = text
        for ch, rep, _ in CHARS:
            fixed = fixed.replace(ch, rep)
        if fixed != text:
            try:
                with open(path, "w", encoding="utf-8", newline="") as fh:
                    fh.write(fixed)
                print("FIXED: {}".format(path))
            except OSError as exc:
                print("WARNING: {}: {}".format(path, exc), file=sys.stderr)


# =============================================================================
# SECTION 4: Entry point
# =============================================================================
def main():
    """Parse arguments and dispatch to check or fix."""
    parser = argparse.ArgumentParser(
        description="Check or replace special characters in source files.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true",
                      help="Scan files; exit 1 if any special characters are found.")
    mode.add_argument("--fix", action="store_true",
                      help="Replace special characters in-place with ASCII equivalents.")
    parser.add_argument("paths", nargs="+", metavar="PATH",
                        help="Files or directories to process.")
    args = parser.parse_args()

    if args.check:
        passed = check(args.paths)
        raise SystemExit(0 if passed else 1)
    else:
        fix(args.paths)


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as exc:
        print("ERROR: {}".format(exc), file=sys.stderr)
        raise SystemExit(1)

