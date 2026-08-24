# @file
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
"""Assertions shared by Uranium tests."""

from __future__ import annotations

from pathlib import Path
import difflib
import re

try:
    from cdifflib import CSequenceMatcher
except ImportError:
    USING_ACCELERATED_DIFF = False
else:
    difflib.SequenceMatcher = CSequenceMatcher
    USING_ACCELERATED_DIFF = True


def assert_matches_gold(actual: str | Path, expected: Path) -> None:
    """Assert that output matches a wildcard-aware gold file."""

    if isinstance(actual, Path):
        if not actual.is_file():
            raise AssertionError(f"Actual output file does not exist: {actual}")
        actual_text = actual.read_text(errors="replace")
        actual_name = str(actual)
    else:
        actual_text = actual
        actual_name = "actual"

    actual_text = actual_text.replace("\r\n", "\n")
    if not expected.is_file():
        raise AssertionError(f"Gold file does not exist: {expected}")
    expected_text = expected.read_text(errors="replace").replace("\r\n", "\n")
    expected_text = expected_text.replace("\n``\n", "``")
    pattern = "\\A" + ".*?".join(
        re.escape(part) for part in re.split(r"(?:\{\}|``)", expected_text)) + "\\Z"
    if re.match(pattern, actual_text, re.DOTALL) is None:
        difference = "".join(
            difflib.unified_diff(
                expected_text.splitlines(True),
                actual_text.splitlines(True),
                str(expected),
                actual_name,
            ))
        raise AssertionError(f"Output did not match gold file:\n{difference}")
