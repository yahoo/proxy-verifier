# @file
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for shared Uranium assertions."""

from pathlib import Path
import difflib

import pytest

from tools.uranium.assertions import USING_ACCELERATED_DIFF, assert_matches_gold


def test_gold_file_wildcards_match_variable_text(tmp_path: Path) -> None:
    """Preserve both established wildcard tokens in gold files."""

    expected = tmp_path / "expected.gold"
    expected.write_text("port=`` id={} done\n")

    assert_matches_gold("port=43127 id=abc-123 done\n", expected)


def test_standalone_gold_wildcard_absorbs_its_line_breaks(tmp_path: Path) -> None:
    """Let a standalone wildcard span arbitrary text without fixed newlines."""

    expected = tmp_path / "expected.gold"
    expected.write_text("before\n``\nafter\n")

    assert_matches_gold("before arbitrary text after\n", expected)


def test_gold_file_difference_reports_unified_diff(tmp_path: Path) -> None:
    """Show the expected and actual lines when gold comparison fails."""

    expected = tmp_path / "expected.gold"
    expected.write_text("expected\n")

    with pytest.raises(AssertionError, match=r"-expected\n\+actual"):
        assert_matches_gold("actual\n", expected)


def test_missing_gold_file_has_an_assertion_message(tmp_path: Path) -> None:
    """Report a missing gold file as an assertion failure."""

    with pytest.raises(AssertionError, match="Gold file does not exist"):
        assert_matches_gold("actual\n", tmp_path / "missing.gold")


def test_missing_actual_file_has_an_assertion_message(tmp_path: Path) -> None:
    """Report a missing captured-output file as an assertion failure."""

    expected = tmp_path / "expected.gold"
    expected.write_text("expected\n")

    with pytest.raises(AssertionError, match="Actual output file does not exist"):
        assert_matches_gold(tmp_path / "missing.out", expected)


def test_cdifflib_is_used_when_available() -> None:
    """Select the C sequence matcher whenever the optional module imports."""

    if not USING_ACCELERATED_DIFF:
        pytest.skip("cdifflib is unavailable")
    assert difflib.SequenceMatcher.__name__ == "CSequenceMatcher"
