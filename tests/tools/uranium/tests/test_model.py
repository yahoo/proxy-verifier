# @file
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the Uranium declarative model."""

from pathlib import Path
import re

import pytest

from tools.uranium.model import CaseSuite, assert_stream


def test_process_references_are_stable(tmp_path: Path) -> None:
    """Port and output references retain their process identity."""

    suite = CaseSuite(tmp_path / "test_example.py")
    case = suite.case("example")
    client = case.add_client("client", "replay.yaml")

    assert str(client.http_port) == f"{{uranium-port:{client.identity}:http:0}}"
    assert str(client.stdout.path) == f"{{uranium-output:{client.identity}:stdout}}"


def test_stream_regular_expressions(tmp_path: Path) -> None:
    """Contains and excludes expectations use regular expressions."""

    suite = CaseSuite(tmp_path / "test_example.py")
    process = suite.case("example").add_process("command", ["true"])
    result = process.stdout.contains(
        r"^value=[0-9]+$",
        "The value should be numeric.",
        reflags=re.MULTILINE,
    )
    process.stdout.excludes("failure", "The command should not report failure.")

    assert result is None
    assert_stream(process.stdout, "value=42\n", tmp_path)


def test_stream_regular_expression_failure(tmp_path: Path) -> None:
    """A missing required expression reports captured output."""

    suite = CaseSuite(tmp_path / "test_example.py")
    process = suite.case("example").add_process("command", ["true"])
    process.stdout.contains("expected", "The expected value should be present.")

    with pytest.raises(AssertionError, match="The expected value should be present") as error:
        assert_stream(process.stdout, "actual\n", tmp_path)
    assert "actual" in str(error.value)


def test_stream_exclusion_failure_reports_explanation(tmp_path: Path) -> None:
    """A forbidden expression reports the reason it must be absent."""

    suite = CaseSuite(tmp_path / "test_example.py")
    process = suite.case("example").add_process("command", ["true"])
    process.stdout.excludes("forbidden", "Forbidden output should be absent.")

    with pytest.raises(AssertionError, match="Forbidden output should be absent"):
        assert_stream(process.stdout, "forbidden\n", tmp_path)


def test_gold_wildcards_ignore_variable_content(tmp_path: Path) -> None:
    """Legacy gold wildcard tokens continue to ignore variable spans."""

    (tmp_path / "output.gold").write_text("prefix``suffix\n")
    suite = CaseSuite(tmp_path / "test_example.py")
    process = suite.case("example").add_process("command", ["true"])
    process.stdout.matches_gold("output.gold")

    assert_stream(process.stdout, "prefix variable content suffix\n", tmp_path)


def test_stream_reset_removes_registered_expectations(tmp_path: Path) -> None:
    """Reset explicitly discards every earlier stream expectation."""

    suite = CaseSuite(tmp_path / "test_example.py")
    process = suite.case("example").add_process("command", ["true"])
    output_path = process.stdout.path
    process.stdout.contains("discarded", "This expectation should be reset.")

    process.stdout.reset()
    process.stdout.contains("retained", "This expectation should remain.")

    assert len(process.stdout.expectations) == 1
    assert process.stdout.path == output_path
    assert_stream(process.stdout, "retained\n", tmp_path)


def test_stream_expectations_require_explanations(tmp_path: Path) -> None:
    """Regex expectations reject missing explanations at declaration time."""

    suite = CaseSuite(tmp_path / "test_example.py")
    process = suite.case("example").add_process("command", ["true"])

    with pytest.raises(ValueError, match="contains.*non-empty explanation"):
        process.stdout.contains("value", "")
    with pytest.raises(ValueError, match="excludes.*non-empty explanation"):
        process.stdout.excludes("value", "   ")


def test_process_streams_are_read_only(tmp_path: Path) -> None:
    """Assignment cannot silently replace a process stream's expectations."""

    suite = CaseSuite(tmp_path / "test_example.py")
    process = suite.case("example").add_process("command", ["true"])

    with pytest.raises(AttributeError, match=r"stdout\.contains"):
        process.stdout = object()
    with pytest.raises(AttributeError, match=r"stderr\.contains"):
        process.stderr = object()
    with pytest.raises(TypeError):
        process.stdout += object()


def test_expected_return_codes_use_explicit_api(tmp_path: Path) -> None:
    """Return-code expectations cannot be overwritten by assignment."""

    suite = CaseSuite(tmp_path / "test_example.py")
    process = suite.case("example").add_process("command", ["true"])

    assert process.return_codes == (0, )
    process.expect_return_codes(0, 1)
    assert process.return_codes == (0, 1)

    with pytest.raises(AttributeError, match="expect_return_codes"):
        process.return_codes = 1
    with pytest.raises(ValueError, match="at least one"):
        process.expect_return_codes()
    with pytest.raises(TypeError, match="integers"):
        process.expect_return_codes("1")
