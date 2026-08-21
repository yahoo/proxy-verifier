# @file
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for Uranium subprocess management."""

from pathlib import Path
import sys

import pytest

from tools.uranium.process import ManagedProcess, ProcessError


def test_managed_process_captures_output(tmp_path: Path) -> None:
    """A successful process exposes its captured streams."""

    process = ManagedProcess(
        "example",
        [sys.executable, "-c", "import sys; print('out'); print('err', file=sys.stderr)"],
        tmp_path,
    )
    process.start()
    process.wait()

    assert process.stdout == "out\n"
    assert process.stderr == "err\n"


def test_managed_process_validates_return_code(tmp_path: Path) -> None:
    """An unexpected exit status includes captured diagnostics."""

    process = ManagedProcess(
        "example",
        [sys.executable, "-c", "print('diagnostic'); raise SystemExit(7)"],
        tmp_path,
    )
    process.start()

    with pytest.raises(ProcessError, match="diagnostic"):
        process.wait()
