# @file
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
"""Pytest fixtures and lifecycle hooks for Proxy Verifier Uranium tests."""

from __future__ import annotations

from collections.abc import Generator, Iterator
from pathlib import Path
import os
import shutil

import pytest

from .runtime import Uranium


def pytest_addoption(parser: pytest.Parser) -> None:
    """Register Uranium runtime paths."""

    group = parser.getgroup("Proxy Verifier Uranium tests")
    group.addoption("--verifier-bin",
                    help="Directory containing verifier-client and verifier-server")
    group.addoption("--sandbox", help="Directory for isolated Uranium test process trees")
    group.addoption("--urtest-shard-index", type=int, help="Zero-based CI shard to collect")
    group.addoption("--urtest-shard-count", type=int, help="Total number of CI shards")


def pytest_configure(config: pytest.Config) -> None:
    """Register the Uranium marker and xdist scheduling mode."""

    config.addinivalue_line("markers", "uranium: Proxy Verifier end-to-end test")
    if getattr(config.option, "numprocesses", None) and getattr(config.option, "dist",
                                                                None) == "load":
        config.option.dist = "loadscope"


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Mark Uranium tests and apply deterministic CI sharding."""

    uranium_items = []
    for item in items:
        if "uranium_tests" in Path(item.path).parts:
            item.add_marker("uranium")
            uranium_items.append(item)
    shard_index = config.getoption("urtest_shard_index")
    shard_count = config.getoption("urtest_shard_count")
    if (shard_index is None) != (shard_count is None):
        raise pytest.UsageError(
            "--urtest-shard-index and --urtest-shard-count must be provided together")
    if shard_count is None:
        return
    if shard_count <= 0 or shard_index < 0 or shard_index >= shard_count:
        raise pytest.UsageError("Uranium shard values must satisfy 0 <= index < count")
    selected_ids = {
        item.nodeid
        for position, item in enumerate(
            sorted(uranium_items, key=lambda candidate: candidate.nodeid))
        if position % shard_count == shard_index
    }
    selected = [item for item in items if item not in uranium_items or item.nodeid in selected_ids]
    deselected = [item for item in uranium_items if item.nodeid not in selected_ids]
    if deselected:
        config.hook.pytest_deselected(items=deselected)
    items[:] = selected


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(
    item: pytest.Item,
    call: pytest.CallInfo[None],
) -> Generator[None, pytest.TestReport, pytest.TestReport]:
    """Retain Uranium sandboxes only for failed tests."""

    report = yield
    if item.get_closest_marker("uranium") is None:
        return report
    if report.failed:
        setattr(item, "_uranium_failed", True)
    if report.when == "teardown" and not getattr(item, "_uranium_failed", False):
        runtime = getattr(item, "_uranium_runtime", None)
        if runtime is not None:
            shutil.rmtree(runtime.run_directory, ignore_errors=True)
    return report


@pytest.fixture
def uranium(pytestconfig: pytest.Config, request: pytest.FixtureRequest) -> Iterator[Uranium]:
    """Provide a test-owned Uranium runtime."""

    repository_root = Path(__file__).resolve().parents[3]
    verifier_bin = pytestconfig.getoption("verifier_bin") or os.environ.get("VERIFIER_BIN")
    sandbox = pytestconfig.getoption("sandbox") or os.environ.get("URTEST_SANDBOX")
    missing = []
    if not verifier_bin:
        missing.append("--verifier-bin")
    if not sandbox:
        missing.append("--sandbox")
    if missing:
        raise pytest.UsageError("Uranium tests require " + " and ".join(missing))
    worker = os.environ.get("PYTEST_XDIST_WORKER", "main")
    runtime = Uranium(repository_root, Path(verifier_bin),
                      Path(sandbox) / worker, request.node.nodeid)
    setattr(request.node, "_uranium_runtime", runtime)
    with runtime.execution_lock():
        yield runtime
