# @file
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
"""Declarative model used by ordinary pytest-based Uranium tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable
import platform
import re

from .assertions import assert_matches_gold


@dataclass(frozen=True)
class Expectation:
    """One assertion applied to a process stream after a case completes."""

    kind: str
    value: str
    explanation: str = ""
    flags: int = 0


def is_platform(name: str) -> bool:
    """Return whether the current platform matches @a name."""

    return platform.system().lower() == name.lower()


@dataclass(frozen=True)
class PortRef:
    """A listener port allocated when a Uranium case starts."""

    process: "ProcessSpec"
    protocol: str
    index: int = 0

    def __str__(self) -> str:
        return f"{{uranium-port:{self.process.identity}:{self.protocol}:{self.index}}}"


@dataclass(frozen=True)
class OutputRef:
    """A process output path resolved after its case has run."""

    process: "ProcessSpec"
    stream: str

    def __str__(self) -> str:
        return f"{{uranium-output:{self.process.identity}:{self.stream}}}"


@dataclass(frozen=True)
class ArtifactRef:
    """A generated process artifact resolved in its case directory."""

    process: "ProcessSpec"
    name: str

    def __str__(self) -> str:
        return f"{{uranium-artifact:{self.process.identity}:{self.name}}}"


class StreamExpectations:
    """Assertions and the eventual path for one captured process stream."""

    def __init__(self, process: "ProcessSpec", name: str) -> None:
        self.process = process
        self.name = name
        self._expectations: list[Expectation] = []

    @property
    def expectations(self) -> tuple[Expectation, ...]:
        """Return the expectations registered for this stream."""

        return tuple(self._expectations)

    @property
    def path(self) -> OutputRef:
        """Return a symbolic reference to the captured stream path."""

        return OutputRef(self.process, self.name)

    def contains(self, expression: str, explanation: str, *, reflags: int = 0) -> None:
        """Require this stream to contain a regular expression."""

        self._require_explanation(explanation, "contains")
        self._expectations.append(Expectation("contains", expression, explanation, reflags))

    def excludes(self, expression: str, explanation: str, *, reflags: int = 0) -> None:
        """Require this stream to exclude a regular expression."""

        self._require_explanation(explanation, "excludes")
        self._expectations.append(Expectation("excludes", expression, explanation, reflags))

    def matches_gold(self, path: str, explanation: str = "") -> None:
        """Require this stream to match a wildcard-aware gold file."""

        self._expectations.append(Expectation("gold", path, explanation))

    def reset(self) -> None:
        """Remove every expectation previously registered for this stream."""

        self._expectations.clear()

    @staticmethod
    def _require_explanation(explanation: str, method: str) -> None:
        if not explanation.strip():
            raise ValueError(f"{method}() requires a non-empty explanation")


@dataclass(eq=False)
class ProcessSpec:
    """Declarative configuration for one process in a Uranium case."""

    case: "Case"
    kind: str
    name: str
    options: dict[str, Any]
    identity: int
    ready: bool = True
    _expected_return_codes: tuple[int, ...] = field(default=(0, ), init=False, repr=False)
    _stdout: StreamExpectations = field(init=False, repr=False)
    _stderr: StreamExpectations = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._stdout = StreamExpectations(self, "stdout")
        self._stderr = StreamExpectations(self, "stderr")

    @property
    def stdout(self) -> StreamExpectations:
        """Return the read-only standard-output expectation API."""

        return self._stdout

    @stdout.setter
    def stdout(self, value: Any) -> None:
        raise AttributeError(
            "stdout is read-only; use stdout.contains(), stdout.excludes(), or stdout.matches_gold()"
        )

    @property
    def stderr(self) -> StreamExpectations:
        """Return the read-only standard-error expectation API."""

        return self._stderr

    @stderr.setter
    def stderr(self, value: Any) -> None:
        raise AttributeError(
            "stderr is read-only; use stderr.contains(), stderr.excludes(), or stderr.matches_gold()"
        )

    @property
    def return_codes(self) -> tuple[int, ...]:
        """Return the acceptable exit statuses for this process."""

        return self._expected_return_codes

    @return_codes.setter
    def return_codes(self, values: Any) -> None:
        raise AttributeError("return_codes is read-only; use expect_return_codes()")

    def expect_return_codes(self, *values: int) -> None:
        """Set the acceptable exit statuses for this process."""

        if not values:
            raise ValueError("expect_return_codes() requires at least one status")
        if not all(isinstance(value, int) for value in values):
            raise TypeError("expect_return_codes() statuses must be integers")
        self._expected_return_codes = values

    def _port(self, protocol: str) -> PortRef:
        ports = self.options.setdefault(f"{protocol}_ports", [])
        if not ports:
            ports.append(PortRef(self, protocol))
        return ports[0]

    @property
    def http_port(self) -> PortRef:
        """Return this process's first HTTP port."""

        return self._port("http")

    @property
    def https_port(self) -> PortRef:
        """Return this process's first HTTPS port."""

        return self._port("https")

    @property
    def http3_port(self) -> PortRef:
        """Return this process's first HTTP/3 port."""

        return self._port("http3")

    def artifact(self, name: str) -> ArtifactRef:
        """Return a symbolic reference to a generated artifact."""

        return ArtifactRef(self, name)


class Case:
    """A group of processes that execute together."""

    def __init__(self, suite: "CaseSuite", name: str, index: int) -> None:
        self.suite = suite
        self.name = name
        self.index = index
        self.processes: list[ProcessSpec] = []

    def _add(self, kind: str, name: str, **options: Any) -> ProcessSpec:
        process = ProcessSpec(self, kind, name, options, self.suite.next_process_identity())
        self.processes.append(process)
        return process

    def add_client(
        self,
        name: str,
        replay_path: str | Path | ArtifactRef | None = None,
        **options: Any,
    ) -> ProcessSpec:
        """Add a verifier-client process to this case."""

        replay_path = options.pop("replay_dir", replay_path)
        return self._add("client", name, replay_path=replay_path, **options)

    def add_server(
        self,
        name: str,
        replay_path: str | Path | ArtifactRef | None = None,
        **options: Any,
    ) -> ProcessSpec:
        """Add a verifier-server process to this case."""

        replay_path = options.pop("replay_dir", replay_path)
        return self._add("server", name, replay_path=replay_path, **options)

    def add_proxy(self, name: str, **options: Any) -> ProcessSpec:
        """Add the Python test proxy to this case."""

        return self._add("proxy", name, **options)

    def add_process(
        self,
        name: str,
        command: str | list[str | Path | OutputRef | ArtifactRef],
        *,
        copies: Iterable[str | Path] = (),
        environment: dict[str, str] | None = None,
    ) -> ProcessSpec:
        """Add an arbitrary foreground command to this case."""

        return self._add("process", name, command=command, copies=tuple(copies),
                         environment=environment)

    def add_replay_generator(
        self,
        name: str,
        *,
        num_transactions: int = 1,
        url_file: str | Path | None = None,
        other_args: str = "",
    ) -> ProcessSpec:
        """Add a replay-gen.py invocation to this case."""

        return self._add(
            "replay_generator",
            name,
            num_transactions=num_transactions,
            url_file=url_file,
            other_args=other_args,
        )


class CaseSuite:
    """Sequential Uranium cases contained in one normal pytest module."""

    def __init__(self, module_path: str | Path) -> None:
        self.module_path = Path(module_path).resolve()
        self.cases: list[Case] = []
        self._process_identity = 0

    @property
    def test_directory(self) -> Path:
        """Return the directory holding this suite's test module."""

        return self.module_path.parent

    def case(self, name: str) -> Case:
        """Append and return a test case."""

        case = Case(self, name, len(self.cases))
        self.cases.append(case)
        return case

    def next_process_identity(self) -> int:
        """Return a suite-unique process identifier."""

        identity = self._process_identity
        self._process_identity += 1
        return identity


def assert_stream(
    expectations: StreamExpectations,
    content: str,
    test_directory: Path,
    resolve: Callable[[str], str] = str,
) -> None:
    """Apply the configured expectations to captured stream content."""

    normalized = content.replace("\r\n", "\n")
    for expectation in expectations.expectations:
        detail = expectation.explanation or expectation.value
        if expectation.kind == "contains":
            assert re.search(resolve(expectation.value), normalized, expectation.flags), (
                f"Expected {expectations.process.name} {expectations.name} to contain {detail!r}.\n{normalized}"
            )
        elif expectation.kind == "excludes":
            assert not re.search(resolve(expectation.value), normalized, expectation.flags), (
                f"Expected {expectations.process.name} {expectations.name} to exclude {detail!r}.\n{normalized}"
            )
        elif expectation.kind == "gold":
            path = test_directory / expectation.value
            assert_matches_gold(normalized, path)
        else:
            raise ValueError(f"Unknown stream expectation: {expectation.kind}")
