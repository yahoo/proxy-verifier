# @file
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
"""Subprocess lifecycle support for Proxy Verifier Uranium tests."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
import os
import signal
import subprocess
import time


class ProcessError(RuntimeError):
    """Report an unexpected process exit or readiness failure."""


class ManagedProcess:
    """Own a subprocess and its captured output files."""

    def __init__(
            self,
            name: str,
            command: Sequence[str | Path],
            run_directory: Path,
            environment: dict[str, str] | None = None,
            expected_return_codes: Iterable[int] = (0, ),
    ) -> None:
        self.name = name
        self.command = [str(argument) for argument in command]
        self.run_directory = run_directory
        self.environment = environment
        self.expected_return_codes = set(expected_return_codes)
        self.stdout_path = run_directory / f"{name}.stdout"
        self.stderr_path = run_directory / f"{name}.stderr"
        self._stdout = None
        self._stderr = None
        self._process: subprocess.Popen[bytes] | None = None

    @property
    def return_code(self) -> int | None:
        """Return the process exit status, or None while it is running."""

        return None if self._process is None else self._process.poll()

    @property
    def stdout(self) -> str:
        """Return captured standard output."""

        self._flush_streams()
        return self.stdout_path.read_text(errors="replace") if self.stdout_path.exists() else ""

    @property
    def stderr(self) -> str:
        """Return captured standard error."""

        self._flush_streams()
        return self.stderr_path.read_text(errors="replace") if self.stderr_path.exists() else ""

    @property
    def output(self) -> str:
        """Return captured standard output and error."""

        return self.stdout + self.stderr

    def start(self) -> None:
        """Start the process in a new process group."""

        self.run_directory.mkdir(parents=True, exist_ok=True)
        self._stdout = self.stdout_path.open("wb")
        self._stderr = self.stderr_path.open("wb")
        self._process = subprocess.Popen(
            self.command,
            cwd=self.run_directory,
            env=self.environment,
            stdout=self._stdout,
            stderr=self._stderr,
            start_new_session=True,
        )

    def wait_until(self, ready: Callable[[], bool], timeout: float, description: str) -> None:
        """Wait for readiness while ensuring the process remains alive."""

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.return_code is not None:
                self._close_streams()
                raise ProcessError(
                    f"{self.name} exited with status {self.return_code} while waiting for {description}.\n{self.output}"
                )
            if ready():
                return
            time.sleep(0.05)
        raise ProcessError(
            f"Timed out after {timeout:g}s waiting for {self.name}: {description}.\n{self.output}")

    def wait(self, timeout: float = 60, *, validate: bool = True) -> int:
        """Wait for completion and optionally validate the return code."""

        if self._process is None:
            raise ProcessError(f"{self.name} has not been started")
        try:
            return_code = self._process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            self.stop()
            raise ProcessError(
                f"{self.name} timed out after {timeout:g}s.\n{self.output}") from error
        finally:
            self._close_streams()
        if validate and return_code not in self.expected_return_codes:
            raise ProcessError(f"{self.name} exited with status {return_code}; expected "
                               f"{sorted(self.expected_return_codes)}.\n{self.output}")
        return return_code

    def interrupt(self, timeout: float = 30) -> int:
        """Send SIGINT and wait for a graceful, validated shutdown."""

        if self._process is None:
            raise ProcessError(f"{self.name} has not been started")
        if self._process.poll() is None:
            self._process.send_signal(signal.SIGINT)
        return self.wait(timeout)

    def stop(self, timeout: float = 5) -> None:
        """Stop the process group, escalating to SIGKILL if necessary."""

        if self._process is None:
            self._close_streams()
            return
        if self._process.poll() is None:
            try:
                os.killpg(self._process.pid, signal.SIGTERM)
                self._process.wait(timeout=timeout)
            except ProcessLookupError:
                pass
            except subprocess.TimeoutExpired:
                os.killpg(self._process.pid, signal.SIGKILL)
                self._process.wait(timeout=timeout)
        self._close_streams()

    def _flush_streams(self) -> None:
        for stream in (self._stdout, self._stderr):
            if stream is not None and not stream.closed:
                stream.flush()

    def _close_streams(self) -> None:
        for stream in (self._stdout, self._stderr):
            if stream is not None and not stream.closed:
                stream.close()
