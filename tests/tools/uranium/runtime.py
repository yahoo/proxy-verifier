# @file
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
"""Execution runtime for Proxy Verifier Uranium test suites."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any
import fcntl
import hashlib
import os
import re
import shlex
import shutil
import socket
import sys

from .model import ArtifactRef, Case, CaseSuite, OutputRef, PortRef, ProcessSpec, assert_stream
from .process import ManagedProcess


class RuntimeConfigError(ValueError):
    """Report invalid Uranium runtime configuration."""


def _tcp_open(port: int, address: str = "127.0.0.1") -> bool:
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as connection:
            connection.settimeout(0.1)
            return connection.connect_ex((address, port)) == 0
    except OSError:
        return False


class Uranium:
    """Own paths, ports, processes, and sandboxes for one pytest item."""

    def __init__(self, repository_root: Path, verifier_bin: Path, sandbox_root: Path,
                 nodeid: str) -> None:
        self.repository_root = repository_root.resolve()
        self.verifier_bin = verifier_bin.resolve()
        self.sandbox_root = sandbox_root.resolve()
        self.nodeid = nodeid
        required = [self.verifier_bin / "verifier-client", self.verifier_bin / "verifier-server"]
        if missing := [str(path) for path in required if not path.is_file()]:
            raise RuntimeConfigError("Missing required test programs: " + ", ".join(missing))
        self.run_directory = self.sandbox_for(nodeid)
        self._prepare_sandbox(self.run_directory)
        self._ports: dict[PortRef, int] = {}
        self._outputs: dict[OutputRef, Path] = {}
        self._artifacts: dict[ArtifactRef, Path] = {}

    def sandbox_for(self, nodeid: str) -> Path:
        """Return a short deterministic sandbox path for a pytest item."""

        digest = hashlib.sha256(nodeid.encode()).hexdigest()[:12]
        return self.sandbox_root / f"test-{digest}"

    def allocate_port(self, socket_type: int = socket.SOCK_STREAM) -> int:
        """Allocate a unique available port across xdist workers."""

        common_sandbox = self.sandbox_root.parent
        common_sandbox.mkdir(parents=True, exist_ok=True)
        state_path = common_sandbox / ".port-counter"
        with state_path.open("a+") as state:
            fcntl.flock(state, fcntl.LOCK_EX)
            state.seek(0)
            candidate = int(state.read().strip() or "10000")
            for _ in range(30000):
                candidate = 10000 if candidate >= 40000 else candidate + 1
                with socket.socket(socket.AF_INET, socket_type) as probe:
                    try:
                        probe.bind(("127.0.0.1", candidate))
                    except OSError:
                        continue
                state.seek(0)
                state.truncate()
                state.write(str(candidate))
                state.flush()
                return candidate
        raise RuntimeConfigError("Could not allocate a test port")

    def run(self, suite: CaseSuite) -> None:
        """Run every case in @a suite sequentially."""

        for case in suite.cases:
            try:
                self._run_case(case)
            except Exception as error:
                if add_note := getattr(error, "add_note", None):
                    add_note(f"Uranium case: {case.name}")
                raise

    def _run_case(self, case: Case) -> None:
        case_directory = self.run_directory / f"case-{case.index:03d}"
        case_directory.mkdir(parents=True)
        processes = {spec: self._make_process(spec, case_directory) for spec in case.processes}
        servers = [spec for spec in case.processes if spec.kind == "server"]
        proxies = [spec for spec in case.processes if spec.kind == "proxy"]
        foreground = [
            spec for spec in case.processes
            if spec.kind in ("client", "process", "replay_generator")
        ]
        has_traffic_driver = bool(proxies or any(spec.kind == "client" for spec in foreground))
        started: list[ProcessSpec] = []
        try:
            if has_traffic_driver:
                for spec in servers:
                    process = processes[spec]
                    process.start()
                    started.append(spec)
                    if spec.ready:
                        address, port = self._server_ready_address(spec)
                        process.wait_until(
                            lambda address=address, port=port: _tcp_open(port, address),
                            10,
                            f"listener on {address}:{port}",
                        )
                for spec in proxies:
                    process = processes[spec]
                    process.start()
                    started.append(spec)
                    self._wait_for_proxy(spec, process)

            for spec in foreground:
                process = processes[spec]
                process.start()
                process.wait(timeout=float(spec.options.get("timeout", 120)))

            for spec in reversed(proxies):
                processes[spec].interrupt()
                started.remove(spec)
            for spec in reversed(servers):
                if spec in started:
                    processes[spec].interrupt()
                    started.remove(spec)

            if not has_traffic_driver:
                for spec in servers:
                    process = processes[spec]
                    process.start()
                    process.wait(timeout=float(spec.options.get("timeout", 30)))
        finally:
            for spec in reversed(started):
                processes[spec].stop()

        for spec, process in processes.items():
            assert_stream(spec.stdout, process.stdout, case.suite.test_directory,
                          self._resolve_text)
            assert_stream(spec.stderr, process.stderr, case.suite.test_directory,
                          self._resolve_text)

    def _make_process(self, spec: ProcessSpec, case_directory: Path) -> ManagedProcess:
        process_directory = case_directory / spec.name
        process_directory.mkdir(parents=True)
        self._outputs[spec.stdout.path] = process_directory / f"{spec.name}.stdout"
        self._outputs[spec.stderr.path] = process_directory / f"{spec.name}.stderr"
        if spec.kind == "client":
            command = self._client_command(spec, process_directory)
        elif spec.kind == "server":
            command = self._server_command(spec, process_directory)
        elif spec.kind == "proxy":
            command = self._proxy_command(spec, process_directory)
        elif spec.kind == "replay_generator":
            command = self._replay_generator_command(spec, process_directory)
        elif spec.kind == "process":
            command = self._generic_command(spec, process_directory)
        else:
            raise RuntimeConfigError(f"Unknown process kind: {spec.kind}")
        environment = os.environ.copy()
        if additions := spec.options.get("environment"):
            environment.update({key: self._resolve_text(value) for key, value in additions.items()})
        return ManagedProcess(spec.name, command, process_directory, environment, spec.return_codes)

    def _client_command(self, spec: ProcessSpec, directory: Path) -> list[str | Path]:
        options = spec.options
        command: list[str | Path] = [self.verifier_bin / "verifier-client", "run"]
        if replay_path := options.get("replay_path"):
            command.append(self._resolve_path(spec.case.suite, replay_path))
        use_ipv6 = bool(options.get("use_ipv6", False))
        for protocol, argument in (
            ("http", "--connect-http"),
            ("https", "--connect-https"),
            ("http3", "--connect-http3"),
        ):
            ports = self._configured_ports(spec, protocol)
            if ports:
                command.extend([argument, self._address_argument(ports, use_ipv6)])
        if self._configured_ports(spec, "https") or self._configured_ports(spec, "http3"):
            self._add_tls_arguments(command, spec.case.suite, options, directory, client=True)
            if options.get("enable_tls_secrets_logging", True):
                command.extend(["--tls-secrets-log-file", directory / "tls_secrets.txt"])
        if self._configured_ports(spec, "http3") and options.get("enable_qlogging", True):
            command.extend(["--qlog-dir", directory / "qlog"])
        if options.get("verbose", True):
            command.extend(["--verbose", "diag"])
        if options.get("single_threaded", True):
            command.extend(["--thread-limit", "1"])
        command.extend(shlex.split(str(options.get("other_args", ""))))
        return command

    def _server_command(self, spec: ProcessSpec, directory: Path) -> list[str | Path]:
        options = spec.options
        command: list[str | Path] = [self.verifier_bin / "verifier-server", "run"]
        use_ipv6 = bool(options.get("use_ipv6", False))
        for protocol, argument in (("http", "--listen-http"), ("https", "--listen-https")):
            ports = self._configured_ports(spec, protocol)
            if ports:
                command.extend([argument, self._address_argument(ports, use_ipv6)])
        if self._configured_ports(spec, "https") or self._configured_ports(spec, "http3"):
            self._add_tls_arguments(command, spec.case.suite, options, directory, client=False)
            if options.get("enable_tls_secrets_logging", True):
                command.extend(["--tls-secrets-log-file", directory / "tls_secrets.txt"])
        if replay_path := options.get("replay_path"):
            command.append(self._resolve_path(spec.case.suite, replay_path))
        if options.get("verbose", True):
            command.extend(["--verbose", "diag"])
        command.extend(shlex.split(str(options.get("other_args", ""))))
        return command

    def _proxy_command(self, spec: ProcessSpec, directory: Path) -> list[str | Path]:
        options = spec.options
        proxy_script = self.repository_root / "tests" / "tools" / "uranium" / "proxy" / "test_proxy.py"
        listen_port = int(self._resolve(options.get("listen_port", 8080)))
        server_port = int(self._resolve(options.get("server_port", 8081)))
        command: list[str | Path] = [
            sys.executable,
            "-u",
            proxy_script,
            "--listen-port",
            str(listen_port),
            "--server-port",
            str(server_port),
        ]
        if options.get("use_ssl", False):
            pem = options.get("https_pem") or self.repository_root / "tests" / "keys" / "client.pem"
            ca = options.get("ca_pem") or self.repository_root / "tests" / "keys" / "ca.pem"
            command.extend([
                "--https-pem",
                self._resolve_path(spec.case.suite, pem), "--ca-pem",
                self._resolve_path(spec.case.suite, ca)
            ])
        for option, flag in (
            ("close_on_goaway", "--close-on-goaway"),
            ("use_http2_to_1", "--http2_to_1"),
            ("use_http2_to_2", "--http2_to_2"),
            ("use_http3_to_1", "--http3_to_1"),
        ):
            if options.get(option, False):
                command.append(flag)
        if options.get("use_http3_to_1", False):
            sentinel = directory / "http3-listener-ready"
            options["ready_sentinel"] = sentinel
            command.extend(["--listening-http3-sentinel", sentinel])
        return command

    def _replay_generator_command(self, spec: ProcessSpec, directory: Path) -> list[str | Path]:
        replay_directory = directory / "replay_dir"
        self._artifacts[spec.artifact("replay_dir")] = replay_directory
        url_file = spec.options.get("url_file")
        if url_file is None:
            url_file = self.repository_root / "tests" / "tools" / "uranium" / "default_url_file"
        command: list[str | Path] = [
            sys.executable,
            self.repository_root / "tools" / "replay-gen.py",
            "--number",
            str(spec.options.get("num_transactions", 1)),
            "--url-file",
            self._resolve_path(spec.case.suite, url_file),
            "--output",
            replay_directory,
        ]
        command.extend(shlex.split(str(spec.options.get("other_args", ""))))
        return command

    def _generic_command(self, spec: ProcessSpec, directory: Path) -> list[str | Path]:
        for path in spec.options.get("copies", ()):
            source = self._resolve_path(spec.case.suite, path)
            destination = directory / source.name
            if source.is_dir():
                shutil.copytree(source, destination)
            else:
                shutil.copy2(source, destination)
        command = spec.options["command"]
        if isinstance(command, str):
            return shlex.split(self._resolve_text(command))
        return [self._resolve_text(value) for value in command]

    def _configured_ports(self, spec: ProcessSpec, protocol: str) -> list[int]:
        key = f"{protocol}_ports"
        options = spec.options
        if key not in options:
            enabled = options.get("find_ports", True) and options.get(f"configure_{protocol}", True)
            options[key] = [PortRef(spec, protocol)] if enabled else []
        return [int(self._resolve(value)) for value in options[key]]

    def _add_tls_arguments(
        self,
        command: list[str | Path],
        suite: CaseSuite,
        options: dict[str, Any],
        directory: Path,
        *,
        client: bool,
    ) -> None:
        certificate_key = "ssl_cert"
        certificate = options.get(certificate_key, "")
        if certificate == "":
            certificate = self.repository_root / "tests" / "keys" / ("client.pem"
                                                                     if client else "server.pem")
        if certificate is not None:
            command.extend([
                "--client-cert" if client else "--server-cert",
                self._resolve_path(suite, certificate)
            ])
        ca_certs = options.get("ca_certs", "")
        if ca_certs == "":
            ca_certs = self.repository_root / "tests" / "keys" / "ca.pem"
        if ca_certs is not None:
            command.extend(["--ca-certs", self._resolve_path(suite, ca_certs)])

    def _server_ready_address(self, spec: ProcessSpec) -> tuple[str, int]:
        address = "::1" if spec.options.get("use_ipv6", False) else "127.0.0.1"
        for protocol in ("http", "https"):
            if ports := self._configured_ports(spec, protocol):
                return address, ports[0]
        raise RuntimeConfigError(f"No TCP readiness port configured for {spec.name}")

    def _wait_for_proxy(self, spec: ProcessSpec, process: ManagedProcess) -> None:
        sentinel = spec.options.get("ready_sentinel")
        if sentinel:
            process.wait_until(lambda: Path(sentinel).exists(), 10, f"sentinel {sentinel}")
            return
        port = int(self._resolve(spec.options.get("listen_port", 8080)))
        process.wait_until(lambda: _tcp_open(port), 10, f"listener on 127.0.0.1:{port}")

    def _resolve(self, value: Any) -> Any:
        if isinstance(value, PortRef):
            if value not in self._ports:
                self._ports[value] = self.allocate_port(socket.SOCK_DGRAM if value.protocol ==
                                                        "http3" else socket.SOCK_STREAM)
            return self._ports[value]
        if isinstance(value, OutputRef):
            return self._outputs[value]
        if isinstance(value, ArtifactRef):
            return self._artifacts[value]
        return value

    def _resolve_text(self, value: Any) -> str:
        if isinstance(value, (PortRef, OutputRef, ArtifactRef)):
            return str(self._resolve(value))
        text = str(value)
        text = text.replace("{verifier-client}", str(self.verifier_bin / "verifier-client"))
        text = text.replace("{verifier-server}", str(self.verifier_bin / "verifier-server"))
        patterns = [
            (r"\{uranium-port:(\d+):(http|https|http3):(\d+)\}", self._replace_port),
            (r"\{uranium-output:(\d+):(stdout|stderr)\}", self._replace_output),
            (r"\{uranium-artifact:(\d+):([^}]+)\}", self._replace_artifact),
        ]
        for pattern, replacement in patterns:
            text = re.sub(pattern, replacement, text)
        return text

    def _replace_port(self, match: re.Match[str]) -> str:
        identity, protocol, index = match.groups()
        ref = next(ref for ref in self._ports.keys() | self._all_port_refs()
                   if ref.process.identity == int(identity) and ref.protocol == protocol
                   and ref.index == int(index))
        return str(self._resolve(ref))

    def _replace_output(self, match: re.Match[str]) -> str:
        identity, stream = match.groups()
        ref = next(ref for ref in self._outputs
                   if ref.process.identity == int(identity) and ref.stream == stream)
        return str(self._outputs[ref])

    def _replace_artifact(self, match: re.Match[str]) -> str:
        identity, name = match.groups()
        ref = next(ref for ref in self._artifacts
                   if ref.process.identity == int(identity) and ref.name == name)
        return str(self._artifacts[ref])

    def _all_port_refs(self) -> set[PortRef]:
        refs: set[PortRef] = set()
        for output in self._outputs:
            spec = output.process
            for protocol in ("http", "https", "http3"):
                for index, value in enumerate(spec.options.get(f"{protocol}_ports", [])):
                    if isinstance(value, PortRef):
                        refs.add(PortRef(value.process, value.protocol, index))
        return refs

    def _resolve_path(self, suite: CaseSuite, value: Any) -> Path:
        if isinstance(value, ArtifactRef):
            return Path(self._resolve(value))
        path = Path(self._resolve_text(value))
        return path if path.is_absolute() else suite.test_directory / path

    @staticmethod
    def _address_argument(ports: Sequence[int], use_ipv6: bool) -> str:
        address = "[::1]" if use_ipv6 else "127.0.0.1"
        return ",".join(f"{address}:{port}" for port in ports)

    def _prepare_sandbox(self, path: Path) -> None:
        if path.parent != self.sandbox_root or path == self.sandbox_root:
            raise RuntimeConfigError(f"Refusing to clean unsafe sandbox path: {path}")
        if path.exists():
            shutil.rmtree(path)
        path.mkdir(parents=True)

    @contextmanager
    def execution_lock(self) -> Iterator[None]:
        """Hold a shared execution lock while this test runs."""

        common_sandbox = self.sandbox_root.parent
        common_sandbox.mkdir(parents=True, exist_ok=True)
        with (common_sandbox / ".execution-lock").open("a+") as lock:
            fcntl.flock(lock, fcntl.LOCK_SH)
            try:
                yield
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)
