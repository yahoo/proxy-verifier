#!/usr/bin/env python3
# @file
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

import argparse
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path

EXIT_TIMEOUT_SECONDS = 5.0
LOG_TIMEOUT_SECONDS = 5.0
CLIENT_POST_READY_DELAY_SECONDS = 0.2
SERVER_POST_READY_DELAY_SECONDS = 1.0


def fail(message: str, log_path: Path | None = None) -> None:
    print(f"FAIL: {message}")
    if log_path is not None and log_path.exists():
        print("----- log output -----")
        print(log_path.read_text(encoding="utf-8", errors="replace"))
    raise SystemExit(1)


def find_unused_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_log_text(log_path: Path, needle: str, process: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + LOG_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        contents = ""
        if log_path.exists():
            contents = log_path.read_text(encoding="utf-8", errors="replace")
            if needle in contents:
                return
        if process.poll() is not None:
            fail(
                f"process exited before emitting {needle!r} (rc={process.returncode})",
                log_path,
            )
        time.sleep(0.05)
    fail(f"timed out waiting for {needle!r}", log_path)


def wait_for_exit(process: subprocess.Popen[str], log_path: Path) -> float:
    start = time.monotonic()
    try:
        process.wait(timeout=EXIT_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        fail(
            f"process did not exit within {EXIT_TIMEOUT_SECONDS:.1f}s after SIGINT",
            log_path,
        )
    return time.monotonic() - start


def run_server_check(verifier_server: Path) -> None:
    replay = textwrap.dedent("""\
        meta:
          version: '1.0'
        sessions:
        - transactions:
          - proxy-request:
              method: GET
              url: /slow
              version: '1.1'
              headers:
                fields:
                - [ Host, example.com ]
                - [ uuid, slow-request ]
            server-response:
              delay: 15s
              status: 200
              reason: OK
              headers:
                fields:
                - [ Content-Length, '0' ]
        """)
    with tempfile.TemporaryDirectory() as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        replay_path = temp_dir / "server-delay.yaml"
        replay_path.write_text(replay, encoding="utf-8")
        log_path = temp_dir / "server.log"
        port = find_unused_port()
        process = None
        curl_process = None
        try:
            with log_path.open("w", encoding="utf-8") as log_file:
                process = subprocess.Popen(
                    [
                        str(verifier_server),
                        "run",
                        "--listen-http",
                        f"127.0.0.1:{port}",
                        str(replay_path),
                        "--verbose",
                        "diag",
                    ],
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
            wait_for_log_text(log_path, "Listening for HTTP/1.x", process)
            curl_path = shutil.which("curl")
            if curl_path is None:
                fail("curl is required for the server-side SIGINT check", log_path)
            curl_process = subprocess.Popen(
                [
                    curl_path,
                    "-sv",
                    "-H",
                    "uuid: slow-request",
                    f"http://127.0.0.1:{port}/slow",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            wait_for_log_text(log_path, 'HTTP/1 Method Success: Key: "slow-request"', process)
            time.sleep(SERVER_POST_READY_DELAY_SECONDS)
            process.send_signal(signal.SIGINT)
            exit_duration = wait_for_exit(process, log_path)
        finally:
            if curl_process is not None and curl_process.poll() is None:
                curl_process.kill()
                curl_process.wait()
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()

        output = log_path.read_text(encoding="utf-8", errors="replace")
        if process.returncode != 0:
            fail(f"verifier-server exited with {process.returncode}", log_path)
        if "Handling SIGINT" not in output:
            fail("verifier-server did not log SIGINT shutdown handling", log_path)
        print(f"OK: server exited promptly in {exit_duration:.3f}s")


def run_client_check(verifier_client: Path) -> None:
    replay = textwrap.dedent("""\
        meta:
          version: '1.0'
        sessions:
        - delay: 15s
          transactions:
          - client-request:
              method: GET
              url: /slow
              version: '1.1'
              headers:
                fields:
                - [ Host, example.com ]
                - [ uuid, slow-request ]
            proxy-response:
              status: 200
        """)
    with tempfile.TemporaryDirectory() as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        replay_path = temp_dir / "client-delay.yaml"
        replay_path.write_text(replay, encoding="utf-8")
        log_path = temp_dir / "client.log"
        unused_port = find_unused_port()
        process = None
        try:
            with log_path.open("w", encoding="utf-8") as log_file:
                process = subprocess.Popen(
                    [
                        str(verifier_client),
                        "run",
                        "--connect-http",
                        f"127.0.0.1:{unused_port}",
                        str(replay_path),
                        "--thread-limit",
                        "1",
                        "--verbose",
                        "diag",
                    ],
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
            wait_for_log_text(log_path, "Client initialization complete.", process)
            time.sleep(CLIENT_POST_READY_DELAY_SECONDS)
            process.send_signal(signal.SIGINT)
            exit_duration = wait_for_exit(process, log_path)
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()

        if process.returncode != 0:
            fail(f"verifier-client exited with {process.returncode}", log_path)
        print(f"OK: client exited promptly in {exit_duration:.3f}s")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("server", "client"), required=True)
    parser.add_argument("--verifier-server")
    parser.add_argument("--verifier-client")
    args = parser.parse_args()

    if args.mode == "server":
        if args.verifier_server is None:
            fail("--verifier-server is required in server mode")
        verifier_server = Path(args.verifier_server)
        run_server_check(verifier_server)
    else:
        if args.verifier_client is None:
            fail("--verifier-client is required in client mode")
        verifier_client = Path(args.verifier_client)
        run_client_check(verifier_client)
    return 0


if __name__ == "__main__":
    sys.exit(main())
