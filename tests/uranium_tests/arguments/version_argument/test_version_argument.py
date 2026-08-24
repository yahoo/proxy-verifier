'''
Verify the version argument of Proxy Verifier.
'''
# @file
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

import re


def get_project_version():
    """
    Parse the top-level CMake project declaration for the specified version.
    """
    cmake_file = suite.module_path.parents[4] / "CMakeLists.txt"
    project_pattern = re.compile(
        r"project\s*\(\s*ProxyVerifier\b.*?\bVERSION\s+([0-9.]+)",
        re.IGNORECASE | re.DOTALL,
    )

    contents = cmake_file.read_text(encoding='utf-8')
    match = project_pattern.search(contents)
    if match:
        return match.group(1)

    raise ValueError(f"Could not find the ProxyVerifier version in {cmake_file}")


project_version = get_project_version()

#
# Test 1: Verify that the client detects when a key is not present in a
#
case = suite.case('Verify that the client detects a non-existent key')
client = case.add_client("client1", replay_dir=None, other_args="--version")

client.stdout.contains(f'Version {project_version} of Proxy Verifier',
                       "The --version output should print the expected string")

#
# Test 2: Verify that the server detects when a key is not present in a
# transaction.
#
case = suite.case('Verify that the server detects a non-existent key')
server = case.add_server("server2", replay_dir=None, other_args="--version")

server.stdout.contains(f'Version {project_version} of Proxy Verifier',
                       "The --version output should print the expected string")


def test_uranium_suite(uranium):
    uranium.run(suite)
