'''
Verify the version argument of Proxy Verifier.
'''
# @file
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

import os
import re
from os.path import dirname

Test.Summary = '''
Verify the version argument of Proxy Verifier.
'''


def get_project_version():
    """
    Parse the top-level CMake project declaration for the specified version.
    """
    repo_dir = dirname(dirname(dirname(Test.TestRoot)))
    cmake_file = os.path.join(repo_dir, "CMakeLists.txt")
    project_pattern = re.compile(
        r"project\s*\(\s*ProxyVerifier\b.*?\bVERSION\s+([0-9.]+)",
        re.IGNORECASE | re.DOTALL,
    )

    with open(cmake_file, 'r', encoding='utf-8') as f:
        contents = f.read()
    match = project_pattern.search(contents)
    if match:
        return match.group(1)

    raise ValueError(f"Could not find the ProxyVerifier version in {cmake_file}")


project_version = get_project_version()

#
# Test 1: Verify that the client detects when a key is not present in a
#
r = Test.AddTestRun('Verify that the client detects a non-existent key')
client = r.AddClientProcess("client1", replay_dir=None, other_args="--version")

client.Streams.stdout += Testers.ContainsExpression(
    f'Version {project_version} of Proxy Verifier',
    "The --version output should print the expected string")

#
# Test 2: Verify that the server detects when a key is not present in a
# transaction.
#
r = Test.AddTestRun('Verify that the server detects a non-existent key')
server = r.AddDefaultServerProcess("server2", replay_dir=None, other_args="--version")

server.Streams.stdout += Testers.ContainsExpression(
    f'Version {project_version} of Proxy Verifier',
    "The --version output should print the expected string")
