'''
Verify the version argument of Proxy Verifier.
'''
# @file
#
# Copyright 2021, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

import os
from os.path import dirname


Test.Summary = '''
Verify the version argument of Proxy Verifier.
'''


def get_part_version():
    """
    Parse the Proxy Verifier part file for the specified version.
    """
    repo_dir = dirname(dirname(dirname(Test.TestRoot)))
    part_file = os.path.join(repo_dir, "local", "parts", "proxy-verifier.part")
    for line in open(part_file, 'r', encoding='utf-8'):
        if 'PartVersion' not in line:
            continue
        version_start = line.find('"') + 1
        if version_start == 0:
            continue
        version_end = line.rfind('"')
        if version_end == -1:
            continue
        return line[version_start:version_end]

    raise ValueError(f"Could not find the PartVersion in {part_file}")


# Parse the proxy-verifier.part file for the expected version string.
part_version = get_part_version()

#
# Test 1: Verify that the client detects when a key is not present in a
#
r = Test.AddTestRun('Verify that the client detects a non-existent key')
client = r.AddClientProcess("client1", replay_dir=None, other_args="--version")

client.Streams.stdout += Testers.ContainsExpression(
    f'Version {part_version} of Proxy Verifier',
    "The --version output should print the expected string")

#
# Test 2: Verify that the server detects when a key is not present in a
# transaction.
#
r = Test.AddTestRun('Verify that the server detects a non-existent key')
server = r.AddDefaultServerProcess("server2", replay_dir=None, other_args="--version")

server.Streams.stdout += Testers.ContainsExpression(
    f'Version {part_version} of Proxy Verifier',
    "The --version output should print the expected string")
