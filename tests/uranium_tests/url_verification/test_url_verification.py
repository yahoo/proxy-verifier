'''
Verify correct URL verification behavior.
'''
# @file
#
# Copyright 2021-2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

#
# Test 1: Verify field verification in a YAML replay file.
#
case = suite.case("Verify URL verification works for a simple HTTP transaction")
client = case.add_client("client1", "url_verification.yaml")
server = case.add_server("server1", "url_verification.yaml")
proxy = case.add_proxy("proxy1", listen_port=client.http_port, server_port=server.http_port)

# Preserve the prior test's effective final stream assertion.
server.stdout.contains(
    'Equals Violation: Absent. Key: "5", URI Part: "fragment", Correct Value: "F"',
    'Validation should be unhappy that the fragment was missing.')

server.expect_return_codes(1)


def test_uranium_suite(uranium):
    uranium.run(suite)
