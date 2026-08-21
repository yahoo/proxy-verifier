'''
Verify correct response status(status code and reason) verification behavior.
'''
# @file
#
# Copyright 2023-2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

#
# Test 1: Verify status verification in a YAML replay file.
#
case = suite.case("Verify status verification works for simple HTTP transactions")
client = case.add_client("client1", "replay_files/status_verification.yaml")
server = case.add_server("server1", "replay_files/status_verification.yaml")
proxy = case.add_proxy("proxy1", listen_port=client.http_port, server_port=server.http_port)

# Verify status validation logs.
client.stdout.excludes(
    'Violation.*key: 1',
    'Transaction 1 should not have any violation since the status code matches the expected.')
client.stdout.contains(
    'Status Violation:.*key: 2',
    'Transaction 2 should have status violation as the status code does not match the expected.')
client.stdout.excludes(
    'Violation.*key: 3',
    'Transaction 3 should not have violation since the reason string matches the expected.')
client.stdout.contains(
    'Reason String Violation:.*key: 4',
    'Transaction 4 should have violation as the reason string does not match the expected.')
client.stdout.excludes(
    'Violation.*key: 5',
    'Transaction 5 should not have a violation for the tolerated 200/304 cache crossover.')
client.expect_return_codes(1)


def test_uranium_suite(uranium):
    uranium.run(suite)
