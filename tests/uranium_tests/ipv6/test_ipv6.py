'''
Verify basic IPv6 support.
'''
# @file
#
# Copyright 2021-2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

#
# Test 1: Verify transactions can be exchanged over IPv6.
#
case = suite.case("Verify the correct handling of an HTTP/1, IPv6 transaction")
server = case.add_server("server1", "replay_files/single_transaction.yaml", use_ipv6=True)
client = case.add_client("client1", "replay_files/single_transaction.yaml", use_ipv6=True,
                         http_ports=[server.http_port], other_args="--no-proxy")

# Note that this test involves no proxy and, instead, the client talks directly
# to the server.

client.stdout.matches_gold("gold/single_transaction_client.gold")
server.stdout.matches_gold("gold/single_transaction_server.gold")

client.stdout.excludes("Violation:",
                       "There should be no verification errors because there are none added.")
server.stdout.excludes("Violation:",
                       "There should be no verification errors because there are none added.")


def test_uranium_suite(uranium):
    uranium.run(suite)
