'''
Verify basic HTTP/1.x functionality.
'''
# @file
#
# Copyright 2021-2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

#
# Test 1: Verify correct behavior of a single HTTP transaction.
#
case = suite.case("Verify HTTP/1 processing of a single HTTP transaction")

# Add configure_https=False to verify ATS client and server work when the https
# optional arguments are not provided.
client = case.add_client("client1", "replay_files/single_transaction.yaml", configure_https=False)
server = case.add_server("server1", "replay_files/single_transaction.yaml", configure_https=False)
proxy = case.add_proxy("proxy1", listen_port=client.http_port, server_port=server.http_port)

proxy.stdout.matches_gold("gold/single_transaction_proxy.gold")
client.stdout.matches_gold("gold/single_transaction_client.gold")
server.stdout.matches_gold("gold/single_transaction_server.gold")

client.stdout.excludes("Violation:",
                       "There should be no verification errors because there are none added.")

server.stdout.excludes("Violation:",
                       "There should be no verification errors because there are none added.")

#
# Test 2: Verify correct behavior of multiple HTTP sessions.
#
case = suite.case("Verify HTTP/1 processing of multiple HTTP transactions")
client = case.add_client("client2", "replay_files/multiple_transactions")
server = case.add_server("server2", "replay_files/multiple_transactions")
proxy = case.add_proxy("proxy2", listen_port=client.http_port, server_port=server.http_port)

client.stdout.contains("7 transactions in 5 sessions", "Verify that 7 transactions were parsed.")

client.stdout.contains("Loading 3 replay files.", "Verify that 3 replay files were parsesd.")

client.stdout.contains("204 No Content", "Verify the No Content reason string.")

client.stdout.contains("POST /some/request HTTP/1.0", "Verify that we sent the HTTP/1.0 version.")

client.stdout.excludes("Violation:",
                       "There should be no verification errors because there are none added.")

server.stdout.contains("Ready with 7 transactions.", "Verify that 7 transactions were parsed.")

server.stdout.contains("Loading 3 replay files", "Verify that 3 replay files were parsed.")

server.stdout.excludes("Violation:",
                       "There should be no verification errors because there are none added.")


def test_uranium_suite(uranium):
    uranium.run(suite)
