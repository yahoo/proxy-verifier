'''
Verify basic HTTPS functionality.
'''
# @file
#
# Copyright 2021-2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

case = suite.case("Verify processing of a simple HTTPS transaction")

# Add configure_http=False to verify ATS client and server work when the http
# optional arguments are not provided.
client = case.add_client("client1", "replay_files/single_transaction.yaml", configure_http=False)
server = case.add_server("server1", "replay_files/single_transaction.yaml", configure_http=False)
proxy = case.add_proxy("proxy1", listen_port=client.https_port, server_port=server.https_port,
                       use_ssl=True)

proxy.stdout.matches_gold("gold/single_transaction_proxy.gold")
client.stdout.matches_gold("gold/single_transaction_client.gold")
server.stdout.matches_gold("gold/single_transaction_server.gold")

client.stdout.excludes("Violation:",
                       "There should be no verification errors because there are none added.")

server.stdout.excludes("Violation:",
                       "There should be no verification errors because there are none added.")


def test_uranium_suite(uranium):
    uranium.run(suite)
