'''
Verify basic body reading functionality.
'''
# @file
#
# Copyright 2021-2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

case = suite.case("Verify bodies can be read correctly.")
client = case.add_client("client1", "body.yaml")
server = case.add_server("server1", "body.yaml")
proxy = case.add_proxy("proxy1", listen_port=client.https_port, server_port=server.https_port,
                       use_ssl=True)

proxy.stdout.matches_gold("gold/body_proxy.gold")
client.stdout.matches_gold("gold/body_client.gold")
server.stdout.matches_gold("gold/body_server.gold")

client.stdout.excludes("Violation:",
                       "There should be no verification errors because there are none added.")

server.stdout.excludes("Violation:",
                       "There should be no verification errors because there are none added.")


def test_uranium_suite(uranium):
    uranium.run(suite)
