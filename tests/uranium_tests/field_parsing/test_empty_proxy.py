'''
Verify correct handling of empty proxy nodes.
'''
# @file
#
# Copyright 2020-2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

#
# Test 1: Verify correct handling of empty proxy-request and response nodes.
#
case = suite.case("Verify correct handling of empty proxy nodes")
client = case.add_client("client1", "replay_files/empty_proxy.yaml")
server = case.add_server("server1", "replay_files/empty_proxy.yaml")
proxy = case.add_proxy("proxy1", listen_port=client.http_port, server_port=server.http_port)

proxy.stdout.matches_gold("gold/empty_proxy_proxy.gold")
client.stdout.matches_gold("gold/empty_proxy_client.gold")
server.stdout.matches_gold("gold/empty_proxy_server.gold")


def test_uranium_suite(uranium):
    uranium.run(suite)
