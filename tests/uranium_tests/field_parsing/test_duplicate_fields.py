'''
Verify correct handling of duplicate fields in a message.
'''
# @file
#
# Copyright 2020-2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

#
# Test 1: Verify correct behavior when there are duplicate HTTP fields.
#
case = suite.case("Verify correct handling of duplicate fields in a message.")
client = case.add_client("client1", "replay_files/duplicate_fields.yaml")
server = case.add_server("server1", "replay_files/duplicate_fields.yaml")
proxy = case.add_proxy("proxy1", listen_port=client.http_port, server_port=server.http_port)

proxy.stdout.matches_gold("gold/duplicate_fields_proxy.gold")
client.stdout.matches_gold("gold/duplicate_fields_client.gold")
server.stdout.matches_gold("gold/duplicate_fields_server.gold")


def test_uranium_suite(uranium):
    uranium.run(suite)
