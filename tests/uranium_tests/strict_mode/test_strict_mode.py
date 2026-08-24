'''
Verify strict mode functionality.
'''
# @file
#
# Copyright 2021-2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

#
# Test 1: Verify there are no warnings when the fields match.
#
case = suite.case("Verify strict mode is silent when the fields match.")
client = case.add_client("client1", "replay_files/fields_match.json", other_args="--strict")
server = case.add_server("server1", "replay_files/fields_match.json", other_args="--strict")
proxy = case.add_proxy("proxy1", listen_port=client.http_port, server_port=server.http_port)

proxy.stdout.matches_gold("gold/fields_match_proxy.gold")

client.stdout.excludes("Violation:",
                       "There should be no verification errors because there are none added.")

server.stdout.excludes("Violation:",
                       "There should be no verification errors because there are none added.")

#
# Test 2: Verify there are warnings when the fields don't match.
#
case = suite.case("Verify strict mode warns when the fields don't match")
client = case.add_client("client2", "replay_files/fields_differ.json", other_args="--strict")
server = case.add_server("server2", "replay_files/fields_differ.json", other_args="--strict")
proxy = case.add_proxy("proxy2", listen_port=client.http_port, server_port=server.http_port)

proxy.stdout.matches_gold("gold/fields_differ_proxy.gold")

client.stdout.contains(
    'Violation: Absent. Key: "cb9b4e94-5d42-43d4-8545-320033298ba2-226381119", Field Name: "x-thisresponseheaderwontexist", Correct Value: "ThereforeTheClientShouldWarn',
    "There should be a warning about the missing response header")

server.stdout.contains(
    'Violation: Absent. Key: "cb9b4e94-5d42-43d4-8545-320033298ba2-226381119", Field Name: "x-thisrequestheaderwontexist", Correct Value: "ThereforeTheServerShouldWarn',
    "There should be a warning about the missing proxy request header.")

client.expect_return_codes(1)
server.expect_return_codes(1)


def test_uranium_suite(uranium):
    uranium.run(suite)
