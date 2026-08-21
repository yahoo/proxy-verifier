'''
Verify correct parsing of YAML replay files.
'''
# @file
#
# Copyright 2020-2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

#
# Test 1: Verify correct behavior with a YAML-specified replay file.
#
case = suite.case("Verify parsing of a YAML-specified replay file")
client = case.add_client("client1", "replay_files/yaml_specified.yaml")
server = case.add_server("server1", "replay_files/yaml_specified.yaml")
proxy = case.add_proxy("proxy1", listen_port=client.http_port, server_port=server.http_port)

proxy.stdout.matches_gold("gold/yaml_specified_proxy.gold")
client.stdout.matches_gold("gold/yaml_specified_client.gold")
server.stdout.matches_gold("gold/yaml_specified_server.gold")

# These expect verification errors.
client.expect_return_codes(1)
server.expect_return_codes(1)

#
# Test 2: Verify correct parsing of transaction-level fields.
#
case = suite.case("Verify parsing of transaction-level fields")
client = case.add_client("client2", "replay_files/transaction_fields.yaml")
server = case.add_server("server2", "replay_files/transaction_fields.yaml")
proxy = case.add_proxy("proxy2", listen_port=client.http_port, server_port=server.http_port)

proxy.stdout.matches_gold("gold/transaction_fields_proxy.gold")
client.stdout.matches_gold("gold/transaction_fields_client.gold")
server.stdout.matches_gold("gold/transaction_fields_server.gold")


def test_uranium_suite(uranium):
    uranium.run(suite)
