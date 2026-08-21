'''
Verify correct handling of malformed replay files.
'''
# @file
#
# Copyright 2021-2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

#
# Test 1: Verify correct handling of empty fields.
#
case = suite.case("Verify correct handling of empty header fields")
client = case.add_client("client1", "replay_files/empty_field.yaml")
server = case.add_server("server1", "replay_files/empty_field.yaml")
proxy = case.add_proxy("proxy1", listen_port=client.http_port, server_port=server.http_port)

client.expect_return_codes(1)
server.expect_return_codes(1)

# Due to the parsing failure, the server will not listen on the port.
# Thus the standard ready criteria will not work.
server.ready = False

client.stdout.contains("Field or rule at line .* is not a sequence as required",
                       "Verify that we inform the user of the malformed field.")
server.stdout.contains("Field or rule at line .* is not a sequence as required",
                       "Verify that we inform the user of the malformed field.")


def test_uranium_suite(uranium):
    uranium.run(suite)
