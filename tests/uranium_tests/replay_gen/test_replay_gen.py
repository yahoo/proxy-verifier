'''
Verify replay-gen.py can generate parsable replay files.
'''
# @file
#
# Copyright 2021-2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

#
# Test 1: Generate replay files via replay_gen and verify they can be replayed.
#
case = suite.case("Generate replay files via replay-gen.py")
replay_gen = case.add_replay_generator("replay_gen1", num_transactions=20)

case = suite.case("Make sure we can use the generated replay files")
client = case.add_client("client1", replay_gen.artifact("replay_dir"))
server = case.add_server("server1", replay_gen.artifact("replay_dir"))
proxy = case.add_proxy("proxy1", listen_port=client.http_port, server_port=server.http_port)

# The Python test proxy may close the connection part way through the
# transactions. I've verified that if the client talks directly to the server,
# there are no problems.
client.expect_return_codes(0, 1)

client.stdout.contains(
    "Parsed 20 transactions",
    "Verify that the verifier client was able to parse the expected 20 transactions.")

server.stdout.contains(
    "Ready with 20 transactions",
    "Verify that the verifier server was able to parse the expected 20 transactions.")


def test_uranium_suite(uranium):
    uranium.run(suite)
