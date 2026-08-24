'''
GOAWAY frame tests.
'''
# @file
#
# Copyright 2024-2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

case = suite.case("GOAWAY frame tests.")
client = case.add_client("client", "http2_close_on_goaway.yaml")
server = case.add_server("server", "http2_close_on_goaway.yaml")
proxy = case.add_proxy("proxy", listen_port=client.https_port, server_port=server.https_port,
                       use_ssl=True, close_on_goaway=True, use_http2_to_2=True)

client.stdout.contains("uuid: 1", "uuid: 1")
client.stdout.contains("uuid: 3", "uuid: 3")
client.stdout.contains("uuid: 4", "uuid: 4")
client.stdout.contains("Failed to submit DATA frame for key 4 on stream 3: -510",
                       "uuid: 4 should fail")

client.stdout.excludes("uuid: 2", "uuid: 2")

server.stdout.contains("uuid: 1", "uuid: 1")
server.stdout.contains("uuid: 3", "uuid: 3")

server.stdout.excludes("uuid: 2", "uuid: 2")
server.stdout.excludes("uuid: 4", "uuid: 4")


def test_uranium_suite(uranium):
    uranium.run(suite)
