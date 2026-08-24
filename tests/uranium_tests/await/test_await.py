'''
Verify correct handling of the transaction await directive.
'''
# @file
#
# Copyright 2022-2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

import re

#
# Test 1: Run a few transactions with the await directive.
#
case = suite.case("Verify correct handling of the await directive")
client = case.add_client("client_await", "await.replay.yaml")
server = case.add_server("server_await", "await.replay.yaml")
proxy = case.add_proxy("proxy_await", listen_port=client.https_port, server_port=server.https_port,
                       use_ssl=True, use_http2_to_2=True)

server.stdout.contains("Ready with 3 transactions.",
                       "The server should have parsed 3 transactions.")

# Make sure that the entire first-request finishes before second-request
# starts. And, further, that the entire second-request finishes before
# third-request starts.
client.stdout.contains(
    "Submitted the following HTTP/2 request headers for key first-request.*"
    "Received an HTTP/2 body of 3432 bytes for key first-request.*"
    "Submitted the following HTTP/2 request headers for key second-request.*"
    "Received an HTTP/2 body of 3432 bytes for key second-request.*"
    "Submitted the following HTTP/2 request headers for key third-request.*"
    "Received an HTTP/2 body of 3432 bytes for key third-request.*",
    "second-request should start only after first-request finishes.",
    reflags=re.MULTILINE | re.DOTALL)


def test_uranium_suite(uranium):
    uranium.run(suite)
