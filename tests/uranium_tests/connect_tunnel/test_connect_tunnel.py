'''
Verify CONNECT establishes a blind tunnel for a follow-up HTTP/1 transaction.
'''
# @file
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

import re

case = suite.case("Verify CONNECT allows a follow-up HTTP/1 transaction to be tunneled")
client = case.add_client("client", "replay_files/client", configure_https=False,
                         configure_http3=False)
server = case.add_server("server", "replay_files/server", configure_https=False,
                         configure_http3=False)
proxy = case.add_proxy("proxy", listen_port=client.http_port, server_port=server.http_port)

client.stdout.contains("CONNECT verifier.example:443 HTTP/1.1",
                       "The client should send a CONNECT request to establish the tunnel.")

client.stdout.contains(
    "GET /through/tunnel HTTP/1.1",
    "The client should send the follow-up transaction through the established tunnel.")

client.stdout.contains(
    "Received an HTTP/1 200 response for key connect-tunnel.*"
    "Received an HTTP/1 200 response for key tunneled-request",
    "The client should handle the CONNECT response before the tunneled response.",
    reflags=re.MULTILINE | re.DOTALL)

client.stdout.contains(
    "tunnel-body",
    "The client should receive the verifier-server response body through the tunnel.")

client.stdout.excludes("Violation:", "There should be no verification errors.")

client.stdout.excludes("Failed HTTP/1 transaction",
                       "Both client transactions should complete successfully.")

proxy.stdout.contains(
    "Received CONNECT request for key connect-tunnel: target verifier.example:443",
    "The test proxy should recognize the CONNECT request.")

proxy.stdout.contains("Established CONNECT tunnel for key connect-tunnel to 127.0.0.1:",
                      "The test proxy should establish a tunnel to verifier-server.")

proxy.stdout.contains(
    "CONNECT tunnel for key connect-tunnel closed after relaying [1-9][0-9]* bytes "
    "client->server and [1-9][0-9]* bytes server->client.",
    "The test proxy should blindly relay data in both directions through the tunnel.",
    reflags=re.MULTILINE)

server.stdout.contains("Ready with 1 transaction.",
                       "Only the tunneled transaction should reach verifier-server.")

server.stdout.contains("GET /through/tunnel HTTP/1.1",
                       "Verifier-server should receive the tunneled request.")

server.stdout.contains("Request with key tunneled-request passed validation.",
                       "Verifier-server should validate the tunneled request.")

server.stdout.contains("Sent the following HTTP/1 response headers for key tunneled-request",
                       "Verifier-server should send the tunneled response back to the client.")

server.stdout.excludes("Violation:", "There should be no verification errors on verifier-server.")


def test_uranium_suite(uranium):
    uranium.run(suite)
