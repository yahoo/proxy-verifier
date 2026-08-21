'''
Verify basic --no-proxy functionality.
'''
# @file
#
# Copyright 2022-2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

case = suite.case("Verify no-proxy mode works for a simple HTTP transaction")
server = case.add_server("server", "replay/single_transaction.json")
client = case.add_client("client", "replay/single_transaction.json", http_ports=[server.http_port],
                         https_ports=[server.https_port], other_args="--no-proxy")

client.stdout.contains('Received an HTTP/1 200 response for .*',
                       "Verify that the response came back from replay-server")

client.stdout.contains('x-testheader: from_server_response',
                       "Verify that the server response headers were used by the replay-server.")

client.stdout.excludes(
    'from_proxy_response',
    "Verify that the proxy response headers were not used by the replay-server.")

client.stdout.excludes("Violation:",
                       "There should be no verification errors because there are none added.")

server.stdout.contains("POST /proxy.do HTTP/1.1",
                       "Verify that the proxy request path was used by the replay-client.")

server.stdout.contains('client-ip: 10.10.10.1',
                       "Verify that the proxy request headers were used by the replay-client.")

server.stdout.excludes("Violation:",
                       "There should be no verification errors because there are none added.")

case = suite.case("Verify no-proxy mode works for a simple HTTP/2 transaction")
server = case.add_server("server-h2", "replay/h2.yaml")
client = case.add_client("client-h2", "replay/h2.yaml", http_ports=[server.http_port],
                         https_ports=[server.https_port], other_args="--no-proxy")

client.stdout.contains(
    "Received an HTTP/2 response for key 1 with stream id 1:",
    "The client should receive the zero-length HTTP/2 response from the replay server.")
client.stdout.contains(
    "Received an HTTP/2 response for key 3 with stream id 1:",
    "The client should receive the POST replay response on the second HTTP/2 session.")
client.stdout.contains(
    r"HTTP/2 replay metrics: requests-submitted=2, max-in-flight-streams=2, "
    r"send-phase-bytes-drained=[0-9]+, final-drain-duration=[0-9]+ms\.",
    "The client should complete the HTTP/2 no-proxy replay and emit replay metrics.")
client.stdout.excludes(
    "Violation:", "The client should not report verification failures in HTTP/2 no-proxy mode.")
client.stdout.excludes(
    "HTTP/2 final response drain made no forward progress",
    "The client should not hit the HTTP/2 stuck-session summary in HTTP/2 no-proxy mode.")

server.stdout.contains("Received an HTTP/2 request for key 1 with stream id 1:",
                       "The server should receive the first no-proxy HTTP/2 request.")
server.stdout.contains(":path: /some/path4",
                       "The server should receive the final no-proxy HTTP/2 request path.")
server.stdout.contains("Request with key 4 passed validation.",
                       "The server should validate the final HTTP/2 no-proxy request.")
server.stdout.excludes(
    "Violation:", "The server should not report verification failures in HTTP/2 no-proxy mode.")


def test_uranium_suite(uranium):
    uranium.run(suite)
