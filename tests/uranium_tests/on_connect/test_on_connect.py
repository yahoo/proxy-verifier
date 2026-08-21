'''
Verify server-response on_connect behavior.
'''
# @file
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

case = suite.case("Verify on_connect accept, refuse, and reset behavior")
client = case.add_client("client", "replay_files/on_connect.yaml", configure_https=False)
server = case.add_server("server", "replay_files/on_connect.yaml", configure_https=False)
proxy = case.add_proxy("proxy", listen_port=client.http_port, server_port=server.http_port)

client.stdout.contains("3 transactions in 3 sessions",
                       "The client should have parsed all three transactions.")

client.stdout.contains("Received an HTTP/1 200 response for key 1",
                       "The accept case should return a normal response.")

client.stdout.contains("Received an HTTP/1 502 response for key 2",
                       "The refuse case should surface as a proxy 502.")

client.stdout.contains("Received an HTTP/1 502 response for key 3",
                       "The reset case should surface as a proxy 502.")

client.stdout.excludes("Violation:", "There should be no verification errors.")

proxy.stdout.contains(
    "Upstream connection for key 2 closed with TCP FIN before any response bytes were received.",
    "The proxy should observe an orderly upstream close for refuse.")

proxy.stdout.contains(
    "Upstream connection for key 3 closed with TCP RST before any response bytes were received.",
    "The proxy should observe an abortive upstream close for reset.")

server.stdout.contains('Applying "refuse" on_connect action for key 2.',
                       "The server should apply the refuse action.")

server.stdout.contains('Applying "reset" on_connect action for key 3.',
                       "The server should apply the reset action.")

server.stdout.contains("Sent the following HTTP/1 response headers for key 1",
                       "The accept case should still write a normal response.")

server.stdout.excludes("Sent the following HTTP/1 response headers for key 2",
                       "The refuse case should not write response headers.")

server.stdout.excludes("Sent the following HTTP/1 response headers for key 3",
                       "The reset case should not write response headers.")

server.stdout.excludes("Violation:", "There should be no verification errors.")

case = suite.case("Verify on_connect accept, refuse, and reset behavior over HTTP/2")
client = case.add_client("client_h2", "replay_files/on_connect_http2.yaml")
server = case.add_server("server_h2", "replay_files/on_connect_http2.yaml")
proxy = case.add_proxy("proxy_h2", listen_port=client.https_port, server_port=server.https_port,
                       use_ssl=True, use_http2_to_1=True)

client.stdout.contains("3 transactions in 3 sessions",
                       "The HTTP/2 client should parse all three transactions.")

client.stdout.contains("Received an HTTP/2 response for key 1 with stream id 1:",
                       "The accept case should return a normal HTTP/2 response.")

client.stdout.contains("Received an HTTP/2 response for key 2 with stream id 1:",
                       "The refuse case should surface as an HTTP/2 502 response.")

client.stdout.contains("Received an HTTP/2 response for key 3 with stream id 1:",
                       "The reset case should surface as an HTTP/2 502 response.")

client.stdout.contains(":status: 502",
                       "The HTTP/2 client should observe 502 responses for failure cases.")

client.stdout.excludes("Violation:", "There should be no verification errors.")

proxy.stdout.contains(
    "Upstream connection for key 2 closed with TCP FIN before any response bytes were received.",
    "The HTTP/2 proxy should observe an orderly upstream close for refuse.")

# On Rocky 8, the Python HTTP/2 test proxy uses the system Python/OpenSSL 1.1.1
# TLS stack. On that HTTPS path, our Python HTTP/2 test client may surface a
# server-side RST as a generic disconnect and report it as a FIN, so this
# assertion accepts either FIN or RST even though the verifier server still
# performs an abortive close which should result in a RST.
proxy.stdout.contains(
    "Upstream connection for key 3 closed with TCP (FIN|RST) before any response bytes were received.",
    "The HTTP/2 proxy should observe the upstream close for reset.")

server.stdout.contains('Applying "refuse" on_connect action for key 2.',
                       "The server should apply the refuse action.")

server.stdout.contains('Applying "reset" on_connect action for key 3.',
                       "The server should apply the reset action.")

server.stdout.contains("Sent the following HTTP/1 response headers for key 1",
                       "The accept case should still write a normal upstream HTTP/1 response.")

server.stdout.excludes("Sent the following HTTP/1 response headers for key 2",
                       "The refuse case should not write response headers.")

server.stdout.excludes("Sent the following HTTP/1 response headers for key 3",
                       "The reset case should not write response headers.")

server.stdout.excludes("Violation:", "There should be no verification errors.")


def test_uranium_suite(uranium):
    uranium.run(suite)
