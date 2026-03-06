'''
Verify server-response on_connect behavior.
'''
# @file
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

Test.Summary = '''
Verify server-response on_connect behavior.
'''

r = Test.AddTestRun("Verify on_connect accept, refuse, and reset behavior")
client = r.AddClientProcess("client", "replay_files/on_connect.yaml", configure_https=False)
server = r.AddServerProcess("server", "replay_files/on_connect.yaml", configure_https=False)
proxy = r.AddProxyProcess("proxy", listen_port=client.Variables.http_port,
                          server_port=server.Variables.http_port)

client.Streams.stdout += Testers.ContainsExpression(
    "3 transactions in 3 sessions", "The client should have parsed all three transactions.")

client.Streams.stdout += Testers.ContainsExpression(
    "Received an HTTP/1 200 response for key 1", "The accept case should return a normal response.")

client.Streams.stdout += Testers.ContainsExpression(
    "Received an HTTP/1 502 response for key 2", "The refuse case should surface as a proxy 502.")

client.Streams.stdout += Testers.ContainsExpression(
    "Received an HTTP/1 502 response for key 3", "The reset case should surface as a proxy 502.")

client.Streams.stdout += Testers.ExcludesExpression("Violation:",
                                                    "There should be no verification errors.")

proxy.Streams.stdout += Testers.ContainsExpression(
    "Upstream connection for key 2 closed with TCP FIN before any response bytes were received.",
    "The proxy should observe an orderly upstream close for refuse.")

proxy.Streams.stdout += Testers.ContainsExpression(
    "Upstream connection for key 3 closed with TCP RST before any response bytes were received.",
    "The proxy should observe an abortive upstream close for reset.")

server.Streams.stdout += Testers.ContainsExpression(
    'Applying "refuse" on_connect action for key 2.', "The server should apply the refuse action.")

server.Streams.stdout += Testers.ContainsExpression('Applying "reset" on_connect action for key 3.',
                                                    "The server should apply the reset action.")

server.Streams.stdout += Testers.ContainsExpression(
    "Sent the following HTTP/1 response headers for key 1",
    "The accept case should still write a normal response.")

server.Streams.stdout += Testers.ExcludesExpression(
    "Sent the following HTTP/1 response headers for key 2",
    "The refuse case should not write response headers.")

server.Streams.stdout += Testers.ExcludesExpression(
    "Sent the following HTTP/1 response headers for key 3",
    "The reset case should not write response headers.")

server.Streams.stdout += Testers.ExcludesExpression("Violation:",
                                                    "There should be no verification errors.")

r = Test.AddTestRun("Verify on_connect accept, refuse, and reset behavior over HTTP/2")
client = r.AddClientProcess("client_h2", "replay_files/on_connect_http2.yaml")
server = r.AddServerProcess("server_h2", "replay_files/on_connect_http2.yaml")
proxy = r.AddProxyProcess("proxy_h2", listen_port=client.Variables.https_port,
                          server_port=server.Variables.https_port, use_ssl=True,
                          use_http2_to_1=True)

client.Streams.stdout += Testers.ContainsExpression(
    "3 transactions in 3 sessions", "The HTTP/2 client should parse all three transactions.")

client.Streams.stdout += Testers.ContainsExpression(
    "Received an HTTP/2 response for key 1 with stream id 1:",
    "The accept case should return a normal HTTP/2 response.")

client.Streams.stdout += Testers.ContainsExpression(
    "Received an HTTP/2 response for key 2 with stream id 1:",
    "The refuse case should surface as an HTTP/2 502 response.")

client.Streams.stdout += Testers.ContainsExpression(
    "Received an HTTP/2 response for key 3 with stream id 1:",
    "The reset case should surface as an HTTP/2 502 response.")

client.Streams.stdout += Testers.ContainsExpression(
    ":status: 502", "The HTTP/2 client should observe 502 responses for failure cases.")

client.Streams.stdout += Testers.ExcludesExpression("Violation:",
                                                    "There should be no verification errors.")

proxy.Streams.stdout += Testers.ContainsExpression(
    "Upstream connection for key 2 closed with TCP FIN before any response bytes were received.",
    "The HTTP/2 proxy should observe an orderly upstream close for refuse.")

proxy.Streams.stdout += Testers.ContainsExpression(
    "Upstream connection for key 3 closed with TCP RST before any response bytes were received.",
    "The HTTP/2 proxy should observe an abortive upstream close for reset.")

server.Streams.stdout += Testers.ContainsExpression(
    'Applying "refuse" on_connect action for key 2.', "The server should apply the refuse action.")

server.Streams.stdout += Testers.ContainsExpression('Applying "reset" on_connect action for key 3.',
                                                    "The server should apply the reset action.")

server.Streams.stdout += Testers.ContainsExpression(
    "Sent the following HTTP/1 response headers for key 1",
    "The accept case should still write a normal upstream HTTP/1 response.")

server.Streams.stdout += Testers.ExcludesExpression(
    "Sent the following HTTP/1 response headers for key 2",
    "The refuse case should not write response headers.")

server.Streams.stdout += Testers.ExcludesExpression(
    "Sent the following HTTP/1 response headers for key 3",
    "The reset case should not write response headers.")

server.Streams.stdout += Testers.ExcludesExpression("Violation:",
                                                    "There should be no verification errors.")
