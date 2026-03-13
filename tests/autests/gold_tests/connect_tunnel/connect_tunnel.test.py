'''
Verify CONNECT establishes a blind tunnel for a follow-up HTTP/1 transaction.
'''
# @file
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

import re

Test.Summary = '''
Verify CONNECT establishes a blind tunnel for a follow-up HTTP/1 transaction.
'''

r = Test.AddTestRun("Verify CONNECT allows a follow-up HTTP/1 transaction to be tunneled")
client = r.AddClientProcess("client", "replay_files/client", configure_https=False,
                            configure_http3=False)
server = r.AddServerProcess("server", "replay_files/server", configure_https=False,
                            configure_http3=False)
proxy = r.AddProxyProcess("proxy", listen_port=client.Variables.http_port,
                          server_port=server.Variables.http_port)

client.Streams.stdout += Testers.ContainsExpression(
    "CONNECT verifier.example:443 HTTP/1.1",
    "The client should send a CONNECT request to establish the tunnel.")

client.Streams.stdout += Testers.ContainsExpression(
    "GET /through/tunnel HTTP/1.1",
    "The client should send the follow-up transaction through the established tunnel.")

client.Streams.stdout += Testers.ContainsExpression(
    "Received an HTTP/1 200 response for key connect-tunnel.*"
    "Received an HTTP/1 200 response for key tunneled-request",
    "The client should handle the CONNECT response before the tunneled response.",
    reflags=re.MULTILINE | re.DOTALL)

client.Streams.stdout += Testers.ContainsExpression(
    "tunnel-body",
    "The client should receive the verifier-server response body through the tunnel.")

client.Streams.stdout += Testers.ExcludesExpression(
    "Violation:", "There should be no verification errors.")

client.Streams.stdout += Testers.ExcludesExpression(
    "Failed HTTP/1 transaction", "Both client transactions should complete successfully.")

proxy.Streams.stdout += Testers.ContainsExpression(
    "Received CONNECT request for key connect-tunnel: target verifier.example:443",
    "The test proxy should recognize the CONNECT request.")

proxy.Streams.stdout += Testers.ContainsExpression(
    "Established CONNECT tunnel for key connect-tunnel to 127.0.0.1:",
    "The test proxy should establish a tunnel to verifier-server.")

proxy.Streams.stdout += Testers.ContainsExpression(
    "CONNECT tunnel for key connect-tunnel closed after relaying [1-9][0-9]* bytes "
    "client->server and [1-9][0-9]* bytes server->client.",
    "The test proxy should blindly relay data in both directions through the tunnel.",
    reflags=re.MULTILINE)

server.Streams.stdout += Testers.ContainsExpression(
    "Ready with 1 transaction.",
    "Only the tunneled transaction should reach verifier-server.")

server.Streams.stdout += Testers.ContainsExpression(
    "GET /through/tunnel HTTP/1.1",
    "Verifier-server should receive the tunneled request.")

server.Streams.stdout += Testers.ContainsExpression(
    "Request with key tunneled-request passed validation.",
    "Verifier-server should validate the tunneled request.")

server.Streams.stdout += Testers.ContainsExpression(
    "Sent the following HTTP/1 response headers for key tunneled-request",
    "Verifier-server should send the tunneled response back to the client.")

server.Streams.stdout += Testers.ExcludesExpression(
    "Violation:", "There should be no verification errors on verifier-server.")
