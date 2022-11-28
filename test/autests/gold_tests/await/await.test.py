'''
Verify correct handling of the transaction await directive.
'''
# @file
#
# Copyright 2022, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

import re

Test.Summary = __doc__

#
# Test 1: Run a few transactions with the await directive.
#
r = Test.AddTestRun("Verify correct handling of the await directive")
client = r.AddClientProcess("client_await", "await.replay.yaml")
server = r.AddServerProcess("server_await", "await.replay.yaml")
proxy = r.AddProxyProcess(
    "proxy_await",
    listen_port=client.Variables.https_port,
    server_port=server.Variables.https_port,
    use_ssl=True,
    use_http2_to_2=True)

server.Streams.stdout += Testers.ContainsExpression(
    "Ready with 3 transactions.",
    "The server should have parsed 3 transactions.")

# Make sure that the entire first-request finishes before second-request
# starts. And, further, that the entire second-request finishes before
# third-request starts.
client.Streams.stdout += Testers.ContainsExpression(
    "Sent the following HTTP/2 request headers for key first-request.*"
    "Received an HTTP/2 body of 3432 bytes for key first-request.*"
    "Sent the following HTTP/2 request headers for key second-request.*"
    "Received an HTTP/2 body of 3432 bytes for key second-request.*",
    "Sent the following HTTP/2 request headers for key third-request.*"
    "Received an HTTP/2 body of 3432 bytes for key third-request.*",
    "second-request should start only after first-request finishes.",
    reflags=re.MULTILINE | re.DOTALL)
