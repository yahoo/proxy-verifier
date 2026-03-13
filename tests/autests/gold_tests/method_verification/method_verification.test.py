'''
Verify request method verification behavior across protocol stacks.
'''
# @file
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

Test.Summary = '''
Verify request method verification behavior across protocol stacks.
'''

HTTP3_ARGS = "--poll-timeout 10000"

#
# Test 1: Verify HTTP/1 method verification uses the top-level proxy-request
# method node.
#
r = Test.AddTestRun("Verify HTTP/1 request method verification")
client = r.AddClientProcess("client1", "replay_files/http1_method_verification.yaml",
                            configure_https=False)
server = r.AddServerProcess("server1", "replay_files/http1_method_verification.yaml",
                            configure_https=False)
r.AddProxyProcess("proxy1", listen_port=client.Variables.http_port,
                  server_port=server.Variables.http_port)

server.Streams.stdout += Testers.ContainsExpression(
    'HTTP/1 Method Success: Key: "1", Method: "GET"',
    "The HTTP/1 request method should verify successfully for the matching transaction.")
server.Streams.stdout += Testers.ExcludesExpression(
    'HTTP/1 Method Violation: .*Key: "1"',
    "The matching HTTP/1 transaction should not report a method verification violation.")
server.Streams.stdout += Testers.ContainsExpression(
    'HTTP/1 Method Violation: Different. Key: "2", Expected Method: "POST", Received Method: "GET"',
    "The HTTP/1 request method should fail when the proxy sends the wrong method.")

client.ReturnCode = 0
server.ReturnCode = 1

#
# Test 2: Verify HTTP/2 request method verification continues to work via the
# :method pseudo header field.
#
r = Test.AddTestRun("Verify HTTP/2 request method verification")
client = r.AddClientProcess("client2", "replay_files/http2_method_verification.yaml")
server = r.AddServerProcess("server2", "replay_files/http2_method_verification.yaml")
r.AddProxyProcess("proxy2", listen_port=client.Variables.https_port,
                  server_port=server.Variables.https_port, use_ssl=True, use_http2_to_2=True)

server.Streams.stdout += Testers.ContainsExpression(
    'Equals Success: Key: "1", Field Name: ":method", Value: "GET"',
    "The HTTP/2 :method pseudo header should verify successfully for the matching transaction.")
server.Streams.stdout += Testers.ExcludesExpression(
    'Equals Violation: .*Key: "1".*Field Name: ":method"',
    "The matching HTTP/2 transaction should not report a :method verification violation.")
server.Streams.stdout += Testers.ContainsExpression(
    'Equals Violation: Different. Key: "2", Field Name: ":method", Correct Value: "POST", Actual Value: "GET"',
    "The HTTP/2 :method pseudo header should fail when the proxy sends the wrong method.")

client.ReturnCode = 0
server.ReturnCode = 1

#
# Test 3: Verify an HTTP/3 client path can exercise the HTTP/1 request method
# verification on the downstream side.
#
r = Test.AddTestRun("Verify HTTP/3 request method verification")
client = r.AddClientProcess("client3", "replay_files/http3_method_verification.yaml",
                            other_args=HTTP3_ARGS)
server = r.AddServerProcess("server3", "replay_files/http3_method_verification.yaml",
                            other_args=HTTP3_ARGS)
r.AddProxyProcess("proxy3", listen_port=client.Variables.http3_port,
                  server_port=server.Variables.http_port, use_ssl=True, use_http3_to_1=True)

server.Streams.stdout += Testers.ContainsExpression(
    'HTTP/1 Method Success: Key: "1", Method: "GET"',
    "The HTTP/3-originated request should pass downstream HTTP/1 method verification.")
server.Streams.stdout += Testers.ExcludesExpression(
    'HTTP/1 Method Violation: .*Key: "1"',
    "The matching HTTP/3 transaction should not report a downstream method violation.")
server.Streams.stdout += Testers.ContainsExpression(
    'HTTP/1 Method Violation: Different. Key: "2", Expected Method: "POST", Received Method: "GET"',
    "The HTTP/3-originated request should fail downstream method verification on mismatch.")

client.ReturnCode = 0
server.ReturnCode = 1
