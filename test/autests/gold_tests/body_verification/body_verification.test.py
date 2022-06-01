'''
Verify basic body verification functionality.
'''
# @file
#
# Copyright 2022, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

Test.Summary = '''
Verify basic body verification functionality.
'''

#
# Test 1: Verify bodies can be verified correctly for HTTP/1.1.
#
r = Test.AddTestRun("Verify bodies can be verified correctly for HTTP/1.1.")
client = r.AddClientProcess("client1", "http.yaml")
server = r.AddServerProcess("server1", "http.yaml")
proxy = r.AddProxyProcess("proxy1", listen_port=client.Variables.https_port,
                          server_port=server.Variables.https_port, use_ssl=True)

client.Streams.stdout += Testers.ContainsExpression(
    'Equals Success: Key: "1", Content Data: "body"',
    "Verification should be happy with the body.")
client.Streams.stdout += Testers.ContainsExpression(
    'Contains Success: Key: "2", Content Data: "body"',
    "Verification should be happy with the body.")
client.Streams.stdout += Testers.ContainsExpression(
    'Equals Violation: Different. Key: "3", Content Data: "body"',
    "Verification should not be happy with the body.")

server.Streams.stdout += Testers.ContainsExpression(
    'Equals Success: Key: "1", Content Data: "body"',
    "Verification should be happy with the body.")
server.Streams.stdout += Testers.ContainsExpression(
    'Contains Success: Key: "2", Content Data: "body"',
    "Verification should be happy with the body.")
server.Streams.stdout += Testers.ContainsExpression(
    'Equals Violation: Different. Key: "3", Content Data: "body"',
    "Verification should not be happy with the body.")

#
# Test 2: Verify bodies can be verified correctly for HTTP/2.
#
r = Test.AddTestRun("Verify bodies can be verified correctly for HTTP/2.")
client = r.AddClientProcess("client2", "http2.yaml")
server = r.AddServerProcess("server2", "http2.yaml")
proxy = r.AddProxyProcess("proxy2", listen_port=client.Variables.https_port,
                          server_port=server.Variables.https_port,
                          use_ssl=True, use_http2_to_2=True)

client.Streams.stdout += Testers.ContainsExpression(
    'Equals Success: Key: "1", Content Data: "body"',
    "Verification should be happy with the body.")
client.Streams.stdout += Testers.ContainsExpression(
    'No Case Prefix Success: Key: "2", Content Data: "body"',
    "Verification should be happy with the body.")

server.Streams.stdout += Testers.ContainsExpression(
    'Equals Success: Key: "1", Content Data: "body"',
    "Verification should be happy with the body.")
server.Streams.stdout += Testers.ContainsExpression(
    'No Case Suffix Success: Key: "2", Content Data: "body"',
    "Verification should be happy with the body.")

#
# Test 3: Verify bodies can be verified correctly for HTTP/3.
#
r = Test.AddTestRun("Verify bodies can be verified correctly for HTTP/3.")
client = r.AddClientProcess("client3", "http3.yaml")
server = r.AddServerProcess("server3", "http3.yaml")
proxy = r.AddProxyProcess("proxy3", listen_port=client.Variables.http3_port,
                          server_port=server.Variables.http_port,
                          use_ssl=True, use_http3_to_1=True)

client.Streams.stdout += Testers.ContainsExpression(
    'Not Contains Success: Not Found. Key: "1", Content Data: "body"',
    "Verification should be happy with the body.")
client.Streams.stdout += Testers.ContainsExpression(
    'Not No Case Contains Violation: Key: "2", Content Data: "body"',
    "Verification should not be happy with the body.")

server.Streams.stdout += Testers.ContainsExpression(
    'Not Equals Success: Different. Key: "1", Content Data: "body"',
    "Verification should be happy with the body.")
server.Streams.stdout += Testers.ContainsExpression(
    'Not No Case Equals Violation: Key: "2", Content Data: "body"',
    "Verification should not be happy with the body.")
