'''
Verify basic HTTP/2 functionality.
'''
# @file
#
# Copyright 2021, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

Test.Summary = '''
Verify basic HTTP/2 functionality.
'''

#
# Test 1: Verify correct behavior of a single client-side HTTP/2 transaction.
#
r = Test.AddTestRun("Verify HTTP/2 behavior on client-side only")
client = r.AddClientProcess("client1", "replay_files/http2_to_http1.yaml")
server = r.AddServerProcess("server1", "replay_files/http2_to_http1.yaml")
proxy = r.AddProxyProcess("proxy1", listen_port=client.Variables.https_port,
                          server_port=server.Variables.https_port,
                          use_ssl=True, use_http2_to_1=True)

proxy.Streams.stdout = "gold/http2_to_http1_proxy.gold"
client.Streams.stdout = "gold/http2_to_http1_client.gold"
server.Streams.stdout = "gold/http2_to_http1_server.gold"

client.Streams.stdout += Testers.ExcludesExpression(
    "Violation:",
    "There should be no verification errors because there are none added.")

server.Streams.stdout += Testers.ExcludesExpression(
    "Violation:",
    "There should be no verification errors because there are none added.")

#
# Test 2: Verify field verification: all success.
#
r = Test.AddTestRun("Verify HTTP/2 behavior on both the client and server sides")
client = r.AddClientProcess("client2", "replay_files/http2_to_http2.yaml")
server = r.AddServerProcess("server2", "replay_files/http2_to_http2.yaml")
proxy = r.AddProxyProcess("proxy2", listen_port=client.Variables.https_port,
                          server_port=server.Variables.https_port,
                          use_ssl=True, use_http2_to_2=True)

proxy.Streams.stdout = "gold/http2_to_http2_proxy.gold"
client.Streams.stdout = "gold/http2_to_http2_client.gold"
server.Streams.stdout = "gold/http2_to_http2_server.gold"

client.Streams.stdout += Testers.ExcludesExpression(
    "Violation:",
    "There should be no verification errors because there are none added.")

server.Streams.stdout += Testers.ExcludesExpression(
    "Violation:",
    "There should be no verification errors because there are none added.")

#
# Test 3: Verify field verification: failures.
#
r = Test.AddTestRun("Verify HTTP/2 field verification")
client = r.AddClientProcess("client3", "replay_files/http2_to_http2_verification_failures.yaml")
server = r.AddServerProcess("server3", "replay_files/http2_to_http2_verification_failures.yaml")
proxy = r.AddProxyProcess("proxy3", listen_port=client.Variables.https_port,
                          server_port=server.Variables.https_port,
                          use_ssl=True, use_http2_to_2=True)

client.ReturnCode = 1
server.ReturnCode = 1


client.Streams.stdout += Testers.ContainsExpression(
    'Contains Violation: Not Found. Key: "1", Field Name: "x-added-header", Required Value: "lmno", Actual Value: "abcdefg"',
    "There should be a verification about a field that doesn't contain the expected content.")
client.Streams.stdout += Testers.ContainsExpression(
    'Presence Violation: Absent. Key: "1", Field Name: "x-deleted-header"',
    "There should be a verification about a missing field.")

server.Streams.stdout += Testers.ContainsExpression(
    'Equals Violation: Different. Key: "1", Field Name: "x-added-header", Correct Value: "4", Actual Value: "3',
    "There should be a verification error about an incorrect value.")
server.Streams.stdout += Testers.ContainsExpression(
    'Presence Violation: Absent. Key: "1", Field Name: "x-deleted-header',
    "There should be a verification error about a missing field.")

#
# Test 4: Verify the ability to control server protocol negotiation via ALPN.
#
r = Test.AddTestRun("Verify HTTP/2 behavior on both the client and server sides")
client = r.AddClientProcess("client4", "replay_files/set_alpn.yaml")
server = r.AddServerProcess("server4", "replay_files/set_alpn.yaml")
proxy = r.AddProxyProcess("proxy4", listen_port=client.Variables.https_port,
                          server_port=server.Variables.https_port,
                          use_ssl=True, use_http2_to_2=True)

# The two sessions race with each other, so don't use a gold file here.
proxy.Streams.stdout += Testers.ContainsExpression(
    "Got SNI from client: b'test_sni_no_h2'",
    "Verify that the SNI associated with no HTTP/2 support was sent.")
proxy.Streams.stdout += Testers.ContainsExpression(
    "Got SNI from client: b'test_sni_with_h2'",
    "Verify that the SNI associated with HTTP/2 support was sent.")
proxy.Streams.stdout += Testers.ContainsExpression(
    "HTTP/2 negotiation failed. Trying with HTTP/1",
    "Verify that the proxy detected that HTTP/2 was rejected.")

# The client sent and received HTTP/2 for both transactions because
# only the server side should down-negotiate HTTP/2, not the proxy.
client.Streams.stdout += Testers.ContainsExpression(
    "Received an HTTP/2 response for stream id 1:",
    "The client should receive an HTTP/2 response for both transactions.")
client.Streams.stdout += Testers.ExcludesExpression(
    "HTTP/1",
    "Neither of the transactions should be HTTP/1")
client.Streams.stdout += Testers.ExcludesExpression(
    "Violation:",
    "There should be no verification errors because there are none added.")

server.Streams.stdout += Testers.ContainsExpression(
    'Using ALPN protocol string "h2,http/1.1,http1.1" for SNI "test_sni_with_h2"',
    "Verify that the correctly parsed ALPN string for the SNI supporting HTTP/2.")
server.Streams.stdout += Testers.ContainsExpression(
    'Using ALPN protocol string "http/1.1,http1.1" for SNI "test_sni_no_h2"',
    "Verify that the correctly parsed ALPN string for the SNI not supporting HTTP/2.")
server.Streams.stdout += Testers.ContainsExpression(
    "Negotiated alpn: h2",
    "Verify that HTTP/2 was negotiated for one session.")
server.Streams.stdout += Testers.ContainsExpression(
    "HTTP/2 is not negotiated. Assuming HTTP/1",
    "Verify that HTTP/1 was negotiated for one session.")
server.Streams.stdout += Testers.ContainsExpression(
    "an HTTP/2 response to request with key 1 with response status 200",
    "Verify that an HTTP/2 response was sent to the client.")
server.Streams.stdout += Testers.ContainsExpression(
    "an HTTP/1 response to request with key 2 with response status 200",
    "Verify that an HTTP/1 response was sent to the client.")
server.Streams.stdout += Testers.ExcludesExpression(
    "Violation:",
    "There should be no verification errors because there are none added.")
