'''
Verify basic HTTP/2 functionality.
'''
# @file
#
# Copyright 2022-2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

#
# Test 1: Verify correct behavior of a single client-side HTTP/2 transaction.
#
case = suite.case("Verify HTTP/2 behavior on client-side only")
client = case.add_client("client1", "replay_files/http2_to_http1.yaml")
server = case.add_server("server1", "replay_files/http2_to_http1.yaml")
proxy = case.add_proxy("proxy1", listen_port=client.https_port, server_port=server.https_port,
                       use_ssl=True, use_http2_to_1=True)

proxy.stdout.matches_gold("gold/http2_to_http1_proxy.gold")
client.stdout.matches_gold("gold/http2_to_http1_client.gold")
server.stdout.matches_gold("gold/http2_to_http1_server.gold")

client.stdout.excludes("Violation:",
                       "There should be no verification errors because there are none added.")

server.stdout.excludes("Violation:",
                       "There should be no verification errors because there are none added.")

#
# Test 2: Verify field verification: all success.
#
case = suite.case("Verify HTTP/2 behavior on both the client and server sides")
client = case.add_client("client2", "replay_files/http2_to_http2.yaml")
server = case.add_server("server2", "replay_files/http2_to_http2.yaml")
proxy = case.add_proxy("proxy2", listen_port=client.https_port, server_port=server.https_port,
                       use_ssl=True, use_http2_to_2=True)

proxy.stdout.matches_gold("gold/http2_to_http2_proxy.gold")

client.stdout.contains("Received an HTTP/2 response for key 1 with stream id 1:",
                       "The client should receive the first HTTP/2 response.")
client.stdout.contains(
    "Received an HTTP/2 response for key 4 with stream id 7:",
    "The client should receive the empty-body HTTP/2 response with Content-Length: 0.")
client.stdout.contains("Received HTTP/2 response trailers for key 5 with stream id 9:",
                       "The client should receive the HTTP/2 response trailers.")
client.stdout.contains("HTTP/2 replay metrics: requests-submitted=5",
                       "The HTTP/2 replay should complete and emit replay metrics.")
client.stdout.excludes("Violation:",
                       "There should be no verification errors because there are none added.")

server.stdout.contains("Request with key 2 passed validation.",
                       "The server should validate the POST transaction on the HTTP/2 session.")
server.stdout.contains("Submitted the following HTTP/2 response headers for key 4 on stream 7:",
                       "The server should send the empty-body HTTP/2 response.")
server.stdout.contains("Request with key 5 passed validation.",
                       "The server should validate the trailer-bearing HTTP/2 transaction.")
server.stdout.excludes("Violation:",
                       "There should be no verification errors because there are none added.")

#
# Test 3: Verify field verification: failures.
#
case = suite.case("Verify HTTP/2 field verification")
client = case.add_client("client3", "replay_files/http2_to_http2_verification_failures.yaml")
server = case.add_server("server3", "replay_files/http2_to_http2_verification_failures.yaml")
proxy = case.add_proxy("proxy3", listen_port=client.https_port, server_port=server.https_port,
                       use_ssl=True, use_http2_to_2=True)

client.expect_return_codes(1)
server.expect_return_codes(1)

client.stdout.contains(
    'Contains Violation: Not Found. Key: "1", Field Name: "x-added-header", Required Value: "lmno", Actual Value: "abcdefg"',
    "There should be a verification about a field that doesn't contain the expected content.")
client.stdout.contains('Presence Violation: Absent. Key: "1", Field Name: "x-deleted-header"',
                       "There should be a verification about a missing field.")

server.stdout.contains(
    'Equals Violation: Different. Key: "1", Field Name: "x-added-header", Correct Value: "4", Actual Value: "3',
    "There should be a verification error about an incorrect value.")
server.stdout.contains('Presence Violation: Absent. Key: "1", Field Name: "x-deleted-header',
                       "There should be a verification error about a missing field.")

#
# Test 4: Verify the ability to control server protocol negotiation via ALPN.
#
case = suite.case("Verify HTTP/2 behavior on both the client and server sides")
client = case.add_client("client4", "replay_files/set_alpn.yaml")
server = case.add_server("server4", "replay_files/set_alpn.yaml")
proxy = case.add_proxy("proxy4", listen_port=client.https_port, server_port=server.https_port,
                       use_ssl=True, use_http2_to_2=True)

# The two sessions race with each other, so don't use a gold file here.
proxy.stdout.contains("Got SNI from client: b'test_sni_no_h2'",
                      "Verify that the SNI associated with no HTTP/2 support was sent.")
proxy.stdout.contains("Got SNI from client: b'test_sni_with_h2'",
                      "Verify that the SNI associated with HTTP/2 support was sent.")

# The client sent and received HTTP/2 for both transactions because
# only the server side should down-negotiate HTTP/2, not the proxy.
client.stdout.contains("Received an HTTP/2 response for key 1 with stream id 1:",
                       "The client should receive an HTTP/2 response for both transactions.")
client.stdout.excludes("HTTP/1", "Neither of the transactions should be HTTP/1")
client.stdout.excludes("Violation:",
                       "There should be no verification errors because there are none added.")

server.stdout.contains(
    'Using ALPN protocol string "h2,http/1.1,http1.1" for SNI "test_sni_with_h2"',
    "Verify that the correctly parsed ALPN string for the SNI supporting HTTP/2.")
server.stdout.contains(
    'Using ALPN protocol string "http/1.1,http1.1" for SNI "test_sni_no_h2"',
    "Verify that the correctly parsed ALPN string for the SNI not supporting HTTP/2.")
server.stdout.contains("Negotiated ALPN: h2", "Verify that HTTP/2 was negotiated for one session.")
server.stdout.contains("HTTP/2 is not negotiated. Assuming HTTP/1",
                       "Verify that HTTP/1 was negotiated for one session.")
server.stdout.contains("Sent the following HTTP/2 response headers for key 1 with stream id 1",
                       "Verify that an HTTP/2 response was sent to the client.")
server.stdout.contains("Sent the following HTTP/1 response headers for key 2",
                       "Verify that an HTTP/1 response was sent to the client.")
server.stdout.excludes("Violation:",
                       "There should be no verification errors because there are none added.")

#
# Test 5: Verify connection-specific headers are sanitized for HTTP/2 replays.
#
case = suite.case("Verify HTTP/2 strips connection-specific headers")
client = case.add_client("client5", "replay_files/http2_hop_by_hop.yaml")
server = case.add_server("server5", "replay_files/http2_hop_by_hop.yaml")
proxy = case.add_proxy("proxy5", listen_port=client.https_port, server_port=server.https_port,
                       use_ssl=True, use_http2_to_2=True)

client.stdout.contains("Received an HTTP/2 response for key h2-hop-by-hop-1 with stream id 1:",
                       "The first concurrent HTTP/2 response should complete successfully.")
client.stdout.contains("Received an HTTP/2 response for key h2-hop-by-hop-2 with stream id 3:",
                       "The second concurrent HTTP/2 response should complete successfully.")
client.stdout.excludes("HTTP/2 final response drain made no forward progress",
                       "The client should not hit the HTTP/2 stuck-session timeout summary.")
client.stdout.excludes(
    "Violation:", "The client should not report verification failures after sanitizing headers.")

server.stdout.contains("Skipping HTTP/2 connection-specific field connection: keep-alive",
                       "The server should strip invalid connection-specific response headers.")
server.stdout.contains("Skipping HTTP/2 connection-specific field upgrade: h2c",
                       "The server should strip invalid upgrade headers from HTTP/2 responses.")
server.stdout.excludes(
    "Received GOAWAY frame with last stream id 0, error code 1",
    "The client should no longer send a protocol-error GOAWAY for these streams.")
server.stdout.excludes(
    "Violation:", "The server should not report verification failures after sanitizing headers.")


def test_uranium_suite(uranium):
    uranium.run(suite)
