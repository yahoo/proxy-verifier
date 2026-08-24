'''
Verify request method verification behavior across protocol stacks.
'''
# @file
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

HTTP3_ARGS = "--poll-timeout 10000"

#
# Test 1: Verify HTTP/1 method verification uses the top-level proxy-request
# method node.
#
case = suite.case("Verify HTTP/1 request method verification")
client = case.add_client("client1", "replay_files/http1_method_verification.yaml",
                         configure_https=False)
server = case.add_server("server1", "replay_files/http1_method_verification.yaml",
                         configure_https=False)
case.add_proxy("proxy1", listen_port=client.http_port, server_port=server.http_port)

server.stdout.contains(
    'HTTP/1 Method Success: Key: "1", Method: "GET"',
    "The HTTP/1 request method should verify successfully for the matching transaction.")
server.stdout.excludes(
    'HTTP/1 Method Violation: .*Key: "1"',
    "The matching HTTP/1 transaction should not report a method verification violation.")
server.stdout.contains(
    'HTTP/1 Method Violation: Different. Key: "2", Expected Method: "POST", Received Method: "GET"',
    "The HTTP/1 request method should fail when the proxy sends the wrong method.")

client.expect_return_codes(0)
server.expect_return_codes(1)

#
# Test 2: Verify HTTP/2 request method verification continues to work via the
# :method pseudo header field.
#
case = suite.case("Verify HTTP/2 request method verification")
client = case.add_client("client2", "replay_files/http2_method_verification.yaml")
server = case.add_server("server2", "replay_files/http2_method_verification.yaml")
case.add_proxy("proxy2", listen_port=client.https_port, server_port=server.https_port, use_ssl=True,
               use_http2_to_2=True)

server.stdout.contains(
    'Equals Success: Key: "1", Field Name: ":method", Value: "GET"',
    "The HTTP/2 :method pseudo header should verify successfully for the matching transaction.")
server.stdout.excludes(
    'Equals Violation: .*Key: "1".*Field Name: ":method"',
    "The matching HTTP/2 transaction should not report a :method verification violation.")
server.stdout.contains(
    'Equals Violation: Different. Key: "2", Field Name: ":method", Correct Value: "POST", Actual Value: "GET"',
    "The HTTP/2 :method pseudo header should fail when the proxy sends the wrong method.")

client.expect_return_codes(0)
server.expect_return_codes(1)

#
# Test 3: Verify an HTTP/3 client path can exercise the HTTP/1 request method
# verification on the downstream side.
#
case = suite.case("Verify HTTP/3 request method verification")
client = case.add_client("client3", "replay_files/http3_method_verification.yaml",
                         other_args=HTTP3_ARGS)
server = case.add_server("server3", "replay_files/http3_method_verification.yaml",
                         other_args=HTTP3_ARGS)
case.add_proxy("proxy3", listen_port=client.http3_port, server_port=server.http_port, use_ssl=True,
               use_http3_to_1=True)

server.stdout.contains(
    'HTTP/1 Method Success: Key: "1", Method: "GET"',
    "The HTTP/3-originated request should pass downstream HTTP/1 method verification.")
server.stdout.excludes(
    'HTTP/1 Method Violation: .*Key: "1"',
    "The matching HTTP/3 transaction should not report a downstream method violation.")
server.stdout.contains(
    'HTTP/1 Method Violation: Different. Key: "2", Expected Method: "POST", Received Method: "GET"',
    "The HTTP/3-originated request should fail downstream method verification on mismatch.")

client.expect_return_codes(0)
server.expect_return_codes(1)


def test_uranium_suite(uranium):
    uranium.run(suite)
