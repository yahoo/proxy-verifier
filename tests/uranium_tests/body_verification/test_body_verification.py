'''
Verify basic body verification functionality.
'''
# @file
#
# Copyright 2022-2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

#
# Test 1: Verify bodies can be verified correctly for HTTP/1.1.
#
case = suite.case("Verify bodies can be verified correctly for HTTP/1.1.")
client = case.add_client("client1", "http.yaml")
server = case.add_server("server1", "http.yaml")
proxy = case.add_proxy("proxy1", listen_port=client.https_port, server_port=server.https_port,
                       use_ssl=True)

client.stdout.contains('Equals Success: Key: "1", Content Data: "body"',
                       "Verification should be happy with the body.")
client.stdout.contains('Contains Success: Key: "2", Content Data: "body"',
                       "Verification should be happy with the body.")
client.stdout.contains('Equals Violation: Different. Key: "3", Content Data: "body"',
                       "Verification should not be happy with the body.")

server.stdout.contains('Equals Success: Key: "1", Content Data: "body"',
                       "Verification should be happy with the body.")
server.stdout.contains('Contains Success: Key: "2", Content Data: "body"',
                       "Verification should be happy with the body.")
server.stdout.contains('Equals Violation: Different. Key: "3", Content Data: "body"',
                       "Verification should not be happy with the body.")

#
# Test 2: Verify bodies can be verified correctly for HTTP/2.
#
case = suite.case("Verify bodies can be verified correctly for HTTP/2.")
client = case.add_client("client2", "http2.yaml")
server = case.add_server("server2", "http2.yaml")
proxy = case.add_proxy("proxy2", listen_port=client.https_port, server_port=server.https_port,
                       use_ssl=True, use_http2_to_2=True)

client.stdout.contains('Equals Success: Key: "1", Content Data: "body"',
                       "Verification should be happy with the body.")
client.stdout.contains('No Case Prefix Success: Key: "2", Content Data: "body"',
                       "Verification should be happy with the body.")

server.stdout.contains('Equals Success: Key: "1", Content Data: "body"',
                       "Verification should be happy with the body.")
server.stdout.contains('No Case Suffix Success: Key: "2", Content Data: "body"',
                       "Verification should be happy with the body.")

#
# Test 3: Verify bodies can be verified correctly for HTTP/3.
#
case = suite.case("Verify bodies can be verified correctly for HTTP/3.")
client = case.add_client("client3", "http3.yaml")
server = case.add_server("server3", "http3.yaml")
proxy = case.add_proxy("proxy3", listen_port=client.http3_port, server_port=server.http_port,
                       use_ssl=True, use_http3_to_1=True)

client.stdout.contains('Not Contains Success: Not Found. Key: "1", Content Data: "body"',
                       "Verification should be happy with the body.")
client.stdout.contains('Not No Case Contains Violation: Key: "2", Content Data: "body"',
                       "Verification should not be happy with the body.")

server.stdout.contains('Not Equals Success: Different. Key: "1", Content Data: "body"',
                       "Verification should be happy with the body.")
server.stdout.contains('Not No Case Equals Violation: Key: "2", Content Data: "body"',
                       "Verification should not be happy with the body.")


def test_uranium_suite(uranium):
    uranium.run(suite)
