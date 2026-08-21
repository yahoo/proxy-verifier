'''
Verify basic HTTP/3 functionality.
'''
# @file
#
# Copyright 2021-2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

r_http3_args = "--poll-timeout 10000"

#
# Test 1: Verify correct behavior of a various HTTP/3 transactions.
#
case = suite.case("Verify HTTP/3")
client = case.add_client("client1", "replay_files/http3_to_http1.yaml", other_args=r_http3_args,
                         verbose=False)
server = case.add_server("server1", "replay_files/http3_to_http1.yaml", other_args=r_http3_args,
                         verbose=False)
proxy = case.add_proxy("proxy1", listen_port=client.http3_port, server_port=server.http_port,
                       use_ssl=True, use_http3_to_1=True)

client.stdout.excludes("Violation:",
                       "There should be no verification errors because there are none added.")

server.stdout.excludes("Violation:",
                       "There should be no verification errors because there are none added.")

#
# Filter stable verification lines before comparing against gold. Raw HTTP/3
# output includes asynchronous debug ordering and large generated bodies that
# are both expensive and noisy to compare directly.
#
case = suite.case("Verify filtered HTTP/3 output")
client_output = client.stdout.path
server_output = server.stdout.path
process = case.add_process(
    "filter-client-server",
    ["python3", "filter_http3_output.py", client_output, server_output],
    copies=["filter_http3_output.py"],
)
process.stdout.matches_gold("gold/http3_to_http1_client_server.gold")

#
# Keep the proxy coverage focused on request and response headers. The proxy
# output includes generated body bytes, so filtering avoids comparing the large
# 300 KB payloads while still catching missing or incorrect headers.
#
case = suite.case("Verify filtered HTTP/3 proxy output")
proxy_output = proxy.stdout.path
process = case.add_process(
    "filter-proxy",
    ["python3", "filter_http3_output.py", "--proxy-output", proxy_output],
    copies=["filter_http3_output.py"],
)
process.stdout.matches_gold("gold/http3_to_http1_proxy.gold")

#
# Test 2: Verify correct verification failure behaviors.
#
case = suite.case("Verify HTTP/3 with verification failures")
client = case.add_client("client2", "replay_files/http3_to_http1_failures.yaml",
                         other_args=r_http3_args)
server = case.add_server("server2", "replay_files/http3_to_http1_failures.yaml",
                         other_args=r_http3_args)
proxy = case.add_proxy("proxy2", listen_port=client.http3_port, server_port=server.http_port,
                       use_ssl=True, use_http3_to_1=True)

client.expect_return_codes(1)

client.stdout.contains(
    'Equals Violation: Different. .* Field Name: "x-equal-header", Correct Value: "other_content", Actual Value: "some_content"',
    "There should be an equal violation for x-equal-header.")

client.stdout.contains('Equals Success: .* Field Name: "x-response-header", Value: "response"',
                       "Verification should be happy with the X-Response-Header.")

client.stdout.contains(
    'Absence Violation: Present. .* Field Name: "x-added-header", Value: "1"',
    "There should be an absence violation for X-Added-Header because it will be present.")

client.stdout.contains(
    'Presence Violation: Absent. .* Field Name: "x-deleted-header"',
    "There should be an presence violation for X-Deleted-Header because it will be absent.")

client.stdout.contains('HTTP/3 Status Violation: expected 502 got 200',
                       "There should a status violation for an unexpected 502 response.")


def test_uranium_suite(uranium):
    uranium.run(suite)
