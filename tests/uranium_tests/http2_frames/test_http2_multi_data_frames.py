'''
Send multiple data frames.
'''
# @file
#
# Copyright 2023-2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

#
# Test 1: Send multiple DATA frames
#
case = suite.case("Send multiple data frames")
client = case.add_client("client1", "http2_multi_data_frames.yaml")
server = case.add_server("server1", "http2_multi_data_frames.yaml")
proxy = case.add_proxy("proxy1", listen_port=client.https_port, server_port=server.https_port,
                       use_ssl=True, use_http2_to_2=True)

proxy.stdout.matches_gold("gold/multi_data_frame_proxy.gold")

client.stdout.contains("Submitted DATA frame for key 1 on stream 1.",
                       "The client should submit the replayed HTTP/2 DATA frames.")
client.stdout.contains(
    'Equals Success: Key: "1", Content Data: "body", Value: "server_data_1server_data_2server_data_3"',
    "The client should verify the combined HTTP/2 response body.")
client.stdout.contains(
    r"HTTP/2 replay metrics: requests-submitted=1, max-in-flight-streams=1, "
    r"send-phase-bytes-drained=0, final-drain-duration=[0-9]+ms\.",
    "The client should complete the HTTP/2 replay and emit replay metrics.")
client.stdout.excludes(
    "Violation:", "The client should not report verification failures for the multi-frame replay.")

server.stdout.contains("Received an HTTP/2 body of 39 bytes for key 1 with stream id 1:",
                       "The server should receive the combined HTTP/2 request body.")
server.stdout.contains(
    'Equals Success: Key: "1", Content Data: "body", Value: "client_data_1client_data_2client_data_3"',
    "The server should verify the combined replayed request body.")
server.stdout.contains("Sent an HTTP/2 body of 13 bytes for key 1 of stream id 1:",
                       "The server should send the replayed HTTP/2 DATA frames.")
server.stdout.excludes(
    "Violation:", "The server should not report verification failures for the multi-frame replay.")

#
# Test 2: Verify that the timing data indicates that the delays took place on the client side.
#
case = suite.case("Verify the client-side delay replay took an expected amount of time to run.")
verifier_script = 'verify_duration.py'
client_output = client.stdout.path
expected_min_delay_ms = "5000"
process = case.add_process(
    "verify-duration",
    ["python3", verifier_script, client_output, expected_min_delay_ms],
    copies=[verifier_script],
)
process.stdout.contains('Good', 'The verifier script should report success.')


def test_uranium_suite(uranium):
    uranium.run(suite)
