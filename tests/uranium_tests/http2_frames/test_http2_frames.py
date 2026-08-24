'''
Specify h2 frame sequence.
'''
# @file
#
# Copyright 2022-2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

#
# Test 1: Abort after DATA frame
#
case = suite.case("Specify h2 frame sequence")
client = case.add_client("client1", "http2_frames.yaml")
server = case.add_server("server1", "http2_frames.yaml")
proxy = case.add_proxy("proxy1", listen_port=client.https_port, server_port=server.https_port,
                       use_ssl=True, use_http2_to_2=True)

client.stdout.matches_gold("gold/client.gold")
server.stdout.matches_gold("gold/server.gold")
proxy.stdout.matches_gold("gold/proxy.gold")

#
# Test 2: Verify that the timing data indicates that the delays took place.
#
case = suite.case("Verify the client-side delay replay took an expected amount of time to run.")
verifier_script = 'verify_duration.py'
client_output = client.stdout.path
expected_min_delay_ms = "1500"
process = case.add_process(
    "verify-duration",
    ["python3", verifier_script, client_output, expected_min_delay_ms],
    copies=[verifier_script],
)
process.stdout.contains('Good', 'The verifier script should report success.')


def test_uranium_suite(uranium):
    uranium.run(suite)
