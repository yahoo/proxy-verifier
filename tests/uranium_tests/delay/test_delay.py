'''
Verify correct handling of session and transaction delay.
'''
# @file
#
# Copyright 2021-2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

#
# Test 1: Run a few sessions and transactions with client-side delay.
#
case = suite.case("Verify the handling of the client-side delay specification.")
client = case.add_client("client_client_delay", "client-side-delay.yaml")
server = case.add_server("server_client_delay", "client-side-delay.yaml")

# The test proxy is not featureful enough to handle both HTTP/1 and HTTP/2
# traffic. Thankfully this is easily addressed by running a separate process
# for each.
proxy = case.add_proxy("proxy_http_client_delay", listen_port=client.http_port,
                       server_port=server.http_port)
proxy = case.add_proxy("proxy_https_client_delay", listen_port=client.https_port,
                       server_port=server.https_port, use_ssl=True, use_http2_to_2=True)

server.stdout.contains("Ready with 3 transactions.",
                       "The server should have parsed 2 transactions.")

client.stdout.contains(
    "3 transactions in 2 sessions .* in .* milliseconds",
    "The client should have reported running the transactions with timing data.")

client.stdout.excludes("Violation:",
                       "There should be no verification errors because there are none added.")

server.stdout.excludes("Violation:",
                       "There should be no verification errors because there are none added.")

#
# Test 2: Verify that the timing data indicates that the delays took place.
#
case = suite.case("Verify the client-side delay replay took an expected amount of time to run.")
verifier_script = 'verify_duration.py'
client_output = client.stdout.path
expected_min_delay_ms = "3000"
process = case.add_process(
    "verify-client-delay",
    ["python3", verifier_script, client_output, expected_min_delay_ms],
    copies=[verifier_script],
)
process.stdout.contains('Good', 'The verifier script should report success.')

#
# Test 3: Run a few sessions and transactions with server-side delay.
#
case = suite.case("Verify the handling of the server-side delay specification.")
client = case.add_client("client_server_delay", "server-side-delay.yaml")
server = case.add_server("server_server_delay", "server-side-delay.yaml")

# The test proxy is not featureful enough to handle both HTTP/1 and HTTP/2
# traffic. Thankfully this is easily addressed by running a separate process
# for each.
proxy = case.add_proxy("proxy_http_server_delay", listen_port=client.http_port,
                       server_port=server.http_port)
proxy = case.add_proxy("proxy_https_server_delay", listen_port=client.https_port,
                       server_port=server.https_port, use_ssl=True, use_http2_to_2=True)

server.stdout.contains("Ready with 2 transactions.",
                       "The server should have parsed 2 transactions.")

client.stdout.contains(
    "2 transactions in 2 sessions .* in .* milliseconds",
    "The client should have reported running the transactions with timing data.")

client.stdout.excludes("Violation:",
                       "There should be no verification errors because there are none added.")

server.stdout.excludes("Violation:",
                       "There should be no verification errors because there are none added.")

#
# Test 4: Verify that the timing data indicates that the delays took place.
#
case = suite.case("Verify the server-side delay replay took an expected amount of time to run.")
client_output = client.stdout.path
expected_min_delay_ms = "1000"
process = case.add_process(
    "verify-server-delay",
    ["python3", verifier_script, client_output, expected_min_delay_ms],
    copies=[verifier_script],
)
process.stdout.contains('Good', 'The verifier script should report success.')

#
# Test 5: Run transactions with a content delay, which delays the response body
# behind the response headers.
#
case = suite.case("Verify the handling of the content delay specification.")
client = case.add_client("client_content_delay", "content-delay.yaml")
server = case.add_server("server_content_delay", "content-delay.yaml")

# A content delay is an HTTP/1.x feature, so only an HTTP/1 proxy is needed.
proxy = case.add_proxy("proxy_http_content_delay", listen_port=client.http_port,
                       server_port=server.http_port)

server.stdout.contains("Ready with 1 transaction.",
                       "The server should have parsed 1 transaction.")

server.stdout.contains(
    "Delaying the body for key content-length-request per the content delay specification: 700",
    "The server should delay the body of the response.")

client.stdout.contains(
    "1 transaction in 1 session .* in .* milliseconds",
    "The client should have reported running the transaction with timing data.")

client.stdout.excludes("Violation:",
                       "There should be no verification errors because there are none added.")

server.stdout.excludes("Violation:",
                       "There should be no verification errors because there are none added.")

#
# Test 6: Verify that the timing data indicates that the content delay took
# place.
#
case = suite.case("Verify the content delay replay took an expected amount of time to run.")
client_output = client.stdout.path
# The response delays 700 ms before its body. Without the content delay the
# transaction would finish almost immediately.
expected_min_delay_ms = "700"
process = case.add_process(
    "verify-content-delay",
    ["python3", verifier_script, client_output, expected_min_delay_ms],
    copies=[verifier_script],
)
process.stdout.contains('Good', 'The verifier script should report success.')


def test_uranium_suite(uranium):
    uranium.run(suite)
