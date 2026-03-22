'''
Send multiple data frames.
'''
# @file
#
# Copyright 2023, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

Test.Summary = '''
Send multiple data frames.
'''

#
# Test 1: Send multiple DATA frames
#
r = Test.AddTestRun("Send multiple data frames")
client = r.AddClientProcess("client1", "http2_multi_data_frames.yaml")
server = r.AddServerProcess("server1", "http2_multi_data_frames.yaml")
proxy = r.AddProxyProcess("proxy1", listen_port=client.Variables.https_port,
                          server_port=server.Variables.https_port, use_ssl=True,
                          use_http2_to_2=True)

proxy.Streams.stdout = "gold/multi_data_frame_proxy.gold"

client.Streams.stdout += Testers.ContainsExpression(
    "Submitted DATA frame for key 1 on stream 1.",
    "The client should submit the replayed HTTP/2 DATA frames.")
client.Streams.stdout += Testers.ContainsExpression(
    'Equals Success: Key: "1", Content Data: "body", Value: "server_data_1server_data_2server_data_3"',
    "The client should verify the combined HTTP/2 response body.")
client.Streams.stdout += Testers.ContainsExpression(
    r"HTTP/2 replay metrics: requests-submitted=1, max-in-flight-streams=1, "
    r"send-phase-bytes-drained=0, final-drain-duration=[0-9]+ms\.",
    "The client should complete the HTTP/2 replay and emit replay metrics.")
client.Streams.stdout += Testers.ExcludesExpression(
    "Violation:", "The client should not report verification failures for the multi-frame replay.")

server.Streams.stdout += Testers.ContainsExpression(
    "Received an HTTP/2 body of 39 bytes for key 1 with stream id 1:",
    "The server should receive the combined HTTP/2 request body.")
server.Streams.stdout += Testers.ContainsExpression(
    'Equals Success: Key: "1", Content Data: "body", Value: "client_data_1client_data_2client_data_3"',
    "The server should verify the combined replayed request body.")
server.Streams.stdout += Testers.ContainsExpression(
    "Sent an HTTP/2 body of 13 bytes for key 1 of stream id 1:",
    "The server should send the replayed HTTP/2 DATA frames.")
server.Streams.stdout += Testers.ExcludesExpression(
    "Violation:", "The server should not report verification failures for the multi-frame replay.")

#
# Test 2: Verify that the timing data indicates that the delays took place on the client side.
#
r = Test.AddTestRun("Verify the client-side delay replay took an expected amount of time to run.")
verifier_script = 'verify_duration.py'
client_output = client.Streams.stdout.AbsTestPath
expected_min_delay_ms = "5000"
r.Processes.Default.Setup.Copy(verifier_script)

r.Processes.Default.Command = \
    f'python3 {verifier_script} {client_output} {expected_min_delay_ms}'
r.ReturnCode = 0
r.Streams.stdout += Testers.ContainsExpression('Good', 'The verifier script should report success.')
