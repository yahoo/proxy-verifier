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
                          server_port=server.Variables.https_port,
                          use_ssl=True, use_http2_to_2=True)

client.Streams.stdout = "gold/multi_data_frame_client.gold"
server.Streams.stdout = "gold/multi_data_frame_server.gold"
proxy.Streams.stdout = "gold/multi_data_frame_proxy.gold"

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
r.Streams.stdout += Testers.ContainsExpression(
    'Good',
    'The verifier script should report success.')
