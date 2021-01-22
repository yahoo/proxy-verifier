'''
Verify correct handling of session and transaction delay.
'''
# @file
#
# Copyright 2021, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

import os
from os.path import dirname

Test.Summary = '''
Verify correct handling of session and transaction delay.
'''

#
# Test 1: Run a few sessions and transactions with delay.
#
r = Test.AddTestRun("Verify the handling of the delay specification.")
client = r.AddClientProcess("client", "delay.yaml",
                            other_args="--verbose diag")
server = r.AddServerProcess("server", "delay.yaml",
                            other_args="--verbose diag")

# The test proxy is not featureful enough to handle both HTTP/1 and HTTP/2
# traffic. Thankfully this is easily addressed by running a separate process
# for each.
proxy = r.AddProxyProcess("proxy_http", listen_port=client.Variables.http_port,
                          server_port=server.Variables.http_port)
proxy = r.AddProxyProcess("proxy_https", listen_port=client.Variables.https_port,
                          server_port=server.Variables.https_port,
                          use_ssl=True, use_http2_to_2=True)

server.Streams.stdout += Testers.ContainsExpression(
        "Ready with 2 transactions.",
        "The server should have parsed 2 transactions.")

client.Streams.stdout += Testers.ContainsExpression(
        "2 transactions in 2 sessions .* in .* milliseconds",
        "The client should have reported running the transactions with timing data.")

client.Streams.stdout += Testers.ExcludesExpression(
        "Violation:",
        "There should be no verification errors because there are none added.")

server.Streams.stdout += Testers.ExcludesExpression(
        "Violation:",
        "There should be no verification errors because there are none added.")

#
# Test 2: Verify that the timing data indicates that the delays took place.
#
r = Test.AddTestRun("Verify the replay took an expected amount of time to run.")
verifier_script = 'verify_duration.py'
client_output = client.Streams.stdout.AbsTestPath
expected_min_delay_ms = "1500"
r.Processes.Default.Setup.Copy(verifier_script)

r.Processes.Default.Command = \
        f'python3 {verifier_script} {client_output} {expected_min_delay_ms}'
r.ReturnCode = 0
r.Streams.stdout += Testers.ContainsExpression(
        'Good',
        f'The verifier script should report success.')
