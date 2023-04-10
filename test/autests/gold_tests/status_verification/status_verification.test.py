'''
Verify correct response status(status code and reason) verification behavior.
'''
# @file
#
# Copyright 2023, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

Test.Summary = '''
Verify correct response status(status code and reason) verification behavior.
'''

#
# Test 1: Verify status verification in a YAML replay file.
#
r = Test.AddTestRun(
    "Verify status verification works for simple HTTP transactions")
client = r.AddClientProcess(
    "client1", "replay_files/status_verification.yaml")
server = r.AddServerProcess(
    "server1", "replay_files/status_verification.yaml")
proxy = r.AddProxyProcess("proxy1", listen_port=client.Variables.http_port,
                          server_port=server.Variables.http_port)

# Verify status validation logs.
client.Streams.stdout = Testers.ExcludesExpression(
    'Violation.*key: 1',
    'Transaction 1 should not have any violation since the status code matches the expected.')
client.Streams.stdout += Testers.ContainsExpression(
    'Status Violation:.*key: 2',
    'Transaction 2 should have status violation as the status code does not match the expected.')
client.Streams.stdout += Testers.ExcludesExpression(
    'Violation.*key: 3',
    'Transaction 3 should not have violation since the reason string matches the expected.')
client.Streams.stdout += Testers.ContainsExpression(
    'Reason String Violation:.*key: 4',
    'Transaction 4 should have violation as the reason string does not match the expected.')
client.ReturnCode = 1
