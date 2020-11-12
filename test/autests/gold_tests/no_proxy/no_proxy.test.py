'''
Verify basic --no-proxy functionality.
'''
# @file
#
# Copyright 2020, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

Test.Summary = '''
Verify basic --no-proxy functionality.
'''

r = Test.AddTestRun("Verify no-proxy mode works for a simple HTTP transaction")
client = r.AddClientProcess("client", "single_transaction.json",
                            other_args="--no-proxy --verbose diag")
server = r.AddServerProcess("server", "single_transaction.json",
                            other_args="--verbose diag")

client.Streams.stdout = Testers.ContainsExpression(
        'Status for key .*: "200"',
        "Verify that the response came back from replay-server")

client.Streams.stdout += Testers.ContainsExpression(
        '"x-testheader": "from_server_response"',
        "Verify that the server response headers were used by the replay-server.")

client.Streams.stdout += Testers.ExcludesExpression(
        '"x-testheader": "from_proxy_response"',
        "Verify that the proxy response headers were not used by the replay-server.")

client.Streams.stdout += Testers.ExcludesExpression(
        "Violation:",
        "There should be no verification errors because there are none added.")

server.Streams.stdout = Testers.ContainsExpression(
        "Responding to request /proxy.do with status 200",
        "Verify that the proxy request path was used by the replay-client.")

server.Streams.stdout += Testers.ContainsExpression(
        '"client-ip": "10.10.10.1"',
        "Verify that the proxy request headers were used by the replay-client.")

server.Streams.stdout += Testers.ExcludesExpression(
        "Violation:",
        "There should be no verification errors because there are none added.")
