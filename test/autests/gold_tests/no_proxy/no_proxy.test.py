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
server = r.AddServerProcess("server", "replay/single_transaction.json",
                            other_args="--verbose diag")
client = r.AddClientProcess("client", "replay/single_transaction.json",
                            http_ports=[server.Variables.http_port],
                            https_ports=[server.Variables.https_port],
                            other_args="--no-proxy --verbose diag")

client.Streams.stdout = Testers.ContainsExpression(
        'Received an HTTP/1 200 response for .*',
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
        "response to request with key .* with response status 200",
        "Verify that the proxy request path was used by the replay-client.")

server.Streams.stdout += Testers.ContainsExpression(
        '"client-ip": "10.10.10.1"',
        "Verify that the proxy request headers were used by the replay-client.")

server.Streams.stdout += Testers.ExcludesExpression(
        "Violation:",
        "There should be no verification errors because there are none added.")

r = Test.AddTestRun("Verify no-proxy mode works for a simple HTTP/2 transaction")
server = r.AddServerProcess("server-h2", "replay/h2.yaml",
                            other_args="--verbose diag")
client = r.AddClientProcess("client-h2", "replay/h2.yaml",
                            http_ports=[server.Variables.http_port],
                            https_ports=[server.Variables.https_port],
                            other_args="--no-proxy --verbose diag")

client.Streams.stdout = "gold/h2_client.gold"
server.Streams.stdout = "gold/h2_server.gold"
