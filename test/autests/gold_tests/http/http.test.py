'''
Verify basic HTTP/1.x functionality.
'''
# @file
#
# Copyright 2021, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#


Test.Summary = '''
Verify basic HTTP/1.x functionality.
'''

#
# Test 1: Verify correct behavior of a single HTTP transaction.
#
r = Test.AddTestRun("Verify HTTP/1 processing of a single HTTP transaction")

# Add configure_https=False to verify ATS client and server work when the https
# optional arguments are not provided.
client = r.AddClientProcess("client1", "replay_files/single_transaction.yaml",
                            configure_https=False)
server = r.AddServerProcess("server1", "replay_files/single_transaction.yaml",
                            configure_https=False)
proxy = r.AddProxyProcess("proxy1", listen_port=client.Variables.http_port,
                          server_port=server.Variables.http_port)


proxy.Streams.stdout = "gold/single_transaction_proxy.gold"
client.Streams.stdout = "gold/single_transaction_client.gold"
server.Streams.stdout = "gold/single_transaction_server.gold"

client.Streams.stdout += Testers.ExcludesExpression(
    "Violation:",
    "There should be no verification errors because there are none added.")

server.Streams.stdout += Testers.ExcludesExpression(
    "Violation:",
    "There should be no verification errors because there are none added.")

#
# Test 2: Verify correct behavior of multiple HTTP sessions.
#
r = Test.AddTestRun("Verify HTTP/1 processing of multiple HTTP transactions")
client = r.AddClientProcess("client2", "replay_files/multiple_transactions")
server = r.AddServerProcess("server2", "replay_files/multiple_transactions")
proxy = r.AddProxyProcess("proxy2", listen_port=client.Variables.http_port,
                          server_port=server.Variables.http_port)


client.Streams.stdout = Testers.ContainsExpression(
    "7 transactions in 5 sessions",
    "Verify that 7 transactions were parsed.")

client.Streams.stdout += Testers.ContainsExpression(
    "Loading 3 replay files.",
    "Verify that 3 replay files were parsesd.")

client.Streams.stdout += Testers.ContainsExpression(
    "204 No Content",
    "Verify the No Content reason string.")

client.Streams.stdout += Testers.ContainsExpression(
    "POST /some/request HTTP/1.0",
    "Verify that we sent the HTTP/1.0 version.")

client.Streams.stdout += Testers.ExcludesExpression(
    "Violation:",
    "There should be no verification errors because there are none added.")

server.Streams.stdout = Testers.ContainsExpression(
    "Ready with 7 transactions.",
    "Verify that 7 transactions were parsed.")

server.Streams.stdout += Testers.ContainsExpression(
    "Loading 3 replay files",
    "Verify that 3 replay files were parsed.")

server.Streams.stdout += Testers.ExcludesExpression(
    "Violation:",
    "There should be no verification errors because there are none added.")
