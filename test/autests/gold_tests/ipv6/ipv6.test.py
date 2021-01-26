'''
Verify basic IPv6 support.
'''
# @file
#
# Copyright 2020, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#


Test.Summary = '''
Verify basic IPv6 support.
'''

#
# Test 1: Verify transactions can be exchanged over IPv6.
#
r = Test.AddTestRun("Verify the correct handling of an HTTP/1, IPv6 transaction")
server = r.AddServerProcess("server1", "replay_files/single_transaction.yaml",
                            use_ipv6=True)
client = r.AddClientProcess("client1", "replay_files/single_transaction.yaml",
                            use_ipv6=True, http_ports=[server.Variables.http_port],
                            other_args="--no-proxy")

# Note that this test involves no proxy and, instead, the client talks directly
# to the server.

client.Streams.stdout = "gold/single_transaction_client.gold"
server.Streams.stdout = "gold/single_transaction_server.gold"

client.Streams.stdout += Testers.ExcludesExpression(
        "Violation:",
        "There should be no verification errors because there are none added.")
server.Streams.stdout += Testers.ExcludesExpression(
        "Violation:",
        "There should be no verification errors because there are none added.")
