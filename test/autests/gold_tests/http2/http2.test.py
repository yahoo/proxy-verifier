'''
Verify basic HTTP/2 functionality.
'''
# @file
#
# Copyright 2020, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#


Test.Summary = '''
Verify basic HTTP/2 functionality.
'''

#
# Test 1: Verify correct behavior of a single HTTP/2 transaction.
#
r = Test.AddTestRun("Verify HTTP/2 processing of a single HTTP transaction")
client = r.AddClientProcess("client1", "replay_files/single_transaction",
                            https_ports=[4443], other_args="--verbose diag")
server = r.AddServerProcess("server1", "replay_files/single_transaction",
                            https_ports=[4444], other_args="--verbose diag")
proxy = r.AddProxyProcess("proxy1", listen_port=4443, server_port=4444,
                          use_ssl=True, use_http2_to_1=True)


proxy.Streams.stdout = "gold/single_transaction_proxy.gold"

client.Streams.stdout = "gold/single_transaction_client.gold"
client.Streams.stdout += Testers.ExcludesExpression(
        "Violation:",
        "There should be no verification errors because there are none added.")

server.Streams.stdout = "gold/single_transaction_server.gold"
server.Streams.stdout += Testers.ExcludesExpression(
        "Violation:",
        "There should be no verification errors because there are none added.")
