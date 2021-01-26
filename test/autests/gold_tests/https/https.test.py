'''
Verify basic HTTPS functionality.
'''
# @file
#
# Copyright 2020, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

Test.Summary = '''
Verify basic HTTPS functionality.
'''

r = Test.AddTestRun("Verify processing of a simple HTTPS transaction")

# Add configure_http=False to verify ATS client and server work when the http
# optional arguments are not provided.
client = r.AddClientProcess("client1", "replay_files/single_transaction.yaml",
                            configure_http=False)
server = r.AddServerProcess("server1", "replay_files/single_transaction.yaml",
                            configure_http=False)
proxy = r.AddProxyProcess("proxy1", listen_port=client.Variables.https_port,
                          server_port=server.Variables.https_port, use_ssl=True)

proxy.Streams.stdout = "gold/single_transaction_proxy.gold"
client.Streams.stdout = "gold/single_transaction_client.gold"
server.Streams.stdout = "gold/single_transaction_server.gold"

client.Streams.stdout += Testers.ExcludesExpression(
        "Violation:",
        "There should be no verification errors because there are none added.")

server.Streams.stdout += Testers.ExcludesExpression(
        "Violation:",
        "There should be no verification errors because there are none added.")
