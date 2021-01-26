'''
Verify basic body reading functionality.
'''
# @file
#
# Copyright 2020, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

Test.Summary = '''
Verify basic HTTPS functionality.
'''

r = Test.AddTestRun("Verify bodies can be read correctly.")
client = r.AddClientProcess("client1", "body.yaml")
server = r.AddServerProcess("server1", "body.yaml")
proxy = r.AddProxyProcess("proxy1", listen_port=client.Variables.https_port,
                          server_port=server.Variables.https_port, use_ssl=True)

proxy.Streams.stdout = "gold/body_proxy.gold"
client.Streams.stdout = "gold/body_client.gold"
server.Streams.stdout = "gold/body_server.gold"

client.Streams.stdout += Testers.ExcludesExpression(
        "Violation:",
        "There should be no verification errors because there are none added.")

server.Streams.stdout += Testers.ExcludesExpression(
        "Violation:",
        "There should be no verification errors because there are none added.")
