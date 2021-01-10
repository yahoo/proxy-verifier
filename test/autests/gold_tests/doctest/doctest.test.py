'''
Verify the sample replay file from the README.
'''
# @file
#
# Copyright 2020, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

Test.Summary = '''
Verify the sample replay file from the README.
'''

#
# Test 1: Verify correct behavior of a single client-side HTTP/2 transaction.
#
r = Test.AddTestRun(" Verify the sample replay file from the README.")
client = r.AddClientProcess("client", "sample_replay.yaml",
                            other_args="--verbose diag")
server = r.AddServerProcess("server", "sample_replay.yaml",
                            other_args="--verbose diag")

# The test proxy is not featureful enough to handle both HTTP/1 and HTTP/2
# traffic. Thankfully this is easily addressed by running a separate process
# for each.
proxy = r.AddProxyProcess("proxy_http", listen_port=client.Variables.http_port,
                          server_port=server.Variables.http_port)
proxy = r.AddProxyProcess("proxy_https", listen_port=client.Variables.https_port,
                          server_port=server.Variables.https_port,
                          use_ssl=True, use_http2_to_2=True)

client.Streams.stdout = "gold/doctest_client.gold"
server.Streams.stdout = "gold/doctest_server.gold"

client.Streams.stdout += Testers.ExcludesExpression(
        "Violation:",
        "There should be no verification errors because there are none added.")

server.Streams.stdout += Testers.ExcludesExpression(
        "Violation:",
        "There should be no verification errors because there are none added.")
