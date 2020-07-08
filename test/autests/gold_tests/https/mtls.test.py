'''
Verify correct TLS client and server verification behavior.
'''
# @file
#
# Copyright 2020, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#


Test.Summary = '''
Verify correct TLS client and server verification behavior.
'''

#
# Test 1: Verify that both the client and server can verify the proxy
#         if specified to do so in the "tls" node.
#
r = Test.AddTestRun("Verify parsing of a YAML-specified replay file")
client = r.AddClientProcess("client1", "replay_files/mtls.yaml",
                            https_ports=[4443], other_args="--verbose diag")
server = r.AddServerProcess("server1", "replay_files/mtls.yaml",
                            https_ports=[4444], other_args="--verbose diag")
proxy = r.AddProxyProcess("proxy1", listen_port=4443, server_port=4444,
                          use_ssl=True)

client.Streams.stdout += Testers.ContainsExpression(
        "Proxy TLS verification result: passed",
        "Verify that the client verified the proxy's cert.")

server.Streams.stdout += Testers.ContainsExpression(
        "Sending a certificate request to client with SNI: bob",
        "Verify that the server requested a cert from the proxy.")
server.Streams.stdout += Testers.ContainsExpression(
        "Client TLS verification result for client with SNI bob: passed",
        "Verify that the proxy's cert was verified.")
