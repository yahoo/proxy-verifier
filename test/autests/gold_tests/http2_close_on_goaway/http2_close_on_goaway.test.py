'''
GOAWAY frame tests.
'''
# @file
#
# Copyright 2024, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#
Test.Summary = '''
GOAWAY frame tests.
'''

tr = Test.AddTestRun("GOAWAY frame tests.")
client = tr.AddClientProcess("client", "http2_close_on_goaway.yaml")
server = tr.AddServerProcess("server", "http2_close_on_goaway.yaml")
proxy = tr.AddProxyProcess("proxy",
                           listen_port=client.Variables.https_port,
                           server_port=server.Variables.https_port,
                           use_ssl=True,
                           close_on_goaway=True,
                           use_http2_to_2=True)

tr.Streams.stdout += Testers.ContainsExpression("uuid: 1", "uuid: 1")
tr.Streams.stdout += Testers.ContainsExpression("uuid: 3", "uuid: 3")
tr.Streams.stdout += Testers.ContainsExpression("uuid: 4", "uuid: 4")
tr.Streams.stdout += Testers.ContainsExpression(
    "Failed to submit DATA frame for key 4 on stream 3: -510",
    "uuid: 4 should fail")

tr.Streams.stdout += Testers.ExcludesExpression("uuid: 2", "uuid: 2")

server.Streams.stdout += Testers.ContainsExpression("uuid: 1", "uuid: 1")
server.Streams.stdout += Testers.ContainsExpression("uuid: 3", "uuid: 3")

server.Streams.stdout += Testers.ExcludesExpression("uuid: 2", "uuid: 2")
server.Streams.stdout += Testers.ExcludesExpression("uuid: 4", "uuid: 4")
