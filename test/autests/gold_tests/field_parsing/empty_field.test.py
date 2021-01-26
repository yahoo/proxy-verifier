'''
Verify correct handling of malformed replay files.
'''
# @file
#
# Copyright 2020, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#


Test.Summary = '''
Verify correct handling of malformed replay files.
'''

#
# Test 1: Verify correct handling of empty fields.
#
r = Test.AddTestRun("Verify correct handling of empty header fields")
client = r.AddClientProcess("client1", "replay_files/empty_field.yaml")
server = r.AddServerProcess("server1", "replay_files/empty_field.yaml")
proxy = r.AddProxyProcess("proxy1", listen_port=client.Variables.http_port,
                          server_port=server.Variables.http_port)

client.ReturnCode = 1
server.ReturnCode = 1

# Due to the parsing failure, the server will not listen on the port.
# Thus the standard ready criteria will not work.
server.Ready = None

client.Streams.stdout = Testers.ContainsExpression(
        "Field or rule at line .* is not a sequence as required",
        "Verify that we inform the user of the malformed field.")
server.Streams.stdout = Testers.ContainsExpression(
        "Field or rule at line .* is not a sequence as required",
        "Verify that we inform the user of the malformed field.")
