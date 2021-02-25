'''
Verify replay_gen.py can generate parsable replay files.
'''
# @file
#
# Copyright 2021, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#


Test.Summary = '''
Verify replay_gen.py can generate parsable replay files.
'''

#
# Test 1: Generate replay files via replay_gen and verify they can be replayed.
#
r = Test.AddTestRun("Generate replay files via replay_gen.py")
replay_gen = r.ConfigureReplayGenDefaultProcess("replay_gen1", num_transactions=20)

r = Test.AddTestRun("Make sure we can use the generated replay files")
client = r.AddClientProcess("client1", replay_gen.Variables.replay_dir)
server = r.AddServerProcess("server1", replay_gen.Variables.replay_dir)
proxy = r.AddProxyProcess("proxy1", listen_port=client.Variables.http_port,
                          server_port=server.Variables.http_port)

# The Python test proxy may close the connection part way through the
# transactions. I've verified that if the client talks directly to the server,
# there are no problems.
client.ReturnCode = Any(0, 1)

client.Streams.stdout += Testers.ContainsExpression(
    "Parsed 20 transactions",
    "Verify that the verifier client was able to parse the expected 20 transactions.")

server.Streams.stdout += Testers.ContainsExpression(
    "Ready with 20 transactions",
    "Verify that the verifier server was able to parse the expected 20 transactions.")
