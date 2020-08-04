'''
Verify replay_gen.py can generate parsable replay files.
'''
# @file
#
# Copyright 2020, Verizon Media
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
client = r.AddClientProcess("client1", replay_gen.Variables.replay_dir,
                            https_ports=[8082], other_args="--verbose diag")
server = r.AddServerProcess("server1", replay_gen.Variables.replay_dir,
                            https_ports=[8083], other_args="--verbose diag")
proxy = r.AddProxyProcess("proxy1", listen_port=8082, server_port=8083)

client.Streams.stdout += Testers.ContainsExpression(
        "Parsed 20 transactions",
        "Verify that the verifier client was able to parse the expected 20 transactions.")

server.Streams.stdout += Testers.ContainsExpression(
        "Ready with 20 transactions",
        "Verify that the verifier server was able to parse the expected 20 transactions.")
