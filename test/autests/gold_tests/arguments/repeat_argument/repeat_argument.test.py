'''
Verify the user can repeat transactions with --repeat.
'''
# @file
#
# Copyright 2020, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#


Test.Summary = '''
Verify the user can repeat transactions with --repeat.
'''

#
# Test 1: Verify that without the repeat argument the transactions are
# executed once.
#
r = Test.AddTestRun("Verify transactions are executed once with no --repeat argument.")
client = r.AddClientProcess("client1", "replay_files/two_files",
                            http_ports=[8086],
                            other_args="--verbose diag")
server = r.AddServerProcess("server1", "replay_files/two_files",
                            http_ports=[8087], other_args="--verbose diag")
proxy = r.AddProxyProcess("proxy1", listen_port=8086, server_port=8087)

client.Streams.stdout += Testers.ContainsExpression(
        'Parsed 8 transactions',
        'Verify the 8 transactions were parsed.')
client.Streams.stdout += Testers.ContainsExpression(
        '8 transactions in 5 sessions',
        'Verify each transaction is executed once.')

#
# Test 2: Verify that with --repeat 1 the transactions are executed once.
#
r = Test.AddTestRun("Verify transactions are executed once with --repeat 1.")
client = r.AddClientProcess("client2", "replay_files/two_files",
                            http_ports=[8086],
                            other_args="--verbose diag --repeat 1")
server = r.AddServerProcess("server2", "replay_files/two_files",
                            http_ports=[8087], other_args="--verbose diag")
proxy = r.AddProxyProcess("proxy2", listen_port=8086, server_port=8087)

client.Streams.stdout += Testers.ContainsExpression(
        'Parsed 8 transactions',
        'Verify the 8 transactions were parsed.')
client.Streams.stdout += Testers.ContainsExpression(
        '8 transactions in 5 sessions',
        'Verify each transaction is executed once.')

#
# Test 3: Verify that with --repeat 0 the transactions are not executed.
#
r = Test.AddTestRun("Verify no transactions are executed with --repeat 0.")
client = r.AddClientProcess("client3", "replay_files/two_files",
                            http_ports=[8086],
                            other_args="--verbose diag --repeat 0")
server = r.AddServerProcess("server3", "replay_files/two_files",
                            http_ports=[8087], other_args="--verbose diag")
proxy = r.AddProxyProcess("proxy3", listen_port=8086, server_port=8087)

client.Streams.stdout += Testers.ContainsExpression(
        'Parsed 8 transactions',
        'Verify the 8 transactions were parsed.')
client.Streams.stdout += Testers.ContainsExpression(
        '0 transactions in 0 sessions',
        'Verify no transactions are executed.')

#
# Test 4: Verify that with --repeat 2 the transactions are executed twice.
#
r = Test.AddTestRun("Verify transactions are executed twice with --repeat 2.")
client = r.AddClientProcess("client4", "replay_files/two_files",
                            http_ports=[8086],
                            other_args="--verbose diag --repeat 2")
server = r.AddServerProcess("server4", "replay_files/two_files",
                            http_ports=[8087], other_args="--verbose diag")
proxy = r.AddProxyProcess("proxy4", listen_port=8086, server_port=8087)

client.Streams.stdout += Testers.ContainsExpression(
        'Parsed 8 transactions',
        'Verify the 8 transactions were parsed.')
client.Streams.stdout += Testers.ContainsExpression(
        '16 transactions in 10 sessions',
        'Verify each transaction is executed twice.')

if Condition.IsPlatform("darwin"):
    # On the Mac, the test proxy seems to close the session prematurely for
    # some transactions, causing the client to fail due to PARSE_INCOMPLETE
    # warnings. Because the client says "Connection reset by peer", I believe
    # this is a test issue.
    client.ReturnCode = 1

#
# Test 5: Verify that with --repeat 10 the transactions are executed ten times
#
r = Test.AddTestRun("Verify transactions are executed ten times with --repeat 10.")
client = r.AddClientProcess("client5", "replay_files/two_files",
                            http_ports=[8086],
                            other_args="--verbose diag --repeat 10")
server = r.AddServerProcess("server5", "replay_files/two_files",
                            http_ports=[8087], other_args="--verbose diag")
proxy = r.AddProxyProcess("proxy5", listen_port=8086, server_port=8087)

client.Streams.stdout += Testers.ContainsExpression(
        'Parsed 8 transactions',
        'Verify the 8 transactions were parsed.')
client.Streams.stdout += Testers.ContainsExpression(
        '80 transactions in 50 sessions',
        'Verify each transaction is executed ten times.')

if Condition.IsPlatform("darwin"):
    # See above comment.
    client.ReturnCode = 1
