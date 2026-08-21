'''
Verify the user can repeat transactions with --repeat.
'''
# @file
#
# Copyright 2021-2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite, is_platform

suite = CaseSuite(__file__)
#

#
# Test 1: Verify that without the repeat argument the transactions are
# executed once.
#
case = suite.case("Verify transactions are executed once with no --repeat argument.")
client = case.add_client("client1", "replay_files/two_files")
server = case.add_server("server1", "replay_files/two_files")
proxy = case.add_proxy("proxy1", listen_port=client.http_port, server_port=server.http_port)

client.stdout.contains('Parsed 8 transactions', 'Verify the 8 transactions were parsed.')
client.stdout.contains('8 transactions in 5 sessions', 'Verify each transaction is executed once.')

#
# Test 2: Verify that with --repeat 1 the transactions are executed once.
#
case = suite.case("Verify transactions are executed once with --repeat 1.")
client = case.add_client("client2", "replay_files/two_files", other_args="--repeat 1")
server = case.add_server("server2", "replay_files/two_files")
proxy = case.add_proxy("proxy2", listen_port=client.http_port, server_port=server.http_port)

client.stdout.contains('Parsed 8 transactions', 'Verify the 8 transactions were parsed.')
client.stdout.contains('8 transactions in 5 sessions', 'Verify each transaction is executed once.')

#
# Test 3: Verify that with --repeat 0 the transactions are not executed.
#
case = suite.case("Verify no transactions are executed with --repeat 0.")
client = case.add_client("client3", "replay_files/two_files", other_args="--repeat 0")
server = case.add_server("server3", "replay_files/two_files")
proxy = case.add_proxy("proxy3", listen_port=client.http_port, server_port=server.http_port)

client.stdout.contains('Parsed 8 transactions', 'Verify the 8 transactions were parsed.')
client.stdout.contains('0 transactions in 0 sessions', 'Verify no transactions are executed.')

#
# Test 4: Verify that with --repeat 2 the transactions are executed twice.
#
case = suite.case("Verify transactions are executed twice with --repeat 2.")
client = case.add_client("client4", "replay_files/two_files", other_args="--repeat 2")
server = case.add_server("server4", "replay_files/two_files")
proxy = case.add_proxy("proxy4", listen_port=client.http_port, server_port=server.http_port)

client.stdout.contains('Parsed 8 transactions', 'Verify the 8 transactions were parsed.')
client.stdout.contains('16 transactions in 10 sessions',
                       'Verify each transaction is executed twice.')

if is_platform("darwin"):
    # On the Mac, the test proxy closes the session prematurely for some
    # transactions, causing the client to fail due to PARSE_INCOMPLETE
    # warnings. This can be observed in packet captures of the running test
    # (the proxy does indeed send RESET responses after the request comes in)
    # and from the client output which says "Connection reset by peer". I've
    # spent some time trying to get the Python server to not close the
    # connections prematurely on Mac but have not been able to get it to work
    # yet.  The client does indeed send the desired number of transactions, as
    # verified with the above stdout Testers, so this test is nevertheless
    # helpful despite the annoying test proxy behavior. For now we'll just
    # ignore the return code.
    client.expect_return_codes(0, 1)

#
# Test 5: Verify that with --repeat 10 the transactions are executed ten times
#
case = suite.case("Verify transactions are executed ten times with --repeat 10.")
client = case.add_client("client5", "replay_files/two_files", other_args="--repeat 10")
server = case.add_server("server5", "replay_files/two_files")
proxy = case.add_proxy("proxy5", listen_port=client.http_port, server_port=server.http_port)

client.stdout.contains('Parsed 8 transactions', 'Verify the 8 transactions were parsed.')
client.stdout.contains('80 transactions in 50 sessions',
                       'Verify each transaction is executed ten times.')

if is_platform("darwin"):
    # See above comment.
    client.expect_return_codes(0, 1)


def test_uranium_suite(uranium):
    uranium.run(suite)
