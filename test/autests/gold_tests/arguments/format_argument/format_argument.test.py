'''
Verify --format argument parsing.
'''
# @file
#
# Copyright 2020, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#


Test.Summary = '''
Verify --format argument parsing.
'''

#
# Test 1: Test with the URL as a key. This is not unique across transactions,
# so only one transaction will be registered.
#
r = Test.AddTestRun('--format "{url}"')
client = r.AddClientProcess("client1", "replay_files/unique_by_host", http_ports=[8080],
                            other_args="--verbose diag --format '{url}'")
server = r.AddServerProcess("server1", "replay_files/unique_by_host", http_ports=[8081],
                            other_args="--verbose diag --format '{url}'")
proxy = r.AddProxyProcess("proxy1", listen_port=8080, server_port=8081)

# The client will see each transaction as unique and will send them as such.
client.Streams.stdout += Testers.ContainsExpression(
        "Parsed 3 transactions",
        "Three transactions should be parsed by the client.")

client.Streams.stdout += Testers.ContainsExpression(
        'Equals Violation: Different.*Actual Value: "first"',
        "The server will always reply with the first response.")

client.Streams.stdout += Testers.ContainsExpression(
        'Key: "/same/path"',
        "The key should be parsed from the URL, not the uuid.")

# The server, however, uses the key which, since we're using the URL which is
# the same across transactions, will only register the first transaction.
server.Streams.stdout += Testers.ContainsExpression(
        'Correct Value: "first", Actual Value: "second"',
        "The second transaction should come up as a violation.")

server.Streams.stdout += Testers.ContainsExpression(
        'Correct Value: "first", Actual Value: "third"',
        "The third transaction should come up as a violation.")

server.Streams.stdout += Testers.ContainsExpression(
        "Ready with 1 transactions",
        "Only one transaction should be parsed by the server.")

server.Streams.stdout += Testers.ContainsExpression(
        'Key: "/same/path"',
        "The key should be parsed from the URL, not the uuid.")

client.ReturnCode = 1
server.ReturnCode = 1

#
# Test 2: Verify using the host as a key, which is unique across transactions.
#
r = Test.AddTestRun('--format "{field.host}"')
client = r.AddClientProcess("client2", "replay_files/unique_by_host", http_ports=[8080],
                            other_args="--verbose diag --format '{field.host}'")
server = r.AddServerProcess("server2", "replay_files/unique_by_host", http_ports=[8081],
                            other_args="--verbose diag --format '{field.host}'")
proxy = r.AddProxyProcess("proxy2", listen_port=8080, server_port=8081)

client.Streams.stdout += Testers.ContainsExpression(
        "Parsed 3 transactions",
        "Three transactions should be parsed by the client.")

client.Streams.stdout += Testers.ExcludesExpression(
        "Violation:",
        "There should be no verification errors because there are none added.")

client.Streams.stdout += Testers.ContainsExpression(
        'Key: "host.one"',
        "The key should be parsed from the host, not the uuid.")

server.Streams.stdout += Testers.ExcludesExpression(
        "Violation:",
        "There should be no verification errors because there are none added.")

server.Streams.stdout += Testers.ContainsExpression(
        "Ready with 3 transactions",
        "Three transactions should be parsed by the server.")

server.Streams.stdout += Testers.ContainsExpression(
        'Key: "host.one"',
        "The key should be parsed from the host, not the uuid.")

#
# Test 3: Use a more complicated key made up of two specifiers.
#
r = Test.AddTestRun('--format "{field.host}/{url}"')
client = r.AddClientProcess("client3", "replay_files/unique_by_host", http_ports=[8080],
                            other_args="--verbose diag --format '{field.host}/{url}'")
server = r.AddServerProcess("server3", "replay_files/unique_by_host", http_ports=[8081],
                            other_args="--verbose diag --format '{field.host}/{url}'")
proxy = r.AddProxyProcess("proxy3", listen_port=8080, server_port=8081)

client.Streams.stdout += Testers.ContainsExpression(
        "Parsed 3 transactions",
        "Three transactions should be parsed by the client.")

client.Streams.stdout += Testers.ExcludesExpression(
        "Violation:",
        "There should be no verification errors because there are none added.")

client.Streams.stdout += Testers.ContainsExpression(
        'Key: "host.one//same/path"',
        "The key should be parsed from the host/url, not the uuid.")

server.Streams.stdout += Testers.ExcludesExpression(
        "Violation:",
        "There should be no verification errors because there are none added.")

server.Streams.stdout += Testers.ContainsExpression(
        "Ready with 3 transactions",
        "Three transactions should be parsed by the server.")

server.Streams.stdout += Testers.ContainsExpression(
        'Key: "host.one//same/path"',
        "The key should be parsed from the host/url, not the uuid.")
