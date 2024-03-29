'''
Verify --format argument parsing.
'''
# @file
#
# Copyright 2022, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#


Test.Summary = '''
Verify --format argument parsing.
'''

#
# Test 1: Test with the URL as a key. This is not unique across transactions,
# so only one transaction will be registered.
#
r = Test.AddTestRun('--format "{url}" against transactions unique by Host')
client = r.AddClientProcess("client1", "unique_by_host.yaml",
                            other_args="--format '{url}'")
server = r.AddServerProcess("server1", "unique_by_host.yaml",
                            other_args="--format '{url}'")
proxy = r.AddProxyProcess("proxy1", listen_port=client.Variables.http_port,
                          server_port=server.Variables.http_port)

# The client will always see each transaction as unique and will send them as
# such. It does not record keys to detect duplicates, it just stores
# transactions in a list.
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
    "Ready with 1 transaction",
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
client = r.AddClientProcess("client2", "unique_by_host.yaml",
                            other_args="--format '{field.host}'")
server = r.AddServerProcess("server2", "unique_by_host.yaml",
                            other_args="--format '{field.host}'")
proxy = r.AddProxyProcess("proxy2", listen_port=client.Variables.http_port,
                          server_port=server.Variables.http_port)

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
client = r.AddClientProcess("client3", "unique_by_host.yaml",
                            other_args="--format '{field.host}/{url}'")
server = r.AddServerProcess("server3", "unique_by_host.yaml",
                            other_args="--format '{field.host}/{url}'")
proxy = r.AddProxyProcess("proxy3", listen_port=client.Variables.http_port,
                          server_port=server.Variables.http_port)

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

#
# Test 4: Verify that the client detects when a key is not present in a
# transaction.
#
r = Test.AddTestRun('Verify that the client detects a non-existent key')
client = r.AddClientProcess("client4", "no_uuid.yaml")

# The client will give a non-zero return code because it found a transaction
# without a key.
client.ReturnCode = 1
client.Streams.stdout += Testers.ContainsExpression(
    'Could not find a key of format "{field.uuid}" for transaction',
    "There should be a parsing warning that a key was not found for a transaction.")

#
# Test 5: Verify that the server detects when a key is not present in a
# transaction.
#
r = Test.AddTestRun('Verify that the server detects a non-existent key')
server = r.AddDefaultServerProcess("server5", "no_uuid.yaml")

# The server will give a non-zero return code because it found a transaction
# without a key.
server.ReturnCode = 1
server.Streams.stdout += Testers.ContainsExpression(
    'Could not find a key of format "{field.uuid}" for transaction',
    "There should be a parsing warning that a key was not found for a transaction.")

#
# Test 6: Verify that the server returns a 404 for an unrecognized key.
#
r = Test.AddTestRun('Verify a 404 response for an unrecognized key')
client = r.AddClientProcess("client6", "uuid1.yaml")

# Notice that the server will be configured to recognize uuid 2, not 1. So when
# a request with uuid 1 is received, it will not recognize it and should return
# a 404 (Not Found).
server = r.AddServerProcess("server6", "uuid2.yaml")
proxy = r.AddProxyProcess("proxy6", listen_port=client.Variables.http_port,
                          server_port=server.Variables.http_port)

server.ReturnCode = 1

client.Streams.stdout += Testers.ContainsExpression(
    'Received an HTTP/1 404 response',
    "The client should receive a 404 response for an unrecognized key.")
server.Streams.stdout += Testers.ContainsExpression(
    'sending a 404',
    "The server should send a 404 response for an unrecognized key.")

#
# Test 7: Verify that --format "{url}" can successfully differentiate
# transactions that are only unique by URL.
#
r = Test.AddTestRun('--format "{url}" against transactions unique by URL')
client = r.AddClientProcess("client7", "unique_by_url.yaml",
                            other_args="--format '{url}'")
server = r.AddServerProcess("server7", "unique_by_url.yaml",
                            other_args="--format '{url}'")
proxy = r.AddProxyProcess("proxy7", listen_port=client.Variables.http_port,
                          server_port=server.Variables.http_port)

client.Streams.stdout += Testers.ContainsExpression(
    "Parsed 3 transactions",
    "Three transactions should be parsed by the client.")

server.Streams.stdout += Testers.ContainsExpression(
    "Ready with 3 transactions",
    "Three transactions should be parsed by the server.")
