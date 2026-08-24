'''
Verify --format argument parsing.
'''
# @file
#
# Copyright 2022-2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

#
# Test 1: Test with the URL as a key. This is not unique across transactions,
# so only one transaction will be registered.
#
case = suite.case('--format "{url}" against transactions unique by Host')
client = case.add_client("client1", "unique_by_host.yaml", other_args="--format '{url}'")
server = case.add_server("server1", "unique_by_host.yaml", other_args="--format '{url}'")
proxy = case.add_proxy("proxy1", listen_port=client.http_port, server_port=server.http_port)

# The client will always see each transaction as unique and will send them as
# such. It does not record keys to detect duplicates, it just stores
# transactions in a list.
client.stdout.contains("Parsed 3 transactions",
                       "Three transactions should be parsed by the client.")

client.stdout.contains('Equals Violation: Different.*Actual Value: "first"',
                       "The server will always reply with the first response.")

client.stdout.contains('Key: "/same/path"', "The key should be parsed from the URL, not the uuid.")

# The server, however, uses the key which, since we're using the URL which is
# the same across transactions, will only register the first transaction.
server.stdout.contains('Correct Value: "first", Actual Value: "second"',
                       "The second transaction should come up as a violation.")

server.stdout.contains('Correct Value: "first", Actual Value: "third"',
                       "The third transaction should come up as a violation.")

server.stdout.contains("Ready with 1 transaction",
                       "Only one transaction should be parsed by the server.")

server.stdout.contains('Key: "/same/path"', "The key should be parsed from the URL, not the uuid.")

client.expect_return_codes(1)
server.expect_return_codes(1)

#
# Test 2: Verify using the host as a key, which is unique across transactions.
#
case = suite.case('--format "{field.host}"')
client = case.add_client("client2", "unique_by_host.yaml", other_args="--format '{field.host}'")
server = case.add_server("server2", "unique_by_host.yaml", other_args="--format '{field.host}'")
proxy = case.add_proxy("proxy2", listen_port=client.http_port, server_port=server.http_port)

client.stdout.contains("Parsed 3 transactions",
                       "Three transactions should be parsed by the client.")

client.stdout.excludes("Violation:",
                       "There should be no verification errors because there are none added.")

client.stdout.contains('Key: "host.one"', "The key should be parsed from the host, not the uuid.")

server.stdout.excludes("Violation:",
                       "There should be no verification errors because there are none added.")

server.stdout.contains("Ready with 3 transactions",
                       "Three transactions should be parsed by the server.")

server.stdout.contains('Key: "host.one"', "The key should be parsed from the host, not the uuid.")

#
# Test 3: Use a more complicated key made up of two specifiers.
#
case = suite.case('--format "{field.host}/{url}"')
client = case.add_client("client3", "unique_by_host.yaml",
                         other_args="--format '{field.host}/{url}'")
server = case.add_server("server3", "unique_by_host.yaml",
                         other_args="--format '{field.host}/{url}'")
proxy = case.add_proxy("proxy3", listen_port=client.http_port, server_port=server.http_port)

client.stdout.contains("Parsed 3 transactions",
                       "Three transactions should be parsed by the client.")

client.stdout.excludes("Violation:",
                       "There should be no verification errors because there are none added.")

client.stdout.contains('Key: "host.one//same/path"',
                       "The key should be parsed from the host/url, not the uuid.")

server.stdout.excludes("Violation:",
                       "There should be no verification errors because there are none added.")

server.stdout.contains("Ready with 3 transactions",
                       "Three transactions should be parsed by the server.")

server.stdout.contains('Key: "host.one//same/path"',
                       "The key should be parsed from the host/url, not the uuid.")

#
# Test 4: Verify that the client detects when a key is not present in a
# transaction.
#
case = suite.case('Verify that the client detects a non-existent key')
client = case.add_client("client4", "no_uuid.yaml")

# The client will give a non-zero return code because it found a transaction
# without a key.
client.expect_return_codes(1)
client.stdout.contains(
    'Could not find a key of format "{field.uuid}" for transaction',
    "There should be a parsing warning that a key was not found for a transaction.")

#
# Test 5: Verify that the server detects when a key is not present in a
# transaction.
#
case = suite.case('Verify that the server detects a non-existent key')
server = case.add_server("server5", "no_uuid.yaml")

# The server will give a non-zero return code because it found a transaction
# without a key.
server.expect_return_codes(1)
server.stdout.contains(
    'Could not find a key of format "{field.uuid}" for transaction',
    "There should be a parsing warning that a key was not found for a transaction.")

#
# Test 6: Verify that the server returns a 404 for an unrecognized key.
#
case = suite.case('Verify a 404 response for an unrecognized key')
client = case.add_client("client6", "uuid1.yaml")

# Notice that the server will be configured to recognize uuid 2, not 1. So when
# a request with uuid 1 is received, it will not recognize it and should return
# a 404 (Not Found).
server = case.add_server("server6", "uuid2.yaml")
proxy = case.add_proxy("proxy6", listen_port=client.http_port, server_port=server.http_port)

server.expect_return_codes(1)

client.stdout.contains('Received an HTTP/1 404 response',
                       "The client should receive a 404 response for an unrecognized key.")
server.stdout.contains('sending a 404',
                       "The server should send a 404 response for an unrecognized key.")

#
# Test 7: Verify that --format "{url}" can successfully differentiate
# transactions that are only unique by URL.
#
case = suite.case('--format "{url}" against transactions unique by URL')
client = case.add_client("client7", "unique_by_url.yaml", other_args="--format '{url}'")
server = case.add_server("server7", "unique_by_url.yaml", other_args="--format '{url}'")
proxy = case.add_proxy("proxy7", listen_port=client.http_port, server_port=server.http_port)

client.stdout.contains("Parsed 3 transactions",
                       "Three transactions should be parsed by the client.")

server.stdout.contains("Ready with 3 transactions",
                       "Three transactions should be parsed by the server.")


def test_uranium_suite(uranium):
    uranium.run(suite)
