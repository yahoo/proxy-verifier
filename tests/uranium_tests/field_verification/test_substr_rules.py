'''
Verify correct field verification behavior for contains, prefix, and suffix.
'''
# @file
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

#
# Test 1: Verify field verification in a YAML replay file.
#
case = suite.case("Verify field verification works for a simple HTTP transaction")
client = case.add_client("client1", "replay_files/substr_rules.yaml")
server = case.add_server("server1", "replay_files/substr_rules.yaml")
proxy = case.add_proxy("proxy1", listen_port=client.http_port, server_port=server.http_port)

server.stdout.contains(
    'Contains Success: Key: "5", Field Name: "host", Required Value: "le.on", Value: "example.one"',
    'Validation should be happy that "le.on" is in "example.one".')

server.stdout.contains(
    'Prefix Success: Key: "5", Field Name: "x-test-request", Required Value: "Req", Value: "RequestData"',
    'Validation should be happy that "RequestData" began with "Req".')

server.stdout.contains(
    'Suffix Success: Key: "5", Field Name: "x-test-present", Required Value: "there", Value: "It\'s there"',
    'Validation should be happy that "It\'s there" ended with "there.')

server.stdout.contains(
    'Contains Violation: Not Found. Key: "5", Field Name: "host", Required Value: "two", Actual Value: "example.one"',
    'Validation should complain that "two" is not in "example.one".')

server.stdout.contains(
    'Prefix Violation: Not Found. Key: "5", Field Name: "x-test-request", Required Value: "equest", Actual Value: "RequestData"',
    'Validation should complain that "RequestData" did not begin with "equest".')

server.stdout.contains(
    'Suffix Violation: Not Found. Key: "5", Field Name: "x-test-present", Required Value: "er", Actual Value: "It\'s there"',
    'Validation should complain that "It\'s there" did not end with "er".')

client.stdout.contains(
    'Contains Success: Key: "5", Field Name: "content-type", Required Value: "html", Value: "text/html"',
    'Validation should be happy that "html" is in "text/html".')

client.stdout.contains(
    'Contains Violation: Not Found. Key: "5", Field Name: "set-cookie", Required Value: "ABCDE", Actual Value: "ABCD"',
    'Validation should complain that "ABCDE" is not in "ABCD".')

client.stdout.contains(
    'Prefix Violation: Absent. Key: "5", Field Name: "x-not-a-header", Required Value: "Whatever"',
    'Validation should complain that "X-Not-A-Header" is missing.')

client.stdout.contains(
    'Contains Violation: Absent. Key: "5", Field Name: "x-does-not-exist", Required Value: "NotHere"',
    'Validation should complain that "X-Does-Not-Exist" is missing.')

client.stdout.contains(
    'Suffix Violation: Absent. Key: "5", Field Name: "x-does-not-exist", Required Value: "NotHere"',
    'Validation should complain that "X-Does-Not-Exist" is missing.')

client.expect_return_codes(1)
server.expect_return_codes(1)

#
# Test 2: Verify substring rules run against the RFC-combined value for repeated field lines.
#
case = suite.case("Verify substring field verification works for repeated RFC-combinable fields")
client = case.add_client("client2", "replay_files/substr_rules_duplicate.yaml")
server = case.add_server("server2", "replay_files/substr_rules_duplicate.yaml")
proxy = case.add_proxy("proxy2", listen_port=client.http_port, server_port=server.http_port)

server.stdout.contains(
    'Contains Success: Key: "1", Field Name: "x-test-contains", Required Value: "alpha, beta", Value: "alpha, beta"',
    'Validation should be happy that repeated field lines are combined before contains checks.')

server.stdout.contains(
    'Contains Violation: Not Found. Key: "1", Field Name: "x-test-contains", Required Value: "gamma", Actual Value: "alpha, beta"',
    'Validation should complain that the combined field value does not contain "gamma".')

server.stdout.contains(
    'Prefix Success: Key: "1", Field Name: "x-test-prefix", Required Value: "start, e", Value: "start, end"',
    'Validation should be happy that prefix checks use the combined field value.')

server.stdout.contains(
    'Prefix Violation: Not Found. Key: "1", Field Name: "x-test-prefix", Required Value: "end", Actual Value: "start, end"',
    'Validation should complain that the combined field value does not begin with "end".')

server.stdout.contains(
    'Suffix Success: Key: "1", Field Name: "x-test-suffix", Required Value: "right", Value: "left, right"',
    'Validation should be happy that suffix checks use the combined field value.')

server.stdout.contains(
    'Suffix Violation: Not Found. Key: "1", Field Name: "x-test-suffix", Required Value: "left", Actual Value: "left, right"',
    'Validation should complain that the combined field value does not end with "left".')

client.expect_return_codes(0)
server.expect_return_codes(1)

#
# Test 3: Verify field verification using the map specification syntax.
#
case = suite.case("Verify field verification works with the map specification syntax")
client = case.add_client("client3", "replay_files/map_specification.yaml")
server = case.add_server("server3", "replay_files/map_specification.yaml")
proxy = case.add_proxy("proxy3", listen_port=client.http_port, server_port=server.http_port)

server.stdout.contains(
    'Contains Success: Key: "13", Field Name: "host", Required Value: "le.on", Value: "example.one"',
    'Validation should be happy that "le.on" is in "example.one".')

server.stdout.contains(
    'Prefix Success: Key: "13", Field Name: "x-test-request", Required Value: "Req", Value: "RequestData"',
    'Validation should be happy that "RequestData" began with "Req".')

server.stdout.contains(
    'Suffix Success: Key: "13", Field Name: "x-test-present", Required Value: "there", Value: "It\'s there"',
    'Validation should be happy that "It\'s there" ended with "there.')

server.stdout.contains(
    'Contains Violation: Not Found. Key: "13", Field Name: "host", Required Value: "two", Actual Value: "example.one"',
    'Validation should complain that "two" is not in "example.one".')

server.stdout.contains(
    'Prefix Violation: Not Found. Key: "13", Field Name: "x-test-request", Required Value: "equest", Actual Value: "RequestData"',
    'Validation should complain that "RequestData" did not begin with "equest".')

server.stdout.contains(
    'Suffix Violation: Not Found. Key: "13", Field Name: "x-test-present", Required Value: "er", Actual Value: "It\'s there"',
    'Validation should complain that "It\'s there" did not end with "er".')

server.stdout.contains('Absence Success: Key: "13", Field Name: "x-test-absent"',
                       'Validation should be happy that "X-Test-Absent" is not there.')

server.stdout.contains(
    'Presence Success: Key: "13", Field Name: "x-test-present", Value: "It\'s there"',
    'Validation should be happy that "X-Test-Present" is there.')

client.stdout.contains(
    'Contains Success: Key: "13", Field Name: "content-type", Required Value: "html", Value: "text/html"',
    'Validation should be happy that "html" is in "text/html".')

client.stdout.contains(
    'Contains Violation: Not Found. Key: "13", Field Name: "set-cookie", Required Value: "ABCDE", Actual Value: "ABCD"',
    'Validation should complain that "ABCDE" is not in "ABCD".')

client.stdout.contains(
    'Prefix Violation: Absent. Key: "13", Field Name: "x-not-a-header", Required Value: "Whatever"',
    'Validation should complain that "X-Not-A-Header" is missing.')

client.stdout.contains(
    'Contains Violation: Absent. Key: "13", Field Name: "x-does-not-exist", Required Value: "NotHere"',
    'Validation should complain that "X-Does-Not-Exist" is missing.')

client.stdout.contains(
    'Suffix Violation: Absent. Key: "13", Field Name: "x-does-not-exist", Required Value: "NotHere"',
    'Validation should complain that "X-Does-Not-Exist" is missing.')

client.expect_return_codes(1)
server.expect_return_codes(1)


def test_uranium_suite(uranium):
    uranium.run(suite)
