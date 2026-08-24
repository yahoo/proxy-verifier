'''
Verify correct field and URL verification behavior
for not and nocase modifiers.
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
# Each combinaton of test type, not/as, and case/nocase, and positive/negative result
# are tested for client, and a mixture for server
#
case = suite.case("Verify 'not' and 'nocase' directives work for a single HTTP transaction")
client = case.add_client("client1", "replay_files/not_nocase.yaml")
server = case.add_server("server1", "replay_files/not_nocase.yaml")
proxy = case.add_proxy("proxy1", listen_port=client.http_port, server_port=server.http_port)

server.stdout.contains(
    'Not Equals Success: Different. Key: "5", Field Name: "host", Correct Value: "le.on", Actual Value: "example.one"',
    'Validation should be happy that "le.on" is not equal to "example.one".')

server.stdout.contains('Not Presence Success: Absent. Key: "5", Field Name: "x-test-absent"',
                       'Validation should be happy that "X-Test-Absent" has no value.')

server.stdout.contains(
    'Not Absence Success: Present. Key: "5", Field Name: "x-test-present", Value: "It\'s there"',
    'Validation should be happy that "X-Test-Present" has a value.')

server.stdout.contains(
    'Not Contains Success: Not Found. Key: "5", Field Name: "host", Required Missing Value: "leo", Actual Value: "example.one"',
    'Validation should be happy that "leo" is not contained in "example.one".')

server.stdout.contains(
    'Not Contains Success: Not Found. Key: "5", Field Name: "cookie", Required Missing Value: "12345678", Actual Value: "foo=bar"',
    'Validation should be happy that a longer required substring is treated as not found.')

server.stdout.contains(
    'Not Prefix Success: Not Found. Key: "5", Field Name: "x-test-request", Required Missing Value: "equ", Actual Value: "RequestData"',
    'Validation should be happy that "equ" does not prefix "RequestData".')

server.stdout.contains(
    'Not Suffix Success: Not Found. Key: "5", Field Name: "x-test-present", Required Missing Value: "It\'s", Actual Value: "It\'s there"',
    'Validation should be happy that "It\'s" does not suffix "It\'s there".')

server.stdout.contains(
    'No Case Equals Success: Key: "5", Field Name: "host", Required Value: "EXAMpLE.ONE", Value: "example.one"',
    'Validation should be happy that "EXAMpLE.ONE" nocase equals "example.one".')

server.stdout.contains(
    'No Case Contains Success: Key: "5", Field Name: "host", Required Value: "Le.ON", Value: "example.one"',
    'Validation should be happy that "Le.ON" is nocase contained in "example.one".')

server.stdout.contains(
    'No Case Prefix Success: Key: "5", Field Name: "x-test-request", Required Value: "rEQ", Value: "RequestData"',
    'Validation should be happy that "rEQ" nocase prefixes "RequestData".')

server.stdout.contains(
    'No Case Suffix Success: Key: "5", Field Name: "x-test-present", Required Value: "heRe", Value: "It\'s there"',
    'Validation should be happy that "heRe" nocase suffixes "It\'s there".')

server.stdout.contains(
    'Not No Case Equals Success: Different. Key: "5", Field Name: "host", Correct Value: "example.ON", Actual Value: "example.one"',
    'Validation should be happy that "le.on" does not nocase equal "example.one".')

server.stdout.contains(
    'Not No Case Contains Success: Not Found. Key: "5", Field Name: "host", Required Missing Value: "U", Actual Value: "example.one"',
    'Validation should be happy that "leo" is not nocase contained in "example.one".')

server.stdout.contains(
    'Not No Case Prefix Success: Not Found. Key: "5", Field Name: "x-test-request", Required Missing Value: "EQU", Actual Value: "RequestData"',
    'Validation should be happy that "equ" does not nocase prefix "RequestData".')

server.stdout.contains(
    'Not No Case Suffix Success: Not Found. Key: "5", Field Name: "x-test-present", Required Missing Value: "hre", Actual Value: "It\'s there"',
    'Validation should be happy that "hre" does not nocase suffix "It\'s there".')

server.stdout.contains('Not Equals Violation: Key: "5", Field Name: "host", Value: "example.one"',
                       'Validation should complain that "example.on" equals "example.one".')

server.stdout.contains(
    'Not Presence Violation: Key: "5", Field Name: "x-test-present", Value: "It\'s there"',
    'Validation should complain that "X-Test-Present" has a value.')

server.stdout.contains('Not Absence Violation: Key: "5", Field Name: "x-test-absent"',
                       'Validation should complain that "X-Test-Absent" has no value.')

server.stdout.contains(
    'Not Contains Violation: Key: "5", Field Name: "host", Required Missing Value: "le.on", Value: "example.one"',
    'Validation should complain that "le.on" is contained in "example.one".')

server.stdout.contains(
    'Not Prefix Violation: Key: "5", Field Name: "x-test-request", Required Missing Value: "Req", Value: "RequestData"',
    'Validation should complain that "Req" prefixes "RequestData".')

server.stdout.contains(
    'Not Suffix Violation: Key: "5", Field Name: "x-test-present", Required Missing Value: "there", Value: "It\'s there"',
    'Validation should complain that "there" suffixes "It\'s there".')

server.stdout.contains(
    'No Case Equals Violation: Different. Key: "5", Field Name: "host", Correct Value: "EXAMPLE.ON", Actual Value: "example.one"',
    'Validation should complain that "EXAMPL.ON" does not nocase equal "example.one".')

server.stdout.contains(
    'No Case Contains Violation: Not Found. Key: "5", Field Name: "host", Required Value: "LE..On", Actual Value: "example.one"',
    'Validation should complain that "LE..On" is not nocase contained in "example.one".')

server.stdout.contains(
    'No Case Prefix Violation: Not Found. Key: "5", Field Name: "x-test-request", Required Value: "-TE", Actual Value: "RequestData"',
    'Validation should complain that "-TE" does not nocase prefix "RequestData".')

server.stdout.contains(
    'No Case Suffix Violation: Not Found. Key: "5", Field Name: "x-test-present", Required Value: "THER", Actual Value: "It\'s there"',
    'Validation should complain that "THER" does not nocase suffix "It\'s there".')

server.stdout.contains(
    'Not No Case Equals Violation: Key: "5", Field Name: "host", Required Value: "Example.one", Value: "example.one"',
    'Validation should complain that "Example.one" nocase equals "example.one".')

server.stdout.contains(
    'Not No Case Contains Violation: Key: "5", Field Name: "host", Required Missing Value: "le.oN", Value: "example.one"',
    'Validation should complain that "le.oN" is nocase contained in "example.one".')

server.stdout.contains(
    'Not No Case Prefix Violation: Key: "5", Field Name: "x-test-request", Required Missing Value: "req", Value: "RequestData"',
    'Validation should complain that "req" nocase prefixes "RequestData".')

server.stdout.contains(
    'Not No Case Suffix Violation: Key: "5", Field Name: "x-test-present", Required Missing Value: "eRE", Value: "It\'s there"',
    'Validation should complain that "eRE" nocase suffixes "It\'s there".')

server.stdout.contains(
    'Not No Case Contains Violation: Key: "5", URI Part: "path", Required Missing Value: "iG/S", Value: "/config/settings.yaml"',
    'Validation should complain that "iG/S" is nocase contained in the path.')

client.stdout.contains(
    'Not Equals Success: Different. Key: "5", Field Name: "content-type", Correct Value: "text", Actual Value: "text/html"',
    'Validation should be happy that "text" does not equal "text/html".')

client.stdout.contains('Not Presence Violation: Key: "5", Field Name: "set-cookie", Value: "ABCD"',
                       'Validation should complain that "set-cookie" is present.')

client.stdout.contains('Not Absence Violation: Key: "5", Field Name: "fake-cookie"',
                       'Validation should complain that "fake-cookie" is absent.')

client.stdout.contains(
    'Not No Case Contains Violation: Key: "5", Field Name: "content-type", Required Missing Value: "Tex", Value: "text/html"',
    'Validation should complain that "Tex" is nocase contained in "text/html".')

client.stdout.contains(
    'Not No Case Prefix Success: Absent. Key: "5", Field Name: "fake-cookie", Required Missing Value: "B"',
    'Validation should be happy that "B" does not nocase prefix a nonexistent header.')

client.stdout.contains(
    'No Case Suffix Success: Key: "5", Field Name: "content-type", Required Value: "L", Value: "text/html"',
    'Validation should be happy that "L" nocase suffixes "text/html".')

client.stdout.contains(
    'Not Prefix Success: Not Found. Key: "5", Field Name: "multiple", Required Missing Value: "Abc, DEF", Actual Value: "abc, DEF"',
    'Validation should be happy that "Abc" does not prefix "abc", even though "DEF" prefixes "DEF".'
)

client.stdout.contains(
    'Not No Case Equals Violation: Key: "5", Field Name: "multiple", Required Value: "Abc, DEF", Value: "abc, DEF"',
    'Validation should complain that each required value nocase equals the corresponding received value.'
)

client.expect_return_codes(1)
server.expect_return_codes(1)


def test_uranium_suite(uranium):
    uranium.run(suite)
