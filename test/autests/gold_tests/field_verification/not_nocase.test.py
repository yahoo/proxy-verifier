'''
Verify correct field and URL verification behavior
for not and nocase modifiers.
'''
# @file
#
# Copyright 2021, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#


Test.Summary = '''
Verify correct field and URL verification behavior for
equals, absent, present, contains, prefix, and suffix
with not, nocase, and both not and nocase modifiers
'''

#
# Test 1: Verify field verification in a YAML replay file.
# Each combinaton of test type, not/as, and case/nocase, and positive/negative result
# are tested for client, and a mixture for server
#
r = Test.AddTestRun("Verify 'not' and 'nocase' directives work for a single HTTP transaction")
client = r.AddClientProcess("client1", "replay_files/not_nocase.yaml")
server = r.AddServerProcess("server1", "replay_files/not_nocase.yaml")
proxy = r.AddProxyProcess(
    "proxy1",
    listen_port=client.Variables.http_port,
    server_port=server.Variables.http_port)

server.Streams.stdout += Testers.ContainsExpression(
    'Not Equals Success: Different. Key: "5", Field Name: "host", Correct Value: "le.on", Actual Value: "example.one"',
    'Validation should be happy that "le.on" is not equal to "example.one".')

server.Streams.stdout += Testers.ContainsExpression(
    'Not Presence Success: Absent. Key: "5", Field Name: "x-test-absent"',
    'Validation should be happy that "X-Test-Absent" has no value.')

server.Streams.stdout += Testers.ContainsExpression(
    'Not Absence Success: Present. Key: "5", Field Name: "x-test-present", Value: "It\'s there"',
    'Validation should be happy that "X-Test-Present" has a value.')

server.Streams.stdout += Testers.ContainsExpression(
    'Not Contains Success: Not Found. Key: "5", Field Name: "host", Required Value: "leo", Actual Value: "example.one"',
    'Validation should be happy that "leo" is not contained in "example.one".')

server.Streams.stdout += Testers.ContainsExpression(
    'Not Prefix Success: Not Found. Key: "5", Field Name: "x-test-request", Required Value: "equ", Actual Value: "RequestData"',
    'Validation should be happy that "equ" does not prefix "RequestData".')

server.Streams.stdout += Testers.ContainsExpression(
    'Not Suffix Success: Not Found. Key: "5", Field Name: "x-test-present", Required Value: "It\'s", Actual Value: "It\'s there"',
    'Validation should be happy that "It\'s" does not suffix "It\'s there".')


server.Streams.stdout += Testers.ContainsExpression(
    'No Case Equals Success: Key: "5", Field Name: "host", Required Value: "EXAMpLE.ONE", Value: "example.one"',
    'Validation should be happy that "EXAMpLE.ONE" nocase equals "example.one".')

server.Streams.stdout += Testers.ContainsExpression(
    'No Case Contains Success: Key: "5", Field Name: "host", Required Value: "Le.ON", Value: "example.one"',
    'Validation should be happy that "Le.ON" is nocase contained in "example.one".')

server.Streams.stdout += Testers.ContainsExpression(
    'No Case Prefix Success: Key: "5", Field Name: "x-test-request", Required Value: "rEQ", Value: "RequestData"',
    'Validation should be happy that "rEQ" nocase prefixes "RequestData".')

server.Streams.stdout += Testers.ContainsExpression(
    'No Case Suffix Success: Key: "5", Field Name: "x-test-present", Required Value: "heRe", Value: "It\'s there"',
    'Validation should be happy that "heRe" nocase suffixes "It\'s there".')


server.Streams.stdout += Testers.ContainsExpression(
    'Not No Case Equals Success: Different. Key: "5", Field Name: "host", Correct Value: "example.ON", Actual Value: "example.one"',
    'Validation should be happy that "le.on" does not nocase equal "example.one".')

server.Streams.stdout += Testers.ContainsExpression(
    'Not No Case Contains Success: Not Found. Key: "5", Field Name: "host", Required Value: "U", Actual Value: "example.one"',
    'Validation should be happy that "leo" is not nocase contained in "example.one".')

server.Streams.stdout += Testers.ContainsExpression(
    'Not No Case Prefix Success: Not Found. Key: "5", Field Name: "x-test-request", Required Value: "EQU", Actual Value: "RequestData"',
    'Validation should be happy that "equ" does not nocase prefix "RequestData".')

server.Streams.stdout += Testers.ContainsExpression(
    'Not No Case Suffix Success: Not Found. Key: "5", Field Name: "x-test-present", Required Value: "hre", Actual Value: "It\'s there"',
    'Validation should be happy that "hre" does not nocase suffix "It\'s there".')


server.Streams.stdout += Testers.ContainsExpression(
    'Not Equals Violation: Key: "5", Field Name: "host", Value: "example.one"',
    'Validation should complain that "example.on" equals "example.one".')

server.Streams.stdout += Testers.ContainsExpression(
    'Not Presence Violation: Key: "5", Field Name: "x-test-present", Value: "It\'s there"',
    'Validation should complain that "X-Test-Present" has a value.')

server.Streams.stdout += Testers.ContainsExpression(
    'Not Absence Violation: Key: "5", Field Name: "x-test-absent"',
    'Validation should complain that "X-Test-Absent" has no value.')

server.Streams.stdout += Testers.ContainsExpression(
    'Not Contains Violation: Key: "5", Field Name: "host", Required Value: "le.on", Value: "example.one"',
    'Validation should complain that "le.on" is contained in "example.one".')

server.Streams.stdout += Testers.ContainsExpression(
    'Not Prefix Violation: Key: "5", Field Name: "x-test-request", Required Value: "Req", Value: "RequestData"',
    'Validation should complain that "Req" prefixes "RequestData".')

server.Streams.stdout += Testers.ContainsExpression(
    'Not Suffix Violation: Key: "5", Field Name: "x-test-present", Required Value: "there", Value: "It\'s there"',
    'Validation should complain that "there" suffixes "It\'s there".')


server.Streams.stdout += Testers.ContainsExpression(
    'No Case Equals Violation: Different. Key: "5", Field Name: "host", Correct Value: "EXAMPLE.ON", Actual Value: "example.one"',
    'Validation should complain that "EXAMPL.ON" does not nocase equal "example.one".')

server.Streams.stdout += Testers.ContainsExpression(
    'No Case Contains Violation: Not Found. Key: "5", Field Name: "host", Required Value: "LE..On", Actual Value: "example.one"',
    'Validation should complain that "LE..On" is not nocase contained in "example.one".')

server.Streams.stdout += Testers.ContainsExpression(
    'No Case Prefix Violation: Not Found. Key: "5", Field Name: "x-test-request", Required Value: "-TE", Actual Value: "RequestData"',
    'Validation should complain that "-TE" does not nocase prefix "RequestData".')

server.Streams.stdout += Testers.ContainsExpression(
    'No Case Suffix Violation: Not Found. Key: "5", Field Name: "x-test-present", Required Value: "THER", Actual Value: "It\'s there"',
    'Validation should complain that "THER" does not nocase suffix "It\'s there".')


server.Streams.stdout += Testers.ContainsExpression(
    'Not No Case Equals Violation: Key: "5", Field Name: "host", Required Value: "Example.one", Value: "example.one"',
    'Validation should complain that "Example.one" nocase equals "example.one".')

server.Streams.stdout += Testers.ContainsExpression(
    'Not No Case Contains Violation: Key: "5", Field Name: "host", Required Value: "le.oN", Value: "example.one"',
    'Validation should complain that "le.oN" is nocase contained in "example.one".')

server.Streams.stdout += Testers.ContainsExpression(
    'Not No Case Prefix Violation: Key: "5", Field Name: "x-test-request", Required Value: "req", Value: "RequestData"',
    'Validation should complain that "req" nocase prefixes "RequestData".')

server.Streams.stdout += Testers.ContainsExpression(
    'Not No Case Suffix Violation: Key: "5", Field Name: "x-test-present", Required Value: "eRE", Value: "It\'s there"',
    'Validation should complain that "eRE" nocase suffixes "It\'s there".')


server.Streams.stdout = Testers.ContainsExpression(
    'Not No Case Contains Violation: Key: "5", URI Part: "path", Required Value: "iG/S", Value: "/config/settings.yaml"',
    'Validation should complain that "iG/S" is nocase contained in the path.')


client.Streams.stdout += Testers.ContainsExpression(
    'Not Equals Success: Different. Key: "5", Field Name: "content-type", Correct Value: "text", Actual Value: "text/html"',
    'Validation should be happy that "text" does not equal "text/html".')

client.Streams.stdout += Testers.ContainsExpression(
    'Not Presence Violation: Key: "5", Field Name: "set-cookie", Value: "ABCD"',
    'Validation should complain that "set-cookie" is present.')

client.Streams.stdout += Testers.ContainsExpression(
    'Not Absence Violation: Key: "5", Field Name: "fake-cookie"',
    'Validation should complain that "fake-cookie" is absent.')

client.Streams.stdout += Testers.ContainsExpression(
    'Not No Case Contains Violation: Key: "5", Field Name: "content-type", Required Value: "Tex", Value: "text/html"',
    'Validation should complain that "Tex" is nocase contained in "text/html".')

client.Streams.stdout += Testers.ContainsExpression(
    'Not No Case Prefix Success: Absent. Key: "5", Field Name: "fake-cookie", Required Value: "B"',
    'Validation should be happy that "B" does not nocase prefix a nonexistent header.')

client.Streams.stdout += Testers.ContainsExpression(
    'No Case Suffix Success: Key: "5", Field Name: "content-type", Required Value: "L", Value: "text/html"',
    'Validation should be happy that "L" nocase suffixes "text/html".')


client.Streams.stdout += Testers.ContainsExpression(
    'Not Prefix Success: Not Found. Key: "5", Field Name: "multiple", Required Values: "Abc" "DEF", Received Values: "abc" "DEF"',
    'Validation should be happy that "Abc" does not prefix "abc", even though "DEF" prefixes "DEF".')

client.Streams.stdout += Testers.ContainsExpression(
    'Not No Case Equals Violation: Key: "5", Field Name: "multiple", Required Values: "Abc" "DEF", Values: "abc" "DEF"',
    'Validation should complain that each required value nocase equals the corresponding received value.')

client.ReturnCode = 1
server.ReturnCode = 1
