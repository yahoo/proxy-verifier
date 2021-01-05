'''
Verify correct field verification behavior for contains, prefix, and suffix.
'''
# @file
#
# Copyright 2020, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#


Test.Summary = '''
Verify correct field verification behavior for contains, prefix, and suffix.
'''

#
# Test 1: Verify field verification in a YAML replay file.
#
r = Test.AddTestRun("Verify field verification works for a simple HTTP transaction")
client = r.AddClientProcess("client1", "replay_files/substr_rules.yaml", other_args="--verbose diag")
server = r.AddServerProcess("server1", "replay_files/substr_rules.yaml", other_args="--verbose diag")
proxy = r.AddProxyProcess("proxy1", listen_port=client.Variables.http_port, server_port=server.Variables.http_port)

server.Streams.stdout += Testers.ContainsExpression(
        'Contains Success: Key: "5", Field Name: "host", Required Value: "le.on", Value: "example.one"',
        'Validation should be happy that "le.on" is in "example.one".')

server.Streams.stdout += Testers.ContainsExpression(
        'Prefix Success: Key: "5", Field Name: "x-test-request", Required Value: "Req", Value: "RequestData"',
        'Validation should be happy that "RequestData" began with "Req".')

server.Streams.stdout += Testers.ContainsExpression(
        'Suffix Success: Key: "5", Field Name: "x-test-present", Required Value: "there", Value: "It\'s there"',
        'Validation should be happy that "It\'s there" ended with "there.')

server.Streams.stdout += Testers.ContainsExpression(
        'Contains Violation: Not Found. Key: "5", Field Name: "host", Required Value: "two", Actual Value: "example.one"',
        'Validation should complain that "two" is not in "example.one".')

server.Streams.stdout += Testers.ContainsExpression(
        'Prefix Violation: Not Found. Key: "5", Field Name: "x-test-request", Required Value: "equest", Actual Value: "RequestData"',
        'Validation should complain that "RequestData" did not begin with "equest".')

server.Streams.stdout += Testers.ContainsExpression(
        'Suffix Violation: Not Found. Key: "5", Field Name: "x-test-present", Required Value: "er", Actual Value: "It\'s there"',
        'Validation should complain that "It\'s there" did not end with "er".')

client.Streams.stdout += Testers.ContainsExpression(
        'Contains Success: Key: "5", Field Name: "content-type", Required Value: "html", Value: "text/html"',
        'Validation should be happy that "html" is in "text/html".')

client.Streams.stdout += Testers.ContainsExpression(
        'Contains Violation: Not Found. Key: "5", Field Name: "set-cookie", Required Value: "ABCDE", Actual Value: "ABCD"',
        'Validation should complain that "ABCDE" is not in "ABCD".')

client.Streams.stdout += Testers.ContainsExpression(
        'Prefix Violation: Absent. Key: "5", Field Name: "x-not-a-header", Required Value: "Whatever"',
        'Validation should complain that "X-Not-A-Header" is missing.')

client.Streams.stdout += Testers.ContainsExpression(
        'Contains Violation: Absent. Key: "5", Field Name: "x-does-not-exist", Required Value: "NotHere"',
        'Validation should complain that "X-Does-Not-Exist" is missing.')

client.Streams.stdout += Testers.ContainsExpression(
        'Suffix Violation: Absent. Key: "5", Field Name: "x-does-not-exist", Required Value: "NotHere"',
        'Validation should complain that "X-Does-Not-Exist" is missing.')

client.ReturnCode = 1
server.ReturnCode = 1

#
# Test 2: Verify duplicate field verification in a YAML replay file.
#
r = Test.AddTestRun("Verify field verification works for HTTP transaction with duplicate fields")
client = r.AddClientProcess("client2", "replay_files/substr_rules_duplicate.yaml", other_args="--verbose diag")
server = r.AddServerProcess("server2", "replay_files/substr_rules_duplicate.yaml", other_args="--verbose diag")
proxy = r.AddProxyProcess("proxy2", listen_port=client.Variables.http_port, server_port=server.Variables.http_port)

client.Streams.stdout += Testers.ContainsExpression(
        'Contains Violation: Absent/Mismatched. Key: "1", Field Name: "set-cookie", Required Values: "AB", Received Values: "ABCD" "EFG"',
        'Validation should be complain that "Set-Cookie" had too many values.')

server.Streams.stdout += Testers.ContainsExpression(
        'Prefix Violation: Absent/Mismatched. Key: "1", Field Name: "pref-cookie", Required Values: "AB" "EF", Received Values: "ABCD"',
        'Validation should be complain that "Set-Cookie" had too few values.')

server.Streams.stdout += Testers.ContainsExpression(
        'Suffix Violation: Absent/Mismatched. Key: "1", Field Name: "suff-cookie", Required Values: "AB" "EF", Received Values:',
        'Validation should complain that "Set-Cookie" had no values.')

server.Streams.stdout += Testers.ContainsExpression(
        'Contains Violation: Not Found. Key: "1", Field Name: "set-cookie", Required Values: "G" "F", Received Values: "ABCD" "EFG"',
        'Validation should be complain that "Set-Cookie" had uncontained values.')

client.Streams.stdout += Testers.ContainsExpression(
        'Prefix Violation: Not Found. Key: "1", Field Name: "set-cookie", Required Values: "BC" "EF", Received Values: "ABCD" "EFG"',
        'Validation should be complain that "Set-Cookie" did not match all prefixes.')

server.Streams.stdout += Testers.ContainsExpression(
        'Suffix Violation: Not Found. Key: "1", Field Name: "set-cookie", Required Values: "AB" "G", Received Values: "ABCD" "EFG"',
        'Validation should complain that "Set-Cookie" did not match all suffixes.')

server.Streams.stdout += Testers.ContainsExpression(
        'Contains Success: Key: "1", Field Name: "set-cookie", Required Values: "AB" "E", Received Values: "ABCD" "EFG"',
        'Validation should be happy that "Set-Cookie" matched all values.')

server.Streams.stdout += Testers.ContainsExpression(
        'Prefix Success: Key: "1", Field Name: "set-cookie", Required Values: "A" "EFG", Received Values: "ABCD" "EFG"',
        'Validation should be happy that "Set-Cookie" matched all prefixes.')

client.Streams.stdout += Testers.ContainsExpression(
        'Suffix Success: Key: "1", Field Name: "set-cookie", Required Values: "ABCD" "EFG", Received Values: "ABCD" "EFG"',
        'Validation should be happy that "Set-Cookie" matched all suffixes.')

client.ReturnCode = 1
server.ReturnCode = 1
