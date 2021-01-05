'''
Verify correct URL verification behavior.
'''
# @file
#
# Copyright 2020, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#


Test.Summary = '''
Verify correct URL verification behavior.
'''

#
# Test 1: Verify field verification in a YAML replay file.
#
r = Test.AddTestRun("Verify URL verification works for a simple HTTP transaction")
client = r.AddClientProcess("client1", "url_verification.yaml", other_args="--verbose diag")
server = r.AddServerProcess("server1", "url_verification.yaml", other_args="--verbose diag")
proxy = r.AddProxyProcess("proxy1", listen_port=client.Variables.http_port,
                          server_port=server.Variables.http_port)

# Verify a success and failure of each validation in the request.
server.Streams.stdout = Testers.ContainsExpression(
        'Equals Success: Key: "5", URI Part: "host", Value: "example.one"',
        'Validation should be happy that the host matches the client host.')
server.Streams.stdout = Testers.ContainsExpression(
        'Equals Success: Key: "5", URI Part: "path", Value: "config/settings.yaml"',
        'Validation should be happy that the path matches the client path.')
server.Streams.stdout = Testers.ContainsExpression(
        'Equals Success: Key: "5", URI Part: "scheme", Value: "http"',
        'Validation should be happy that the scheme matches the client scheme.')
server.Streams.stdout = Testers.ContainsExpression(
        'Equals Success: Key: "5", URI Part: "net-loc", Value: "example.one:8080"',
        'Validation should be happy that the authority matches the client authority.')
server.Streams.stdout = Testers.ContainsExpression(
        'Equals Success: Key: "5", URI Part: "net-loc", Value: "example.one:8080"',
        'Validation should be happy that the authority matches the client authority.')
server.Streams.stdout = Testers.ContainsExpression(
        'Equals Success: Key: "5", "port", Value: "8080"',
        'Validation should be happy that the port matches the client paportth.')
server.Streams.stdout = Testers.ContainsExpression(
        'Equals Success: Key: "5", URI Part: "query", Value: "q=3"',
        'Validation should be happy that the query matches the client query.')
server.Streams.stdout = Testers.ContainsExpression(
        'Absence Success: Key: "5", URI Part: "fragment"',
        'Validation should be happy that the fragment was missing.')
server.Streams.stdout = Testers.ContainsExpression(
        'Presence Success: Key: "5", URI Part: "host"',
        'Validation should be happy that the host was not missing.')
server.Streams.stdout = Testers.ContainsExpression(
        'Contains Success: Key: "5", URI Part: "path", Value: "yaml"',
        'Validation should be happy that the client path contains the value.')
server.Streams.stdout = Testers.ContainsExpression(
        'Suffix Success: Key: "5", URI Part: "scheme", Value: "p"',
        'Validation should be happy that the client scheme ends with the value.')
server.Streams.stdout = Testers.ContainsExpression(
        'Prefix Success: Key: "5", URI Part: "port", Value: "8"',
        'Validation should be happy that the client port begins with the value.')
server.Streams.stdout = Testers.ContainsExpression(
        'Equals Violation: Different. Key: "5", URI Part: "net-loc", Correct Value: "8080", Actual Value: "example.one:8080"',
        'Validation should be unhappy that the authority was too long.')
server.Streams.stdout = Testers.ContainsExpression(
        'Equals Violation: Absent. Key: "5", URI Part: "fragment", Correct Value: "F"',
        'Validation should be unhappy that the fragment was missing.')

server.ReturnCode = 1
