'''
Verify correct field verification behavior.
'''
# @file
#
# Copyright 2020, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#


Test.Summary = '''
Verify correct field verification behavior.
'''

#
# Test 1: Verify field verification in a JSON replay file.
#
r = Test.AddTestRun("Verify field verification works for a simple HTTP transaction")
client = r.AddClientProcess("client1", "http_replay_files/json", http_ports=[8080], other_args="--verbose diag")
server = r.AddServerProcess("server1", "http_replay_files/json", http_ports=[8081], other_args="--verbose diag")
proxy = r.AddProxyProcess("proxy1", listen_port=8080, server_port=8081)

# Verify a success and failure of each validation in the request.
server.Streams.stdout = Testers.ContainsExpression(
        'Absence Success: Key: "1", Name: "x-candy"',
        'Validation should be happy that the proxy removed X-CANDY.')
server.Streams.stdout += Testers.ContainsExpression(
        'Absence Violation: Present. Key: "1", Name: "content-type", Value: "application/octet-stream"',
        'Validation should complain that "content-type" is present')
server.Streams.stdout += Testers.ContainsExpression(
        'Presence Success: Key: "1", Name: "content-length", Value: "399"',
        'Validation should be happy that "content-length" is present.')
server.Streams.stdout += Testers.ContainsExpression(
        'Presence Success: Key: "1", Name: "exampleremoteip", Value: "10.10.10.4"',
        'Validation should be happy that "ExampleRemoteIP" is present even though its value differs.')
server.Streams.stdout += Testers.ContainsExpression(
        'Presence Violation: Absent. Key: "1", Name: "client-ip"',
        'Validation should complain that "client-ip" is misssing')
server.Streams.stdout += Testers.ContainsExpression(
        'Equals Success: Key: "1", Name: "x-someid", Value: "21djfk39jfkds"',
        'Validation should be happy that "S-SomeId" has the expected value.')
server.Streams.stdout += Testers.ContainsExpression(
        'Equals Violation: Different. Key: "1", Name: "host", Correct Value: "example.com", Actual Value: "test.example.com"',
        'Validation should complain that the "Host" value differs from the expected value.')
server.Streams.stdout += Testers.ContainsExpression(
        'Equals Violation: Different. Key: "1", Name: "x-test-case", Correct Value: "CASEmatters", Actual Value: "caseMATTERS"',
        'Equals validation must be case-sensitive.')

# Verify a success and failure of each validation in the response.
client.Streams.stdout = Testers.ContainsExpression(
        'Absence Success: Key: "1", Name: "x-newtestheader"',
        'Validation should be happy that the proxy removed X-NewTestHeader.')
client.Streams.stdout += Testers.ContainsExpression(
        'Absence Violation: Present. Key: "1", Name: "x-shouldexist", Value: "trustme; it=will"',
        'Validation should complain that "X-ShouldExist" is present')
client.Streams.stdout += Testers.ContainsExpression(
        'Presence Success: Key: "1", Name: "content-length", Value: "0"',
        'Validation should be happy that "content-length" is present.')
client.Streams.stdout += Testers.ContainsExpression(
        'Presence Success: Key: "1", Name: "age", Value: "4"',
        'Validation should be happy that "Age" is present even though its value differs.')
client.Streams.stdout += Testers.ContainsExpression(
        'Presence Violation: Absent. Key: "1", Name: "x-request-id"',
        'Validation should complain that "x-request-id" is misssing')
client.Streams.stdout += Testers.ContainsExpression(
        'Equals Success: Key: "1", Name: "date", Value: "Sat, 16 Mar 2019 03:11:36 GMT"',
        'Validation should be happy that "date" has the expected value.')
client.Streams.stdout += Testers.ContainsExpression(
        ('Equals Violation: Different. Key: "1", Name: "x-testheader", '
            'Correct Value: "from_proxy_response", Actual Value: "from_server_response"'),
        'Validation should complain that the "x-testheader" value differs from the expected value.')

#
# Test 2: Verify field verification in a YAML replay file.
#
r = Test.AddTestRun("Verify field verification works for a simple HTTP transaction")
client = r.AddClientProcess("client2", "http_replay_files/yaml", http_ports=[8080], other_args="--verbose diag")
server = r.AddServerProcess("server2", "http_replay_files/yaml", http_ports=[8081], other_args="--verbose diag")
proxy = r.AddProxyProcess("proxy2", listen_port=8080, server_port=8081)

client.Streams.stdout += Testers.ContainsExpression(
        'Absence Success: Key: "5", Name: "x-not-a-header"',
        'Validation should be happy that "X-Not-A-Header" is missing.')

client.Streams.stdout += Testers.ContainsExpression(
        'Equals Success: Key: "5", Name: "set-cookie", Value: "ABCD"',
        'Validation should be happy that "Set-Cookie" had the expected header.')

client.Streams.stdout += Testers.ContainsExpression(
        'Equals Success: Key: "5", Name: "set-cookie", Value: "ABCD"',
        'Validation should be happy that "Set-Cookie" had the expected header.')

client.Streams.stdout += Testers.ContainsExpression(
        'Presence Violation: Absent. Key: "5", Name: "x-does-not-exist"',
        'Validation should complain that "X-Does-Not-Exist" is not present.')

server.Streams.stdout += Testers.ContainsExpression(
        'Equals Violation: Different. Key: "5", Name: "x-test-request", Correct Value: "rEQUESTdATA", Actual Value: "RequestData"',
        'Validation should complain that "X-Test-Request" is different.')

server.Streams.stdout += Testers.ContainsExpression(
        'Absence Violation: Present. Key: "5", Name: "x-test-present", Value: "It\'s there"',
        'Validation should complain that "X-Test-Pressent" is present.')

server.Streams.stdout += Testers.ContainsExpression(
        'Equals Success: Key: "5", Name: "cookie", Value: "',
        'Validation should complainthat "X-Does-Not-Exist" is not present.')
