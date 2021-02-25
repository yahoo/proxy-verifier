'''
Verify there is an error if the user provides no port arguments.
'''
# @file
#
# Copyright 2021, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#


Test.Summary = '''
Verify --format argument parsing.
'''

#
# Test 1: Verify the client complains if no ports are provided.
#
r = Test.AddTestRun('Verify the client complains if no ports are provided.')
client = r.AddClientProcess("client1", "not_used.yaml", configure_http=False,
                            configure_https=False)
client.Streams.stdout += Testers.ContainsExpression(
    'Must provide either "--connect-http" and/or "--connect-https" arguments',
    'The client should explain that a port argument is required')
client.ReturnCode = 1

#
# Test 1: Verify the server complains if no ports are provided.
#
r = Test.AddTestRun('Verify the server complains if no ports are provided.')
server = r.AddDefaultServerProcess("server1", "not_used.yaml", configure_http=False,
                                   configure_https=False)
server.Streams.stdout += Testers.ContainsExpression(
    'Must provide either "--listen-http" and/or "--listen-https" arguments',
    'The server should explain that a port argument is required')
server.ReturnCode = 1
