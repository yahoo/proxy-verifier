'''
Abort HTTP/2 connection.
'''
# @file
#
# Copyright 2022, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

Test.Summary = '''
Abort HTTP/2 connection.
'''

#
# Test 1: Client abort after DATA frame
#
r = Test.AddTestRun('Client aborts after DATA frame')
client = r.AddClientProcess('client1', 'replay_files/client_after_data.yaml')
server = r.AddServerProcess('server1', 'replay_files/client_after_data.yaml')
proxy = r.AddProxyProcess('proxy1', listen_port=client.Variables.https_port,
                          server_port=server.Variables.https_port,
                          use_ssl=True, use_http2_to_2=True)

client.Streams.stdout += Testers.ContainsExpression(
    'Submitting RST_STREAM frame for key 1 after DATA frame with error code INTERNAL_ERROR.',
    'Detect client abort flag.')

client.Streams.stdout += Testers.ContainsExpression(
    'Sent frame for key 1: RST_STREAM',
    'Send RST_STREAM frame.')

server.Streams.stdout += Testers.ExcludesExpression(
    'RST_STREAM',
    'Server is not affected.')

proxy.Streams.stdout += Testers.ContainsExpression(
    'Received RST_STREAM frame with error code INTERNAL_ERROR',
    'Received RST_STREAM frame.')

proxy.Streams.stdout += Testers.ContainsExpression(
    'Frame sequence from client: HEADERS, DATA, RST_STREAM',
    'Frame sequence.')

#
# Test 2: Client abort after HEADERS frame
#
r = Test.AddTestRun('Client aborts after HEADERS frame')
client = r.AddClientProcess('client2', 'replay_files/client_after_headers.yaml')
server = r.AddServerProcess('server2', 'replay_files/client_after_headers.yaml')
proxy = r.AddProxyProcess('proxy2', listen_port=client.Variables.https_port,
                          server_port=server.Variables.https_port,
                          use_ssl=True, use_http2_to_2=True)

client.Streams.stdout += Testers.ContainsExpression(
    'Submitting RST_STREAM frame for key 1 after HEADERS frame with error code STREAM_CLOSED.',
    'Detect client abort flag.')

client.Streams.stdout += Testers.ContainsExpression(
    'Sent frame for key 1: RST_STREAM',
    'Send RST_STREAM frame.')

server.Streams.stdout += Testers.ExcludesExpression(
    'RST_STREAM',
    'Server is not affected.')

proxy.Streams.stdout += Testers.ContainsExpression(
    'Received RST_STREAM frame with error code STREAM_CLOSED',
    'Received RST_STREAM frame.')

proxy.Streams.stdout += Testers.ContainsExpression(
    'Frame sequence from client: HEADERS, RST_STREAM',
    'Frame sequence.')

#
# Test 3: Server abort after HEADERS frame
#
r = Test.AddTestRun('Server abort after HEADERS frame')
client = r.AddClientProcess('client3', 'replay_files/server_after_headers.yaml')
server = r.AddServerProcess('server3', 'replay_files/server_after_headers.yaml')
proxy = r.AddProxyProcess('proxy3', listen_port=client.Variables.https_port,
                          server_port=server.Variables.https_port,
                          use_ssl=True, use_http2_to_2=True)

client.Streams.stdout += Testers.ExcludesExpression(
    'RST_STREAM',
    'Client is not affected.')

server.Streams.stdout = "gold/server_after_headers.gold"

proxy.Streams.stdout += Testers.ContainsExpression(
    'httpcore.RemoteProtocolError:',
    'Received RST_STREAM frame.')

proxy.Streams.stdout += Testers.ContainsExpression(
    'error_code:ErrorCodes.ENHANCE_YOUR_CALM, remote_reset:True',
    'Received RST_STREAM frame.')
