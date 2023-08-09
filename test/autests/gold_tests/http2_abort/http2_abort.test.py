'''
Abort HTTP/2 connection.
'''
# @file
#
# Copyright 2023, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

Test.Summary = '''
Abort HTTP/2 connection.
'''

#
# Test 1: Client sends RST_STREAM after DATA frame
#
r = Test.AddTestRun('Client sends RST_STREAM after DATA frame')
client = r.AddClientProcess(
    'client1', 'replay_files/client_rst_stream_after_data.yaml')
server = r.AddServerProcess(
    'server1', 'replay_files/client_rst_stream_after_data.yaml')
proxy = r.AddProxyProcess('proxy1', listen_port=client.Variables.https_port,
                          server_port=server.Variables.https_port,
                          use_ssl=True, use_http2_to_2=True)

client.Streams.stdout += Testers.ContainsExpression(
    'Submitting RST_STREAM frame for key 1 after DATA frame with error code INTERNAL_ERROR.',
    'Detect client abort flag.')

client.Streams.stdout += Testers.ContainsExpression(
    'Submitted RST_STREAM frame for key 1 on stream 1.',
    'Submitted RST_STREAM frame.')

server.Streams.stdout += Testers.ContainsExpression(
    'Received an HTTP/2 request for key 1 with stream id 1',
    'Server is functional.')

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
# Test 2: Client sends RST_STREAM after HEADERS frame
#
r = Test.AddTestRun('Client sends RST_STREAM after HEADERS frame')
client = r.AddClientProcess(
    'client2', 'replay_files/client_rst_stream_after_headers.yaml')
server = r.AddServerProcess(
    'server2', 'replay_files/client_rst_stream_after_headers.yaml')
proxy = r.AddProxyProcess('proxy2', listen_port=client.Variables.https_port,
                          server_port=server.Variables.https_port,
                          use_ssl=True, use_http2_to_2=True)

client.Streams.stdout += Testers.ContainsExpression(
    'Submitting RST_STREAM frame for key 1 after HEADERS frame with error code STREAM_CLOSED.',
    'Detect client abort flag.')

client.Streams.stdout += Testers.ContainsExpression(
    'Submitted RST_STREAM frame for key 1 on stream 1.',
    'Submitted RST_STREAM frame.')

client.Streams.stdout += Testers.ExcludesExpression(
    'Timed out waiting for frame: HEADERS',
    'Await HEADERS')

server.Streams.stdout += Testers.ContainsExpression(
    'Received an HTTP/2 request for key 1 with stream id 1',
    'Server is functional.')

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
# Test 3: Server sends RST_STREAM after HEADERS frame
#
r = Test.AddTestRun('Server sends RST_STREAM after HEADERS frame')
client = r.AddClientProcess(
    'client3', 'replay_files/server_rst_stream_after_headers.yaml')
server = r.AddServerProcess(
    'server3', 'replay_files/server_rst_stream_after_headers.yaml')
proxy = r.AddProxyProcess('proxy3', listen_port=client.Variables.https_port,
                          server_port=server.Variables.https_port,
                          use_ssl=True, use_http2_to_2=True)

client.Streams.stdout += Testers.ContainsExpression(
    'Received RST_STREAM frame with stream id 1',
    'RST_STREAM pass through.')

server.Streams.stdout += Testers.ContainsExpression(
    'Submitting RST_STREAM frame for key 1 after HEADERS frame with error code ENHANCE_YOUR_CALM.',
    'Detect client abort flag.')

server.Streams.stdout += Testers.ContainsExpression(
    'Submitted RST_STREAM frame for key 1 on stream 1.',
    'Submitted RST_STREAM frame.')

proxy.Streams.stdout += Testers.ContainsExpression(
    'StreamReset stream_id:1, error_code:(11|ErrorCodes.ENHANCE_YOUR_CALM), remote_reset:True',
    'Received RST_STREAM frame.')

#
# Test 4: Client sends GOAWAY after HEADERS frame
#
r = Test.AddTestRun('Client sends GOAWAY after HEADERS frame')
client = r.AddClientProcess(
    'client4', 'replay_files/client_goaway_after_headers.yaml')
server = r.AddServerProcess(
    'server4', 'replay_files/client_goaway_after_headers.yaml')
proxy = r.AddProxyProcess('proxy4', listen_port=client.Variables.https_port,
                          server_port=server.Variables.https_port,
                          use_ssl=True, use_http2_to_2=True)

client.Streams.stdout += Testers.ContainsExpression(
    'Submitting GOAWAY frame for key 1 after HEADERS frame with error code STREAM_CLOSED.',
    'Detect client abort flag.')

client.Streams.stdout += Testers.ContainsExpression(
    'Submitted GOAWAY frame for key 1.',
    'Submitted GOAWAY frame.')

client.Streams.stdout += Testers.ExcludesExpression(
    'should_not_send',
    'Client connection should terminate.')

server.Streams.stdout += Testers.ExcludesExpression(
    'GOAWAY',
    'Server is not affected.')

server.Streams.stdout += Testers.ExcludesExpression(
    'should_not_send',
    'Server connection should terminate.')

proxy.Streams.stdout += Testers.ContainsExpression(
    'Received GOAWAY frame with error code STREAM_CLOSED',
    'Received GOAWAY frame.')

proxy.Streams.stdout += Testers.ContainsExpression(
    'Frame sequence from client: HEADERS, GOAWAY',
    'Frame sequence.')

#
# Test 5: Server sends GOAWAY after HEADERS frame
#
r = Test.AddTestRun('Server sends GOAWAY after HEADERS frame')
client = r.AddClientProcess(
    'client5', 'replay_files/server_goaway_after_headers.yaml')
server = r.AddServerProcess(
    'server5', 'replay_files/server_goaway_after_headers.yaml')
proxy = r.AddProxyProcess('proxy5', listen_port=client.Variables.https_port,
                          server_port=server.Variables.https_port,
                          use_ssl=True, use_http2_to_2=True)

client.Streams.stdout += Testers.ContainsExpression(
    'Received GOAWAY frame with last stream id 0',
    'GOAWAY pass through.')

client.Streams.stdout += Testers.ExcludesExpression(
    'should_not_send',
    'Client connection should terminate.')

server.Streams.stdout += Testers.ContainsExpression(
    'Submitting GOAWAY frame for key 1 after HEADERS frame with error code STREAM_CLOSED.',
    'Detect server abort flag.')

server.Streams.stdout += Testers.ContainsExpression(
    'Submitted GOAWAY frame for key 1.',
    'Submitted GOAWAY frame.')

server.Streams.stdout += Testers.ExcludesExpression(
    'should_not_send',
    'Server connection should terminate.')

proxy.Streams.stdout += Testers.ContainsExpression(
    'ConnectionTerminated error_code:(5|ErrorCodes.STREAM_CLOSED), last_stream_id:0, additional_data:None',
    'Received GOAWAY frame.')

#
# Test 6: Client sends RST_STREAM mixed within multiple DATA frames
#
r = Test.AddTestRun('Client sends RST_STREAM mixed within multiple DATA frames')
client = r.AddClientProcess(
    'client6', 'replay_files/client_rst_stream_mixed_data.yaml')
server = r.AddServerProcess(
    'server6', 'replay_files/client_rst_stream_mixed_data.yaml')
proxy = r.AddProxyProcess('proxy6', listen_port=client.Variables.https_port,
                          server_port=server.Variables.https_port,
                          use_ssl=True, use_http2_to_2=True)

client.Streams.stdout += Testers.ContainsExpression(
    'Submitting RST_STREAM frame for key 1 after DATA frame with error code INTERNAL_ERROR.',
    'Detect client abort flag.')

client.Streams.stdout += Testers.ContainsExpression(
    'Submitted RST_STREAM frame for key 1 on stream 1.',
    'Submitted RST_STREAM frame.')

server.Streams.stdout += Testers.ContainsExpression(
    'Received an HTTP/2 request for key 1 with stream id 1',
    'Server is functional.')

server.Streams.stdout += Testers.ExcludesExpression(
    'RST_STREAM',
    'Server is not affected.')

proxy.Streams.stdout += Testers.ContainsExpression(
    'Received RST_STREAM frame with error code INTERNAL_ERROR',
    'Received RST_STREAM frame.')

proxy.Streams.stdout += Testers.ContainsExpression(
    'Frame sequence from client: HEADERS, DATA, RST_STREAM',
    'Frame sequence.')
