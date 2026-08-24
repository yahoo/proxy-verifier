'''
Abort HTTP/2 connection.
'''
# @file
#
# Copyright 2023-2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

#
# Test 1: Client sends RST_STREAM after DATA frame
#
case = suite.case('Client sends RST_STREAM after DATA frame')
client = case.add_client('client1', 'replay_files/client_rst_stream_after_data.yaml')
server = case.add_server('server1', 'replay_files/client_rst_stream_after_data.yaml')
proxy = case.add_proxy('proxy1', listen_port=client.https_port, server_port=server.https_port,
                       use_ssl=True, use_http2_to_2=True)

client.stdout.contains(
    'Submitting RST_STREAM frame for key 1 after DATA frame with error code INTERNAL_ERROR.',
    'Detect client abort flag.')

client.stdout.contains('Submitted RST_STREAM frame for key 1 on stream 1.',
                       'Submitted RST_STREAM frame.')

server.stdout.contains('Received an HTTP/2 request for key 1 with stream id 1',
                       'Server is functional.')

server.stdout.excludes('RST_STREAM', 'Server is not affected.')

proxy.stdout.contains('Received RST_STREAM frame with error code INTERNAL_ERROR',
                      'Received RST_STREAM frame.')

proxy.stdout.contains('Frame sequence from client: HEADERS, DATA, RST_STREAM', 'Frame sequence.')

#
# Test 2: Client sends RST_STREAM after HEADERS frame
#
case = suite.case('Client sends RST_STREAM after HEADERS frame')
client = case.add_client('client2', 'replay_files/client_rst_stream_after_headers.yaml')
server = case.add_server('server2', 'replay_files/client_rst_stream_after_headers.yaml')
proxy = case.add_proxy('proxy2', listen_port=client.https_port, server_port=server.https_port,
                       use_ssl=True, use_http2_to_2=True)

client.stdout.contains(
    'Submitting RST_STREAM frame for key 1 after HEADERS frame with error code STREAM_CLOSED.',
    'Detect client abort flag.')

client.stdout.contains('Submitted RST_STREAM frame for key 1 on stream 1.',
                       'Submitted RST_STREAM frame.')

client.stdout.excludes('Timed out waiting for frame: HEADERS', 'Await HEADERS')

server.stdout.contains('Received an HTTP/2 request for key 1 with stream id 1',
                       'Server is functional.')

server.stdout.excludes('RST_STREAM', 'Server is not affected.')

proxy.stdout.contains('Received RST_STREAM frame with error code STREAM_CLOSED',
                      'Received RST_STREAM frame.')

proxy.stdout.contains('Frame sequence from client: HEADERS, RST_STREAM', 'Frame sequence.')

#
# Test 3: Server sends RST_STREAM after HEADERS frame
#
case = suite.case('Server sends RST_STREAM after HEADERS frame')
client = case.add_client('client3', 'replay_files/server_rst_stream_after_headers.yaml')
server = case.add_server('server3', 'replay_files/server_rst_stream_after_headers.yaml')
proxy = case.add_proxy('proxy3', listen_port=client.https_port, server_port=server.https_port,
                       use_ssl=True, use_http2_to_2=True)

client.stdout.contains('Received RST_STREAM frame with stream id 1', 'RST_STREAM pass through.')

server.stdout.contains(
    'Submitting RST_STREAM frame for key 1 after HEADERS frame with error code ENHANCE_YOUR_CALM.',
    'Detect client abort flag.')

server.stdout.contains('Submitted RST_STREAM frame for key 1 on stream 1.',
                       'Submitted RST_STREAM frame.')

proxy.stdout.contains(
    'StreamReset stream_id:1, error_code:(11|ErrorCodes.ENHANCE_YOUR_CALM), remote_reset:True',
    'Received RST_STREAM frame.')

#
# Test 4: Client sends GOAWAY after HEADERS frame
#
case = suite.case('Client sends GOAWAY after HEADERS frame')
client = case.add_client('client4', 'replay_files/client_goaway_after_headers.yaml')
server = case.add_server('server4', 'replay_files/client_goaway_after_headers.yaml')
proxy = case.add_proxy('proxy4', listen_port=client.https_port, server_port=server.https_port,
                       use_ssl=True, use_http2_to_2=True)

client.stdout.contains(
    'Submitting GOAWAY frame for key 1 after HEADERS frame with error code STREAM_CLOSED.',
    'Detect client abort flag.')

client.stdout.contains('Submitted GOAWAY frame for key 1.', 'Submitted GOAWAY frame.')

client.stdout.excludes('should_not_send', 'Client connection should terminate.')

server.stdout.excludes('GOAWAY', 'Server is not affected.')

server.stdout.excludes('should_not_send', 'Server connection should terminate.')

proxy.stdout.contains('Received GOAWAY frame with error code STREAM_CLOSED',
                      'Received GOAWAY frame.')

proxy.stdout.contains('Frame sequence from client: HEADERS, GOAWAY', 'Frame sequence.')

#
# Test 5: Server sends GOAWAY after HEADERS frame
#
case = suite.case('Server sends GOAWAY after HEADERS frame')
client = case.add_client('client5', 'replay_files/server_goaway_after_headers.yaml')
server = case.add_server('server5', 'replay_files/server_goaway_after_headers.yaml')
proxy = case.add_proxy('proxy5', listen_port=client.https_port, server_port=server.https_port,
                       use_ssl=True, use_http2_to_2=True)

client.stdout.contains('Received GOAWAY frame with last stream id 0', 'GOAWAY pass through.')

client.stdout.excludes('should_not_send', 'Client connection should terminate.')

server.stdout.contains(
    'Submitting GOAWAY frame for key 1 after HEADERS frame with error code STREAM_CLOSED.',
    'Detect server abort flag.')

server.stdout.contains('Submitted GOAWAY frame for key 1.', 'Submitted GOAWAY frame.')

server.stdout.excludes('should_not_send', 'Server connection should terminate.')

proxy.stdout.contains(
    'ConnectionTerminated error_code:(5|ErrorCodes.STREAM_CLOSED), last_stream_id:0, additional_data:None',
    'Received GOAWAY frame.')

#
# Test 6: Client sends RST_STREAM mixed within multiple DATA frames
#
case = suite.case('Client sends RST_STREAM mixed within multiple DATA frames')
client = case.add_client('client6', 'replay_files/client_rst_stream_mixed_data.yaml')
server = case.add_server('server6', 'replay_files/client_rst_stream_mixed_data.yaml')
proxy = case.add_proxy('proxy6', listen_port=client.https_port, server_port=server.https_port,
                       use_ssl=True, use_http2_to_2=True)

client.stdout.contains(
    'Submitting RST_STREAM frame for key 1 after DATA frame with error code INTERNAL_ERROR.',
    'Detect client abort flag.')

client.stdout.contains('Submitted RST_STREAM frame for key 1 on stream 1.',
                       'Submitted RST_STREAM frame.')

server.stdout.contains('Received an HTTP/2 request for key 1 with stream id 1',
                       'Server is functional.')

server.stdout.excludes('RST_STREAM', 'Server is not affected.')

proxy.stdout.contains('Received RST_STREAM frame with error code INTERNAL_ERROR',
                      'Received RST_STREAM frame.')

proxy.stdout.contains('Frame sequence from client: HEADERS, DATA, RST_STREAM', 'Frame sequence.')


def test_uranium_suite(uranium):
    uranium.run(suite)
