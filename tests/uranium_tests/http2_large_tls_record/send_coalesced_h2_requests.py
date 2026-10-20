#!/usr/bin/env python3
'''
Send two HTTP/2 requests in a single TLS record larger than the buffer the
verifier-server passes to SSL_read, then wait for both responses.
'''
# @file
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

import argparse
import socket
import ssl
import struct
import sys
import time

CLIENT_PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'

FRAME_HEADER_SIZE = 9
FRAME_DATA = 0x0
FRAME_HEADERS = 0x1
FRAME_SETTINGS = 0x4
FRAME_GOAWAY = 0x7
FLAG_END_STREAM = 0x1
FLAG_ACK = 0x1
FLAG_END_HEADERS = 0x4

FIRST_STREAM_ID = 1
SECOND_STREAM_ID = 3

# The verifier-server reads TLS application data in 10 KiB chunks. The second
# request ends past that point, so after the first SSL_read OpenSSL still holds
# the end of the record. The whole batch stays within one maximum-sized TLS
# record (16 KiB of plaintext) so that it is sent as a single record.
SERVER_READ_BUFFER_SIZE = 10 * 1024
MAX_TLS_RECORD_PLAINTEXT = 16 * 1024
SECOND_REQUEST_BODY_SIZE = 12000

# Let the server finish the connection preface exchange and return to waiting
# for requests before the batch arrives.
SETTLE_DELAY_SECONDS = 0.5
RESPONSE_TIMEOUT_SECONDS = 5.0


def frame(frame_type: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    '''Serialize one HTTP/2 frame.'''
    length = len(payload)
    header = struct.pack('!BHBBI', length >> 16, length & 0xFFFF, frame_type, flags, stream_id)
    return header + payload


def hpack_literal(name: str, value: str) -> bytes:
    '''Encode a literal header field without indexing, with a literal name.

    Each name and value here is shorter than 127 bytes, so its length fits
    in the 7-bit string length prefix.
    '''
    encoded = b'\x00'
    for text in (name, value):
        data = text.encode()
        assert len(data) < 127
        encoded += bytes([len(data)]) + data
    return encoded


def headers_block(fields: list[tuple[str, str]]) -> bytes:
    return b''.join(hpack_literal(name, value) for name, value in fields)


def request_fields(method: str, path: str, uuid: str) -> list[tuple[str, str]]:
    return [
        (':method', method),
        (':scheme', 'https'),
        (':authority', 'example.com'),
        (':path', path),
        ('uuid', uuid),
    ]


def build_batch() -> bytes:
    '''Build both requests: the first ends early, the second ends late.'''
    first = frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, FIRST_STREAM_ID,
                  headers_block(request_fields('GET', '/first', 'first-request')))
    second_fields = request_fields('POST', '/second', 'second-request')
    second_fields.append(('content-length', str(SECOND_REQUEST_BODY_SIZE)))
    second = frame(FRAME_HEADERS, FLAG_END_HEADERS, SECOND_STREAM_ID, headers_block(second_fields))
    second += frame(FRAME_DATA, FLAG_END_STREAM, SECOND_STREAM_ID,
                    b'x' * SECOND_REQUEST_BODY_SIZE)
    return first + second


class FrameReader:
    '''Read HTTP/2 frames from a TLS socket.'''

    def __init__(self, sock: ssl.SSLSocket) -> None:
        self._sock = sock
        self._buffer = b''

    def read_frame(self, deadline: float) -> tuple[int, int, int, bytes] | None:
        '''Return (type, flags, stream id, payload), or None at the deadline or close.'''
        while True:
            if len(self._buffer) >= FRAME_HEADER_SIZE:
                length_high, length_low, frame_type, flags, stream_id = struct.unpack(
                    '!BHBBI', self._buffer[:FRAME_HEADER_SIZE])
                length = (length_high << 16) | length_low
                end = FRAME_HEADER_SIZE + length
                if len(self._buffer) >= end:
                    payload = self._buffer[FRAME_HEADER_SIZE:end]
                    self._buffer = self._buffer[end:]
                    return frame_type, flags, stream_id & 0x7FFFFFFF, payload
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            self._sock.settimeout(remaining)
            try:
                data = self._sock.recv(65536)
            except (socket.timeout, TimeoutError):
                return None
            if not data:
                return None
            self._buffer += data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('host', help='The verifier-server address.')
    parser.add_argument('port', type=int, help='The verifier-server HTTPS port.')
    args = parser.parse_args()

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(['h2'])

    batch = build_batch()
    second_request_end = len(batch)
    assert SERVER_READ_BUFFER_SIZE < second_request_end <= MAX_TLS_RECORD_PLAINTEXT

    with socket.create_connection((args.host, args.port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname='example.com') as sock:
            if sock.selected_alpn_protocol() != 'h2':
                print(f'The server did not negotiate h2: {sock.selected_alpn_protocol()}')
                return 1
            reader = FrameReader(sock)
            sock.sendall(CLIENT_PREFACE + frame(FRAME_SETTINGS, 0, 0, b''))

            deadline = time.monotonic() + RESPONSE_TIMEOUT_SECONDS
            while True:
                received = reader.read_frame(deadline)
                if received is None:
                    print('Did not receive the server SETTINGS frame.')
                    return 1
                frame_type, flags, _, _ = received
                if frame_type == FRAME_SETTINGS and not flags & FLAG_ACK:
                    break
            sock.sendall(frame(FRAME_SETTINGS, FLAG_ACK, 0, b''))
            time.sleep(SETTLE_DELAY_SECONDS)

            # A single sendall of no more than 16 KiB is a single SSL_write,
            # which OpenSSL sends as a single TLS record.
            print(f'Sending both requests in one {len(batch)}-byte TLS record.')
            sock.sendall(batch)

            # Send nothing more: any further bytes would make the server's
            # socket readable and hide a server that waits on poll(2) while
            # OpenSSL holds the end of the record.
            completed: set[int] = set()
            deadline = time.monotonic() + RESPONSE_TIMEOUT_SECONDS
            while completed != {FIRST_STREAM_ID, SECOND_STREAM_ID}:
                received = reader.read_frame(deadline)
                if received is None:
                    break
                frame_type, flags, stream_id, _ = received
                if frame_type == FRAME_GOAWAY:
                    print('The server sent GOAWAY.')
                    break
                if frame_type in (FRAME_HEADERS, FRAME_DATA) and flags & FLAG_END_STREAM:
                    print(f'Received a complete response on stream {stream_id}.')
                    completed.add(stream_id)

    for stream_id in (FIRST_STREAM_ID, SECOND_STREAM_ID):
        if stream_id not in completed:
            print(f'Did not receive a complete response on stream {stream_id}.')
    if completed != {FIRST_STREAM_ID, SECOND_STREAM_ID}:
        return 1
    print('Received complete responses on both streams.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
