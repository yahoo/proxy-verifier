#!/usr/bin/env python3
'''
Send PROXY protocol v2 headers whose declared length is too short for the
advertised address family.
'''
# @file
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

import argparse
import socket
import struct
import sys
import time

V2SIG = b'\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A'
VERSION_2_PROXY_COMMAND = 0x21
FAMILY_TCP4 = 0x11
FAMILY_TCP6 = 0x21
TCP4_ADDRESS_LENGTH = 12
TCP6_ADDRESS_LENGTH = 36

# Give the server time to peek at and parse the header before closing.
POST_SEND_DELAY_SECONDS = 0.5


def build_header(family: int, declared_length: int) -> bytes:
    '''Build a PROXY v2 header carrying exactly @a declared_length body bytes.'''
    fixed = V2SIG + struct.pack('!BBH', VERSION_2_PROXY_COMMAND, family, declared_length)
    return fixed + b'\x00' * declared_length


def send_header(host: str, port: int, header: bytes) -> None:
    with socket.create_connection((host, port), timeout=5) as sock:
        sock.sendall(header)
        time.sleep(POST_SEND_DELAY_SECONDS)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('host', help='The verifier-server address.')
    parser.add_argument('port', type=int, help='The verifier-server port.')
    args = parser.parse_args()

    # Each header declares a length shorter than the address block its family
    # requires. The bytes sent match the declared length exactly, so any
    # address read past them comes from outside the received data.
    headers = [
        ('TCP4 with length 0', build_header(FAMILY_TCP4, 0)),
        ('TCP6 with length 0', build_header(FAMILY_TCP6, 0)),
        ('TCP6 with TCP4 length', build_header(FAMILY_TCP6, TCP4_ADDRESS_LENGTH)),
    ]
    for description, header in headers:
        print(f'Sending {len(header)}-byte PROXY v2 header: {description}')
        send_header(args.host, args.port, header)
    print('Done sending short PROXY v2 headers')
    return 0


if __name__ == '__main__':
    sys.exit(main())
