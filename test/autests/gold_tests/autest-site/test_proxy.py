'''
Implement the common test proxy logic.
'''
# @file
#
# Copyright 2021, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#


import argparse
import os
import sys

import proxy_http1
import proxy_http2


def parse_args():
    parser = argparse.ArgumentParser(
        description='Implement a simple HTTP proxy which simply forwards transactions.')
    parser.add_argument('--listen-port', metavar='listen_port', type=int,
                        help='The port on which to listen')
    parser.add_argument('--server-port', metavar='server_port', type=int,
                        help='The port on which to connect to the server')
    parser.add_argument('--https-pem', metavar='https_pem', type=str, default=None,
                        help='The file with the cert and key to use for the '
                        'proxy https connection from the client')
    parser.add_argument('--ca-pem', metavar='ca_pem', type=str, default=None,
                        help='The certificate authority file for verifying peers')

    proto_group = parser.add_mutually_exclusive_group()
    proto_group.add_argument('--http2_to_1', action="store_true",
                             help='Listen for HTTP/2 connections but talk HTTP/1 to the server.')
    proto_group.add_argument('--http2_to_2', action="store_true",
                             help='Listen for HTTP/2 connections and talk HTTP/2 to the server.')

    args = parser.parse_args()

    if args.https_pem:
        if not os.path.isfile(args.https_pem):
            raise argparse.ArgumentTypeError(
                "--https-pem argument is not a file: {}".format(args.https_pem))
    return args


def main():
    args = parse_args()

    try:
        if args.http2_to_1:
            proxy_http2.configure_http2_server(
                args.listen_port,
                args.server_port,
                args.https_pem,
                args.ca_pem,
                h2_to_server=False)
        if args.http2_to_2:
            proxy_http2.configure_http2_server(
                args.listen_port,
                args.server_port,
                args.https_pem,
                args.ca_pem,
                h2_to_server=True)
        else:
            proxy_http1.configure_http1_server(
                proxy_http1.ProxyRequestHandler, proxy_http1.ThreadingHTTPServer,
                "HTTP/1.1", args.listen_port, args.server_port, args.https_pem)
    except KeyboardInterrupt:
        print("Received KeyboardInterrupt. Exiting gracefully.")

    return 0


if __name__ == '__main__':
    import doctest
    doctest.testmod()
    sys.exit(main())
