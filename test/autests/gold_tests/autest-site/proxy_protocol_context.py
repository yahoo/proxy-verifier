'''
Implement the PROXY protocol utility class and the socket wrapper class.
'''
# @file
#
# Copyright 2023, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#


import socket
import struct
import time
from enum import Enum
import threading

PP_V2_PREFIX = b'\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a'
# The maximum size of the proxy protocol header is 108 bytes(assuming TLV and
# linux socket address are not used)
PP_MAX_DATA_SIZE = 108


class ProxyProtocolVersion(Enum):
    NONE = 0
    V1 = 1
    V2 = 2


class ProxyProtocolUtil:
    """Utility class for parsing and encoding the PROXY protocol header. The
    parsing code is largely adopted from Brian Neradt's proxy_protocol_server in
    the ATS repo.
    """

    # The Proxy header version to be sent to the origin server. This is set when
    # a PROXY header is received by the proxy. Needs to be thread-local as
    # connections can be concurrent
    pp_version = threading.local()

    @staticmethod
    def wrap_socket(sock, use_ssl=False, ssl_ctx=None):
        return PP_socket(sock, use_ssl, ssl_ctx)

    # utility methods for parsing or encoding the PROXY protocol header
    @staticmethod
    def parse_pp_v1(pp_bytes: bytes) -> int:
        """Parse and print the Proxy Protocol v1 string.
        :param pp_bytes: The bytes containing the Proxy Protocol string. There may
        be more bytes than the Proxy Protocol string.
        :returns: The number of bytes occupied by the proxy v1 protocol.
        """
        # Proxy Protocol v1 string ends with CRLF.
        end = pp_bytes.find(b'\r\n')
        if end == -1:
            raise ValueError("Proxy Protocol v1 string ending not found")
        print(pp_bytes[:end].decode("utf-8"))
        return end + 2

    @staticmethod
    def parse_pp_v2(pp_bytes: bytes) -> int:
        """Parse and print the Proxy Protocol v2 string.
        :param pp_bytes: The bytes containing the Proxy Protocol string. There may
        be more bytes than the Proxy Protocol string.
        :returns: The number of bytes occupied by the proxy v2 protocol string.
        """

        # Skip the 12 byte header.
        pp_bytes = pp_bytes[12:]
        version_command = pp_bytes[0]
        pp_bytes = pp_bytes[1:]
        family_protocol = pp_bytes[0]
        pp_bytes = pp_bytes[1:]
        tuple_length = int.from_bytes(pp_bytes[:2], byteorder='big')
        pp_bytes = pp_bytes[2:]

        # Of version_command, the higher 4 bits is the version and the lower 4
        # is the command.
        version = version_command >> 4
        command = version_command & 0x0F

        if version != 2:
            raise ValueError(
                f'Invalid version: {version} (by spec, should always be 0x02)')

        if command == 0x0:
            command_description = 'LOCAL'
        elif command == 0x1:
            command_description = 'PROXY'
        else:
            raise ValueError(
                f'Invalid command: {command} (by spec, should be 0x00 or 0x01)')

        # Of address_family, the higher 4 bits is the address family and the
        # lower 4 is the transport protocol.
        if family_protocol == 0x0:
            transport_protocol_description = 'UNSPEC'
        elif family_protocol == 0x11:
            transport_protocol_description = 'TCP4'
        elif family_protocol == 0x12:
            transport_protocol_description = 'UDP4'
        elif family_protocol == 0x21:
            transport_protocol_description = 'TCP6'
        elif family_protocol == 0x22:
            transport_protocol_description = 'UDP6'
        elif family_protocol == 0x31:
            transport_protocol_description = 'UNIX_STREAM'
        elif family_protocol == 0x32:
            transport_protocol_description = 'UNIX_DGRAM'
        else:
            raise ValueError(
                f'Invalid address family: {family_protocol} (by spec, should be '
                '0x00, 0x11, 0x12, 0x21, 0x22, 0x31, or 0x32)')

        if family_protocol in (0x11, 0x12):
            if tuple_length != 12:
                raise ValueError(
                    "Unexpected tuple length for TCP4/UDP4: "
                    f"{tuple_length} (by) spec, should be 12)"
                )
            src_addr = socket.inet_ntop(socket.AF_INET, pp_bytes[:4])
            pp_bytes = pp_bytes[4:]
            dst_addr = socket.inet_ntop(socket.AF_INET, pp_bytes[:4])
            pp_bytes = pp_bytes[4:]
            src_port = int.from_bytes(pp_bytes[:2], byteorder='big')
            pp_bytes = pp_bytes[2:]
            dst_port = int.from_bytes(pp_bytes[:2], byteorder='big')
            pp_bytes = pp_bytes[2:]

        tuple_description = f'{src_addr} {dst_addr} {src_port} {dst_port}'
        print(
            f'{command_description} {transport_protocol_description} '
            f'{tuple_description}')

        return 16 + tuple_length

    @staticmethod
    def construct_proxy_header_v1(src_addr, dst_addr, family):
        """ Construct a Proxy Protocol v1 string.
        :param src_addr: the source socket address
        :param dst_addr: the destination socket address
        :param family: the socket family
        :returns: The bytes containing the Proxy Protocol v1 string.
        """
        # Construct the PROXY protocol v1 header
        family_desc = 'TCP4' if family == socket.AF_INET else 'TCP6'
        return f"PROXY {family_desc} {src_addr[0]} {dst_addr[0]} {src_addr[1]} {dst_addr[1]}\r\n".encode()

    @staticmethod
    def construct_proxy_header_v2(src_addr, dst_addr, family):
        """ Construct a Proxy Protocol v2 string.
        :param src_addr: the source socket address
        :param dst_addr: the destination socket address
        :param family: the socket family
        :returns: The bytes containing the Proxy Protocol v2 string.
        """
        # Construct the PROXY protocol v2 header
        header = PP_V2_PREFIX
        # Protocol version 2 + PROXY command
        header += b'\x21'
        # TCP over IPv4 or IPv6
        header += b'\x11' if family == socket.AF_INET else b'\x21'
        # address length
        header += b'\x00\x0C'
        header += socket.inet_pton(socket.AF_INET, src_addr[0])
        header += socket.inet_pton(socket.AF_INET, dst_addr[0])
        header += struct.pack('!H', src_addr[1])
        header += struct.pack('!H', dst_addr[1])
        return header

    @staticmethod
    def send_proxy_header(sock, proxy_protocol_version):
        """ Send the PROXY header to the stream
        :param sock: the socket of the stream
        :param proxy_protocol_version: the version of the proxy protocol to send
        """
        # get source ip and port from socket
        print(f'Sending PROXY protocol version {proxy_protocol_version.value}')
        proxy_header_construcut_func = ProxyProtocolUtil.construct_proxy_header_v1 if proxy_protocol_version == ProxyProtocolVersion.V1 else ProxyProtocolUtil.construct_proxy_header_v2
        proxy_header_data = proxy_header_construcut_func(
            sock.getsockname(), sock.getpeername(), sock.family)
        sock.sendall(proxy_header_data)
        time.sleep(1)

    @staticmethod
    def read_pp_header_if_present(sock):
        """ Consume the PROXY header from the socket if present
        :param sock: the socket of the stream
        """
        # peek at the file content to check for proxy protocol header
        data = sock.recv(PP_MAX_DATA_SIZE, socket.MSG_PEEK)
        pp_num_bytes = ProxyProtocolUtil.check_for_proxy_header(data)
        if pp_num_bytes > 0:
            # read the pp header bytes from the file
            sock.recv(pp_num_bytes)
        return

    @staticmethod
    def check_for_proxy_header(data):
        """ Examine the data to see if it contains a proxy protocol header
        :param data: the data to examine
        :returns: the number of bytes in the proxy protocol header if present, 0 otherwise
        """
        print("checking for PROXY protocol header")
        pp_length = 0
        ProxyProtocolUtil.pp_version = ProxyProtocolVersion.NONE

        if (data.startswith(b'PROXY') and b'\r\n' in data):
            pp_length = ProxyProtocolUtil.parse_pp_v1(data)
            ProxyProtocolUtil.pp_version = ProxyProtocolVersion.V1
        if data.startswith(PP_V2_PREFIX):
            pp_length = ProxyProtocolUtil.parse_pp_v2(data)
            ProxyProtocolUtil.pp_version = ProxyProtocolVersion.V2
        if pp_length > 0:
            print(
                f"Received {pp_length} bytes of Proxy Protocol V{ProxyProtocolUtil.pp_version.value}")
        return pp_length

    @staticmethod
    def create_connection_and_send_pp(address, timeout,
                                      source_address):
        """ This is a wraper of the socket.create_connection method, which in
        addition sends a PROXY protocol header as the connection is established.
        :param address: the address to connect to
        :param timeout: the timeout for the connection
        :param source_address: the source address to bind to
        :returns: the socket of the established connection
        """
        sock = socket.create_connection(
            address, timeout, source_address)
        if ProxyProtocolUtil.pp_version != ProxyProtocolVersion.NONE:
            # send the PROXY protocol header
            ProxyProtocolUtil.send_proxy_header(
                sock, ProxyProtocolUtil.pp_version)
        return sock


class PP_socket(socket.socket):
    """A minimal socket wrapper that reads the proxy protocol header. The most
    notable override is the accept method."""

    def __init__(self, sock, use_ssl, ssl_ctx):
        self._socket = sock
        self._use_ssl = use_ssl
        self._ssl_ctx = ssl_ctx
        super().__init__()

    def getsockname(self, *args, **kwargs):
        return self._socket.getsockname(*args, **kwargs)

    def fileno(self):
        return self._socket.fileno()

    def accept(self):
        """ stripes off any proxy protocol header before returning the accepted
        client socket
        """
        client_sock, client_addr = self._socket.accept()
        ProxyProtocolUtil.read_pp_header_if_present(client_sock)
        if self._use_ssl:
            print("wrapping the socket with ssl")
            client_sock = self._ssl_ctx.wrap_socket(
                client_sock, server_side=True)
        # Returning the accepted client socket here, since we are done with
        # proxy protocol processing and can yield control back to the raw socket
        # beyond this point
        return client_sock, client_addr
