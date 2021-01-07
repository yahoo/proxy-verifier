'''
Implement HTTP/2 proxy behavior in Python.
'''
# @file
#
# Copyright 2020, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#


from email.message import EmailMessage as HttpHeaders
import sys
import ssl
import hyper
import http.client
import urllib.parse
import threading
import traceback

from proxy_http1 import ProxyRequestHandler

import eventlet
from eventlet.green.OpenSSL import SSL, crypto
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import RequestReceived, DataReceived


class WrapSSSLContext(ssl.SSLContext):
    '''
    HTTPSConnection provides no way to specify the
    server_hostname in the underlying socket. We
    accomplish this by wrapping the context to
    overrride the wrap_socket behavior (called later
    by HTTPSConnection) to specify the
    server_hostname that we want.
    '''
    def __new__(cls, server_hostname, *args, **kwargs):
        return super().__new__(cls, *args, *kwargs)

    def __init__(self, server_hostname, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._server_hostname = server_hostname

    def wrap_socket(self, sock, *args, **kwargs):
        kwargs['server_hostname'] = self._server_hostname
        return super().wrap_socket(sock, *args, **kwargs)


class Http2ConnectionManager(object):
    timeout = 5
    """
    An object that manages a single HTTP/2 connection.
    """
    def __init__(self, sock, h2_to_server=False):
        listening_config = H2Configuration(client_side=False, validate_inbound_headers=False)
        self.tls = threading.local()
        self.tls.http_conns = {}
        self.sock = sock
        self.listening_conn = H2Connection(config=listening_config)
        self.is_h2_to_server = h2_to_server

    def run_forever(self):
        self.listening_conn.initiate_connection()

        self.sock.sendall(self.listening_conn.data_to_send())
        ssl_conn = self.sock.fd
        # See servername_callback for where this is set with set_app_data().
        try:
            self.client_sni = ssl_conn.get_app_data()['sni']
        except KeyError:
            self.client_sni = None

        while True:
            data = self.sock.recv(65535)
            if not data:
                # Connection ended.
                for http_conn in self.tls.http_conns.values():
                    http_conn.close()
                break

            events = self.listening_conn.receive_data(data)

            # The hyper.HTTP20Connection.request interface expects data to be
            # None for a header's only request. Otherwise, if it is b'', it
            # expects that there is some body and doesn't end the stream
            # correctly.
            data = None
            for event in events:
                if isinstance(event, DataReceived):
                    if data is None:
                        data = b''
                    data += event.data

            for event in events:
                if isinstance(event, RequestReceived):
                    self.request_received(event.headers, data, event.stream_id)

            self.sock.sendall(self.listening_conn.data_to_send())

    @staticmethod
    def convert_headers_to_http1(headers):
        """
        Remove the ':...' headers.
        """
        new_headers = http.client.HTTPMessage()
        for key, value in headers.items():
            if key[0] == ':':
                continue
            new_headers.add_header(key, value)
        return new_headers

    def _send_http1_request_to_server(self, request_headers, req_body, stream_id):
        if not isinstance(request_headers, HttpHeaders):
            request_headers_message = HttpHeaders()
            for name, value in request_headers:
                request_headers_message.add_header(name, value)
            request_headers = request_headers_message
        request_headers = ProxyRequestHandler.filter_headers(request_headers)

        scheme = request_headers[':scheme']
        replay_server = "127.0.0.1:{}".format(self.server_port)
        method = request_headers[':method']
        path = request_headers[':path']

        try:
            origin = (scheme, replay_server)
            if origin not in self.tls.http_conns:
                if scheme == 'https':
                    if self.client_sni:
                        gcontext = WrapSSSLContext(self.client_sni)
                    else:
                        gcontext = ssl.SSLContext()
                    self.tls.http_conns[origin] = http.client.HTTPSConnection(
                            replay_server, timeout=self.timeout, context=gcontext, cert_file=self.cert_file)
                else:
                    self.tls.http_conns[origin] = http.client.HTTPConnection(replay_server, timeout=self.timeout)
            connection_to_server = self.tls.http_conns[origin]
            http1_headers = self.convert_headers_to_http1(request_headers)
            connection_to_server.request(method, path, req_body, http1_headers)
            res = connection_to_server.getresponse()

            version_table = {10: 'HTTP/1.0', 11: 'HTTP/1.1'}
            setattr(res, 'headers', res.msg)
            setattr(res, 'response_version', version_table[res.version])

            response_body = res.read()
        except Exception as e:
            if origin in self.tls.http_conns:
                del self.tls.http_conns[origin]
            self.listening_conn.send_headers(stream_id, ((':status', '502')), end_stream=True)
            print("Connection to '{}' initiated with request to '{}://{}{}' failed: {}".format(
                replay_server, scheme, request_headers.get(':authority', ''), path, e))
            traceback.print_exc(file=sys.stdout)
            return

        setattr(res, 'headers', ProxyRequestHandler.filter_headers(res.headers))

        response_headers = (
            (':status', str(res.status)),
        )
        for k, v in res.headers.items():
            response_headers += ((k, v),)
        self.print_info(request_headers, req_body, response_headers, response_body, res.status, res.reason)
        return response_headers, response_body

    def _send_http2_request_to_server(self, request_headers, req_body, client_stream_id):
        if not self.is_h2_to_server:
            raise RuntimeError("Unexpected received non is_h2_to_server in _send_http2_request_to_server")

        request_headers_message = HttpHeaders()
        for name, value in request_headers:
            request_headers_message.add_header(name, value)
        request_headers = request_headers_message
        request_headers = ProxyRequestHandler.filter_headers(request_headers)
        scheme = request_headers[':scheme']
        replay_server = "127.0.0.1:{}".format(self.server_port)
        method = request_headers[':method']
        path = request_headers[':path']

        try:
            origin = (scheme, replay_server, self.client_sni)
            if origin not in self.tls.http_conns:
                gcontext = hyper.tls.init_context(cert_path=self.ca_file, cert=self.cert_file)
                if self.client_sni:
                    setattr(gcontext, "old_wrap_socket", gcontext.wrap_socket)

                    def new_wrap_socket(sock, *args, **kwargs):
                        kwargs['server_hostname'] = self.client_sni
                        gcontext.check_hostname = False
                        return gcontext.old_wrap_socket(sock, *args, **kwargs)
                    setattr(gcontext, "wrap_socket", new_wrap_socket)

                http2_connection = hyper.HTTP20Connection(
                        '127.0.0.1', port=self.server_port, secure=True, ssl_context=gcontext)
                try:
                    http2_connection.connect()
                except AssertionError:
                    # This will happen if the ALPN negotiation refuses HTTP2. Try with HTTP/1.
                    print("HTTP/2 negotiation failed. Trying with HTTP/1")
                    return self._send_http1_request_to_server(request_headers, req_body, client_stream_id)

                self.tls.http_conns[origin] = http2_connection

            connection_to_server = self.tls.http_conns[origin]
            server_stream_id = connection_to_server.request(method, path, req_body, request_headers)
            res = connection_to_server.get_response(server_stream_id)
            response_body = res.read(decode_content=False)
        except Exception as e:
            if origin in self.tls.http_conns:
                del self.tls.http_conns[origin]
            self.listening_conn.send_headers(client_stream_id, ((':status', '502')), end_stream=True)
            print("Connection to '{}' initiated with request to '{}://{}{}' failed: {}".format(
                replay_server, scheme, request_headers.get(':authority', ''), path, e))
            traceback.print_exc(file=sys.stdout)
            return

        setattr(res, 'headers', ProxyRequestHandler.filter_headers(res.headers))
        response_headers = (
            (':status', str(res.status)),
        )
        previous_k = b''
        previous_v = b''
        for k, v in res.headers:
            if k == b'date' and k == previous_k:
                # This happens with date, which HTTPHeaderMap annoyingly splits
                # on the comma:
                # "Sat, 16 Mar 2019 01:13:21 GMT"
                #
                # This yields the following two tuples:
                # (b'date', b'Sat')
                # (b'date', b'16 Mar 2019 01:13:21 GMT')
                v = previous_v + b', ' + v
                response_headers = response_headers[0:-1]
            response_headers += ((k, v),)
            previous_k, previous_v = k, v
        self.print_info(request_headers, req_body, response_headers, response_body, res.status, res.reason)
        return response_headers, response_body

    def request_received(self, request_headers, req_body, stream_id):
        if self.is_h2_to_server:
            response_headers, response_body = self._send_http2_request_to_server(request_headers, req_body, stream_id)
        else:
            response_headers, response_body = self._send_http1_request_to_server(request_headers, req_body, stream_id)

        self.listening_conn.send_headers(stream_id, response_headers)
        self.listening_conn.send_data(stream_id, response_body, end_stream=True)

    def print_info(self, request_headers, req_body, response_headers, res_body,
                   response_status, response_reason):
        def parse_qsl(s):
            return '\n'.join("%-20s %s" % (k, v) for k, v in urllib.parse.parse_qsl(s, keep_blank_values=True))

        print("==== REQUEST HEADERS ====")
        for k, v in request_headers.items():
            print("{}: {}".format(k, v))

        if req_body is not None:
            print("\n==== REQUEST BODY ====\n%s" % req_body)

        print("\n==== RESPONSE ====")
        status_line = "%d %s" % (response_status, response_reason)
        print(status_line)

        print("\n==== RESPONSE HEADERS ====")
        for k, v in response_headers:
            if isinstance(k, bytes):
                k, v = (k.decode('ascii'), v.decode('ascii'))
            print("{}: {}".format(k, v))

        if res_body is not None:
            print("\n==== RESPONSE BODY ====\n%s\n" % res_body)


def alpn_callback(conn, protos):
    if b'h2' in protos:
        return b'h2'

    raise RuntimeError("No acceptable protocol offered!")


def servername_callback(conn):
    sni = conn.get_servername()
    conn.set_app_data({'sni': sni})
    print("Got SNI from client: {}".format(sni))


def configure_http2_server(listen_port, server_port, https_pem, ca_pem, h2_to_server=False):
    # Let's set up SSL. This is a lot of work in PyOpenSSL.
    options = (
        SSL.OP_NO_COMPRESSION |
        SSL.OP_NO_SSLv2 |
        SSL.OP_NO_SSLv3 |
        SSL.OP_NO_TLSv1 |
        SSL.OP_NO_TLSv1_1
    )
    # Keep things TSL1_2 and non-ECDH in case tester wants to decrypt the traffic
    # in wireshark with the pem key.
    context = SSL.Context(SSL.TLSv1_2_METHOD)
    context.set_options(options)
    context.set_verify(SSL.VERIFY_NONE, lambda *args: True)
    context.use_privatekey_file(https_pem)
    context.use_certificate_file(https_pem)
    context.set_alpn_select_callback(alpn_callback)
    context.set_tlsext_servername_callback(servername_callback)
    context.set_cipher_list(
        "RSA+AESGCM"
    )
    context.set_tmp_ecdh(crypto.get_elliptic_curve(u'prime256v1'))

    server = eventlet.listen(('0.0.0.0', listen_port))
    server = SSL.Connection(context, server)
    server_side_proto = "HTTP/2" if h2_to_server else "HTTP/1.x"
    print("Serving HTTP/2 Proxy on {}:{} with pem '{}', forwarding to {}:{} via {}".format(
        "127.0.0.1", listen_port, https_pem, "127.0.0.1", server_port, server_side_proto))
    pool = eventlet.GreenPool()

    while True:
        try:
            new_sock, _ = server.accept()
            manager = Http2ConnectionManager(new_sock, h2_to_server)
            manager.server_port = server_port
            manager.cert_file = https_pem
            manager.ca_file = ca_pem
            pool.spawn_n(manager.run_forever)
        except KeyboardInterrupt as e:
            # The calling test_proxy.py will handle this.
            print("Handling KeyboardInterrupt")
            raise e
        except SystemExit:
            break
