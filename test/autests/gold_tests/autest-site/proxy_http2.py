'''
Implement HTTP/2 proxy behavior in Python.
'''
# @file
#
# Copyright 2021, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#


from email.message import EmailMessage as HttpHeaders
import sys
import ssl
from OpenSSL.SSL import Error as SSLError
from OpenSSL.SSL import SysCallError as SSLSysCallError
import httpx
import http.client
import urllib.parse
import threading
import traceback

from proxy_http1 import ProxyRequestHandler

import eventlet
from eventlet.green.OpenSSL import SSL, crypto
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import StreamEnded, RequestReceived, DataReceived, StreamReset
from h2.errors import ErrorCodes as H2ErrorCodes
from h2.exceptions import StreamClosedError


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


class RequestInfo(object):
    def __init__(self, stream_id):
        self._body_bytes = None
        self._headers = None
        self._stream_id = stream_id


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
        self.sock.settimeout(1.0)
        self.listening_conn = H2Connection(config=listening_config)
        self.is_h2_to_server = h2_to_server
        self.request_infos = {}
        self.client_sni = None

    def run_forever(self):
        self.listening_conn.initiate_connection()

        try:
            self.sock.sendall(self.listening_conn.data_to_send())
        except (SSLError, SSLSysCallError) as e:
            print(f'Ignoring exception for now: {e}')
            pass

        ssl_conn = self.sock.fd
        # See servername_callback for where this is set with set_app_data().
        try:
            self.client_sni = ssl_conn.get_app_data()['sni']
        except (KeyError, TypeError):
            self.client_sni = None

        stream_id_list = set()
        frame_sequences = {}
        resp_from_server = {}
        while True:
            try:
                data = self.sock.recv(65535)
            except SSLError:
                data = None
            except TimeoutError:
                data = None
                for stream_id in resp_from_server.keys():
                    response_headers, response_body = resp_from_server[stream_id]
                    try:
                        self.listening_conn.send_headers(stream_id, response_headers)
                        self.listening_conn.send_data(stream_id, response_body, end_stream=True)
                    except StreamClosedError as e:
                        print(e)
                try:
                    self.sock.sendall(self.listening_conn.data_to_send())
                except (SSLError, SSLSysCallError) as e:
                    print(f'Ignoring exception for now: {e}')
                    pass

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
            for event in events:
                if not hasattr(event, 'stream_id'):
                    # All the frame types interesting to us have a stream id.
                    # Flow control frames aren't important to us.
                    continue
                stream_id = event.stream_id
                if stream_id not in self.request_infos:
                    self.request_infos[stream_id] = RequestInfo(stream_id)
                    frame_sequences[stream_id] = []

                request_info = self.request_infos[stream_id]
                frame_seq = frame_sequences[stream_id]

                if isinstance(event, DataReceived):
                    frame_seq.append('DATA')
                    if request_info._body_bytes is None:
                        request_info._body_bytes = b''
                    request_info._body_bytes += event.data

                if isinstance(event, RequestReceived):
                    frame_seq.append('HEADERS')
                    request_info._headers = event.headers

                if isinstance(event, StreamReset):
                    frame_seq.append('RST_STREAM')
                    f_str = ', '.join(frame_seq)
                    print(f'Frame sequence from client: {f_str}')
                    stream_id_list.add(stream_id)
                    err = H2ErrorCodes(event.error_code).name
                    print(
                        f'Received RST_STREAM frame with error code {err} on stream {event.stream_id}.')

                if isinstance(event, StreamEnded):
                    stream_id_list.add(stream_id)
                    ret_vals = self.request_received(
                        request_info._headers, request_info._body_bytes, stream_id)
                    if ret_vals is not None:
                        resp_from_server[stream_id] = ret_vals

            for stream_id in stream_id_list:
                if self.listening_conn.streams[stream_id].closed:
                    del self.request_infos[stream_id]
            stream_id_list = set(
                [id for id in stream_id_list if not self.listening_conn.streams[id].closed])

            try:
                self.sock.sendall(self.listening_conn.data_to_send())
            except (SSLError, SSLSysCallError) as e:
                print(f'Ignoring exception for now: {e}')
                pass

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
                request_headers_message.add_header(name.decode("utf-8"), value.decode("utf-8"))
            request_headers = request_headers_message
        request_headers = ProxyRequestHandler.filter_headers(request_headers)

        scheme = request_headers[':scheme']
        replay_server = f"127.0.0.1:{self.server_port}"
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
                        replay_server, timeout=self.timeout, context=gcontext,
                        cert_file=self.cert_file)
                else:
                    self.tls.http_conns[origin] = http.client.HTTPConnection(
                        replay_server, timeout=self.timeout)
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
            try:
                self.listening_conn.send_headers(
                    stream_id, [(':status', '502')], end_stream=True)
            except StreamClosedError as err:
                print(err)
            authority = request_headers.get(':authority', '')
            print(f"Connection to '{replay_server}' initiated with request to "
                  f"'{scheme}://{authority}{path}' failed: {e}")
            traceback.print_exc(file=sys.stdout)
            return

        setattr(res, 'headers', ProxyRequestHandler.filter_headers(res.headers))

        response_headers = [
            (':status', str(res.status)),
        ]
        for k, v in res.headers.items():
            response_headers.append((k, v))
        self.print_info(
            request_headers,
            req_body,
            response_headers,
            response_body,
            res.status,
            res.reason)
        return response_headers, response_body

    def _remove_pseudo_headers(self, old_headers):
        new_headers = HttpHeaders()
        for name, value in old_headers.items():
            if (name == ':method' or
                    name == ':path' or
                    name == ':authority' or
                    name == ':scheme'):
                continue
            new_headers.add_header(name, value)
        return new_headers

    def _send_http2_request_to_server(self, request_headers, req_body, client_stream_id):
        if not self.is_h2_to_server:
            raise RuntimeError(
                "Unexpected received non is_h2_to_server in _send_http2_request_to_server")

        request_headers_message = HttpHeaders()
        for name, value in request_headers:
            request_headers_message.add_header(name.decode("utf-8"), value.decode("utf-8"))
        request_headers = request_headers_message
        request_headers = ProxyRequestHandler.filter_headers(request_headers)

        scheme = request_headers[':scheme']
        replay_server = f"127.0.0.1:{self.server_port}"
        path = request_headers[':path']
        url = f'{scheme}://{replay_server}{path}'
        method = request_headers[':method']

        original_request_headers = request_headers
        request_headers = self._remove_pseudo_headers(request_headers)

        try:
            origin = (scheme, replay_server, self.client_sni)
            if origin not in self.tls.http_conns:
                ssl_context = httpx.create_ssl_context(cert=self.cert_file, verify=False)
                if self.client_sni:
                    setattr(ssl_context, "old_wrap_socket", ssl_context.wrap_socket)

                    def new_wrap_socket(sock, *args, **kwargs):
                        kwargs['server_hostname'] = self.client_sni
                        return ssl_context.old_wrap_socket(sock, *args, **kwargs)
                    setattr(ssl_context, "wrap_socket", new_wrap_socket)

                http2_connection = httpx.Client(
                    verify=ssl_context,
                    http2=True)

                self.tls.http_conns[origin] = http2_connection

            client = self.tls.http_conns[origin]
            response_from_server = client.request(
                method=method,
                url=url,
                headers=request_headers.items(),
                content=req_body)
            response_body = response_from_server.content
        except (Exception, httpx.RemoteProtocolError) as e:
            if origin in self.tls.http_conns:
                del self.tls.http_conns[origin]
            try:
                self.listening_conn.send_headers(
                    client_stream_id, [(':status', '502')], end_stream=True)
            except StreamClosedError as err:
                print(err)
            authority = request_headers.get(':authority', '')
            print(f"Connection to '{replay_server}' initiated with request to "
                  f"'{scheme}://{authority}{path}' failed: {e}")
            traceback.print_exc(file=sys.stdout)
            return

        setattr(
            response_from_server,
            'headers',
            ProxyRequestHandler.filter_headers(response_from_server.headers))
        response_headers = [
            (':status', str(response_from_server.status_code)),
        ]
        previous_k = b''
        previous_v = b''
        for k, v in response_from_server.headers.raw:
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
            response_headers.append((k, v))
            previous_k, previous_v = k, v

        # httpx will insert a reason phrase for HTTP/2, but there technically
        # isn't one, so don't confuse the output with it.
        empty_reason_phrase = ''
        self.print_info(
            original_request_headers,
            req_body,
            response_headers,
            response_body,
            response_from_server.status_code,
            empty_reason_phrase)
        return response_headers, response_body

    def request_received(self, request_headers, req_body, stream_id):
        if self.is_h2_to_server:
            return self._send_http2_request_to_server(
                request_headers, req_body, stream_id)
        else:
            return self._send_http1_request_to_server(
                request_headers, req_body, stream_id)

    def print_info(self, request_headers, req_body, response_headers, res_body,
                   response_status, response_reason):
        def parse_qsl(s):
            return '\n'.join(
                "%-20s %s" %
                (k, v) for k, v in urllib.parse.parse_qsl(
                    s, keep_blank_values=True))

        print("==== REQUEST HEADERS ====")
        for k, v in request_headers.items():
            print(f"{k}: {v}")

        if req_body is not None:
            print(f"\n==== REQUEST BODY ====\n{req_body}")

        print("\n==== RESPONSE ====")
        status_line = f"{response_status} {response_reason}".strip()
        print(status_line)

        print("\n==== RESPONSE HEADERS ====")
        for k, v in response_headers:
            if isinstance(k, bytes):
                k, v = (k.decode('ascii'), v.decode('ascii'))
            print(f"{k}: {v}")

        if res_body is not None:
            print(f"\n==== RESPONSE BODY ====\n{res_body}\n")


def alpn_callback(conn, protos):
    if b'h2' in protos:
        return b'h2'

    raise RuntimeError("No acceptable protocol offered!")


def servername_callback(conn):
    sni = conn.get_servername()
    conn.set_app_data({'sni': sni})
    print(f"Got SNI from client: {sni}")


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
    context.set_tmp_ecdh(crypto.get_elliptic_curve('prime256v1'))

    server = eventlet.listen(('0.0.0.0', listen_port))
    server = SSL.Connection(context, server)
    server_side_proto = "HTTP/2" if h2_to_server else "HTTP/1.x"
    print(f"Serving HTTP/2 Proxy on 127.0.0.1:{listen_port} with pem "
          f"'{https_pem}', forwarding to 127.0.0.1:{server_port} via "
          f"{server_side_proto}")
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
