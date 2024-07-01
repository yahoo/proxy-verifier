'''
Implement HTTP/2 proxy behavior in Python.
'''
# @file
#
# Copyright 2022, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#


from email.message import EmailMessage as HttpHeaders
import sys
import ssl
from OpenSSL.SSL import Error as SSLError
from OpenSSL.SSL import SysCallError as SSLSysCallError
import http.client
import urllib.parse
import threading
import traceback

from proxy_http1 import ProxyRequestHandler
from proxy_protocol_context import ProxyProtocolUtil, ProxyProtocolVersion

import eventlet
from eventlet.green.OpenSSL import SSL, crypto
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import StreamEnded, RequestReceived, ResponseReceived, DataReceived, TrailersReceived, StreamReset, ConnectionTerminated
from h2.errors import ErrorCodes as H2ErrorCodes
from h2.exceptions import StreamClosedError, StreamIDTooLowError


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
        # send proxy protocol header first before TLS handshake
        if ProxyProtocolUtil.pp_version != ProxyProtocolVersion.NONE:
            ProxyProtocolUtil.send_proxy_header(
                sock, ProxyProtocolUtil.pp_version)
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

    def __init__(self, sock, strict_goaway, h2_to_server=False):
        listening_config = H2Configuration(
            client_side=False, validate_inbound_headers=False)
        self.tls = threading.local()
        self.tls.http_conns = {}
        self.sock = sock
        self.sock.settimeout(1.0)
        self.listening_conn = H2Connection(config=listening_config)
        self.is_h2_to_server = h2_to_server
        self.request_infos = {}
        self.client_sni = None
        self.strict_goaway = strict_goaway

    def run_forever(self):
        self.listening_conn.initiate_connection()

        try:
            self.sock.sendall(self.listening_conn.data_to_send())
        except (SSLError, SSLSysCallError) as e:
            print(f'Ignoring exception for now: {e}')

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
                    response_headers, response_body, response_trailers = resp_from_server[
                        stream_id]
                    try:
                        self.listening_conn.send_headers(
                            stream_id, response_headers)
                        self.listening_conn.send_data(
                            stream_id, response_body, end_stream=False if response_trailers else True)
                        if response_trailers:
                            self.listening_conn.send_headers(
                                stream_id, response_trailers, end_stream=True)
                        if self.strict_goaway:
                            self.listening_conn.close_connection()

                    except StreamClosedError as e:
                        print(e)
                    except StreamIDTooLowError as e:
                        print(e)
                try:
                    self.sock.sendall(self.listening_conn.data_to_send())
                except (SSLError, SSLSysCallError) as e:
                    print(f'Ignoring exception for now: {e}')

                # Loop back around to receive more data.
                continue

            if not data:
                # Connection ended.
                for http_conn in self.tls.http_conns.values():
                    http_conn.close()
                break

            events = self.listening_conn.receive_data(data)
            # For a header's only request, body data needs to be None.
            for event in events:
                if hasattr(event, 'stream_id'):
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
                        if stream_id not in resp_from_server.keys():
                            ret_vals = self.request_received(
                                request_info._headers, request_info._body_bytes, stream_id)
                            if ret_vals is not None:
                                resp_from_server[stream_id] = ret_vals

                    if isinstance(event, StreamEnded):
                        print('StreamEnded')
                        stream_id_list.add(stream_id)
                        if stream_id not in resp_from_server.keys():
                            ret_vals = self.request_received(
                                request_info._headers, request_info._body_bytes, stream_id)
                            if ret_vals is not None:
                                resp_from_server[stream_id] = ret_vals

                else:
                    if isinstance(event, ConnectionTerminated):
                        frame_seq.append('GOAWAY')
                        f_str = ', '.join(frame_seq)
                        print(f'Frame sequence from client: {f_str}')
                        err = H2ErrorCodes(event.error_code).name
                        print(
                            f'Received GOAWAY frame with error code {err} on with last stream id {event.last_stream_id}.')
                        self.listening_conn.close_connection()

            for stream_id in stream_id_list:
                try:
                    if self.listening_conn.streams[stream_id].closed:
                        del self.request_infos[stream_id]
                except KeyError:
                    pass
            try:
                stream_id_list = set(
                    [id for id in stream_id_list if not self.listening_conn.streams[id].closed])
            except KeyError:
                pass

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
                request_headers_message.add_header(
                    name.decode("utf-8"), value.decode("utf-8"))
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
            None,
            res.status,
            res.reason)
        # do not return trailers
        return response_headers, response_body, None

    def _send_http2_request_to_server(self, request_headers, req_body, client_stream_id):
        if not self.is_h2_to_server:
            raise RuntimeError(
                "Unexpected received non is_h2_to_server in _send_http2_request_to_server")

        request_headers_message = HttpHeaders()
        for name, value in request_headers:
            request_headers_message.add_header(
                name.decode("utf-8"), value.decode("utf-8"))
        request_headers = request_headers_message
        request_headers = ProxyRequestHandler.filter_headers(request_headers)

        scheme = request_headers[':scheme']
        replay_server = f"127.0.0.1:{self.server_port}"
        path = request_headers[':path']

        try:
            origin = (scheme, replay_server, self.client_sni)
            if origin not in self.tls.http_conns:
                # Open a socket to the server and initiate TLS/SSL.
                ssl_context = _create_ssl_context(
                    cert=self.cert_file)
                if self.client_sni:
                    setattr(ssl_context, "old_wrap_socket",
                            ssl_context.wrap_socket)

                    def new_wrap_socket(sock, *args, **kwargs):
                        # Send proxy protocol header first before TLS handshake.
                        kwargs['server_hostname'] = self.client_sni
                        return ssl_context.old_wrap_socket(sock, *args, **kwargs)
                    setattr(ssl_context, "wrap_socket", new_wrap_socket)
                # Opens a connection to the server.
                sock = ProxyProtocolUtil.create_connection_and_send_pp(
                    ('127.0.0.1', self.server_port))
                sock = ssl_context.wrap_socket(sock)
                if sock.selected_alpn_protocol() != 'h2':
                    # Server downgrades to HTTP/1. Send an http/1 request
                    # instead.
                    return self._send_http1_request_to_server(
                        request_headers, req_body, client_stream_id)
                # Initiate a HTTP/2 connection.
                http2_connection = H2Connection()
                http2_connection.initiate_connection()
                sock.sendall(http2_connection.data_to_send())
                self.tls.http_conns[origin] = Http2Connection(
                    sock, http2_connection)

            client = self.tls.http_conns[origin]
            response_from_server = client.send_request(
                client_stream_id, request_headers.items(), req_body)
            if response_from_server.errors:
                if origin in self.tls.http_conns:
                    del self.tls.http_conns[origin]
                try:
                    if 'StreamReset' in response_from_server.errors:
                        self.listening_conn.reset_stream(client_stream_id)
                    if 'ConnectionTerminated' in response_from_server.errors:
                        self.listening_conn.close_connection(last_stream_id=0)
                except StreamClosedError as err:
                    print(err)
                return
        except Exception as e:
            if origin in self.tls.http_conns:
                del self.tls.http_conns[origin]
            self.listening_conn.send_headers(
                client_stream_id, [(':status', '502')], end_stream=True)
            authority = request_headers.get(':authority', '')
            print(f"Connection to '{replay_server}' initiated with request to "
                  f"'{scheme}://{authority}{path}' failed: {e}")
            traceback.print_exc(file=sys.stdout)
            return
        # Process the headers with directEngine.
        filtered_response_headers = ProxyRequestHandler.filter_headers(
            response_from_server.headers).raw
        # Http/2 response does not have reason phrase.
        empty_reason_phrase = ''

        self.print_info(
            request_headers,
            req_body,
            filtered_response_headers,
            response_from_server.body,
            response_from_server.trailers,
            response_from_server.status_code,
            empty_reason_phrase)
        return filtered_response_headers, response_from_server.body, response_from_server.trailers

    def request_received(self, request_headers, req_body, stream_id):
        if self.is_h2_to_server:
            return self._send_http2_request_to_server(
                request_headers, req_body, stream_id)
        else:
            return self._send_http1_request_to_server(
                request_headers, req_body, stream_id)

    def print_info(
            self,
            request_headers,
            req_body,
            response_headers,
            res_body,
            response_trailers,
            response_status,
            response_reason):
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

        if response_trailers:
            print("\n==== RESPONSE TRAILERS ====")
            for k, v in response_trailers:
                if isinstance(k, bytes):
                    k, v = (k.decode('ascii'), v.decode('ascii'))
                print("{}: {}".format(k, v))


def alpn_callback(conn, protos):
    if b'h2' in protos:
        return b'h2'

    raise RuntimeError("No acceptable protocol offered!")


def servername_callback(conn):
    sni = conn.get_servername()
    conn.set_app_data({'sni': sni})
    print(f"Got SNI from client: {sni}")


def configure_http2_server(listen_port, server_port, https_pem, ca_pem, strict_goaway, h2_to_server=False):
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

    print("wrapping socket with proxy protocol")
    # wrap the socket with proxy protocol socket. Here we don't pass in the SSL
    # info as SSL stuff will be taken care later in SSL.Connection()
    server = ProxyProtocolUtil.wrap_socket(server)
    server = SSL.Connection(context, server)
    server_side_proto = "HTTP/2" if h2_to_server else "HTTP/1.x"
    print(f"Serving HTTP/2 Proxy on 127.0.0.1:{listen_port} with pem "
          f"'{https_pem}', forwarding to 127.0.0.1:{server_port} via "
          f"{server_side_proto}")
    pool = eventlet.GreenPool()

    while True:
        try:
            new_sock, _ = server.accept()
            manager = Http2ConnectionManager(new_sock, strict_goaway, h2_to_server)
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


class Headers:
    """
    This class is needed to support some dict-like operations in the
    directEngine logic for header processing. Under the hood, the headers are
    stored as a list of tuples. It allows for multiple values for the same key.
    """

    def __init__(self, raw_headers):
        self.raw = raw_headers

    def __getitem__(self, key):
        # This function returns the value of the key in the headers. If there
        # are multiple values, they are joined by a comma. This behavior is
        # similar to what httpx does.
        values = [str(tuple_item[1])
                  for tuple_item in self.raw if tuple_item[0] == key]
        if not values:
            raise KeyError(f'Key {key} not found in headers.')
        return ','.join(values)

    def __setitem__(self, key, value):
        # This function sets the value of the first matching key in the headers.
        for i, kv in enumerate(self.raw):
            if kv[0] == key:
                self.raw[i] = (key, value)
                return
        # The key is not in the list. Append the key-value pair.
        self.raw.append((key, value))

    def __delitem__(self, key):
        # Remove all the key-value pairs with the given key.
        self.raw = [item for item in self.raw if item[0] != key]

    def __iter__(self):
        return (tuple_item[0] for tuple_item in self.raw)


class Response:
    """
    This class represents a Http/2 response.
    """

    def __init__(self, status, headers, body, trailers=None, errors=None):
        self.status_code = status
        self.headers = headers
        self.body = body
        self.trailers = trailers
        self.errors = errors


class Http2Connection:
    '''
    This class manages a single HTTP/2 connection to a server. It is not
    thread-safe. For our purpose though, no lock is neccessary as the streams of
    each connection are processed sequentially.
    '''

    def __init__(self, sock, h2conn):
        self.sock = sock
        self.conn = h2conn

    def send_request(self, stream_id, headers, req_body):
        '''
        Sends a request to the h2 connection and returns the response object containing the headers, body, and possible errors.
        '''
        self.conn.send_headers(stream_id, headers)
        if req_body:
            self.conn.send_data(stream_id, req_body)
        self.conn.end_stream(stream_id)
        # Send the data over the socket.
        self.sock.sendall(self.conn.data_to_send())
        response_headers_raw = None
        response_body = b''
        response_stream_ended = False
        trailers = None
        errors = []
        while not response_stream_ended:
            # Read raw data from the socket.
            data = self.sock.recv(65536 * 1024)
            if not data:
                break
            # Feed raw data into h2 engine, and process resulting events.
            events = self.conn.receive_data(data)
            for event in events:
                if isinstance(event, ResponseReceived):
                    # Received response headers.
                    response_headers_raw = event.headers
                if isinstance(event, DataReceived):
                    # Update flow control so the server doesn't starve us.
                    self.conn.acknowledge_received_data(
                        event.flow_controlled_length, event.stream_id)
                    # Received more response body data.
                    response_body += event.data
                if isinstance(event, TrailersReceived):
                    # Received trailer headers.
                    trailers = event.headers
                if isinstance(event, StreamReset):
                    # Stream reset by the server.
                    print(
                        f"Received RST_STREAM from the server: {event}")
                    errors.append('StreamReset')
                    response_stream_ended = True
                    break
                if isinstance(event, ConnectionTerminated):
                    # Received GOAWAY frame from the server.
                    print(
                        f"Received GOAWAY from the server: {event}")
                    errors.append('ConnectionTerminated')
                    response_stream_ended = True
                    break
                if isinstance(event, StreamEnded):
                    # Received complete response body.
                    response_stream_ended = True
                    break
            if not errors:
                # Send any pending data to the server.
                self.sock.sendall(self.conn.data_to_send())

        # Decode the header fields.
        response_headers = [(key.decode(), value.decode())
                            for key, value in response_headers_raw]
        status_code = next(
            (t[1] for t in response_headers if t[0] == ':status'), None)
        return Response(status_code, Headers(response_headers), response_body, trailers, errors)

    def close(self):
        # Tell the server we are closing the h2 connection.
        self.conn.close_connection()
        self.sock.sendall(self.conn.data_to_send())
        self.sock.close()


def _create_ssl_context(cert):
    """
    Create a SSL context with the given cert file.
    """
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(['h2', 'http/1.1'])
    # Load the cert file
    ctx.load_cert_chain(cert)
    # Do not verify the server's certificate
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx
