'''
Implement HTTP/1 proxy behavior in Python.
'''
# @file
#
# Copyright 2020, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#


import sys
import socket
import ssl
import http.client
import urllib.parse
import threading
import traceback
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from directive_engine import DirectiveEngine


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    address_family = socket.AF_INET
    daemon_threads = True

    def handle_error(self, request, client_address):
        # surpress socket/ssl related errors
        cls, e = sys.exc_info()[:2]
        if cls is socket.error or cls is ssl.SSLError:
            pass
        else:
            return HTTPServer.handle_error(self, request, client_address)


class ProxyRequestHandler(BaseHTTPRequestHandler):
    """
    This implements the test proxy logic.

    Transactions are generally proxied unmodified. However, request and
    response transactions are parsed for a X-Proxy-Directive header whose value
    can control the proxy behavior per transaction. See the documentation
    in DirectiveEngine for how these directives work.
    """
    timeout = 5
    lock = threading.Lock()

    def __init__(self, *args, **kwargs):
        self.tls = threading.local()
        self.tls.conns = {}

        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def log_error(self, format, *args):
        # surpress "Request timed out: timeout('timed out',)"
        if isinstance(args[0], socket.timeout):
            return

        self.log_message(format, *args)

    def do_GET(self):
        req = self
        content_length = int(req.headers.get('Content-Length', 0))
        req_body = self.rfile.read(content_length) if content_length else None

        if req.path[0] == '/':
            if isinstance(self.connection, ssl.SSLSocket):
                req.path = "https://%s%s" % (req.headers['Host'], req.path)
            else:
                req.path = "http://%s%s" % (req.headers['Host'], req.path)

        client_sni = None
        if hasattr(socket, 'client_sni'):
            client_sni = socket.client_sni
            print("Client SNI: {}".format(client_sni))
        req_body_modified = self.request_handler(req, req_body)
        if req_body_modified is False:
            self.send_error(403)
            return
        elif req_body_modified is not None:
            req_body = req_body_modified
            req.headers['Content-length'] = str(len(req_body))

        u = urllib.parse.urlsplit(req.path)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
        assert scheme in ('http', 'https')
        setattr(req, 'headers', self.filter_headers(req.headers))

        replay_server = "127.0.0.1:{}".format(self.server_port)
        print("Connecting to: {}".format(replay_server))

        try:
            origin = (scheme, replay_server)
            if origin not in self.tls.conns:
                if scheme == 'https':
                    if client_sni:

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

                        proxy_to_server_context = WrapSSSLContext(client_sni)
                    else:
                        proxy_to_server_context = ssl.SSLContext()
                    self.tls.conns[origin] = http.client.HTTPSConnection(
                            replay_server, timeout=self.timeout,
                            context=proxy_to_server_context, cert_file=self.cert_file)
                else:
                    self.tls.conns[origin] = http.client.HTTPConnection(replay_server, timeout=self.timeout)
            conn = self.tls.conns[origin]
            conn.request(self.command, path, req_body, req.headers)
            res = conn.getresponse()

            version_table = {10: 'HTTP/1.0', 11: 'HTTP/1.1'}
            setattr(res, 'headers', res.msg)
            setattr(res, 'response_version', version_table[res.version])

            # support streaming
            if 'Content-Length' not in res.headers and 'no-store' in res.headers.get('Cache-Control', ''):
                self.response_handler(req, req_body, res, '')
                setattr(res, 'headers', self.filter_headers(res.headers))
                self.relay_streaming(res)
                with self.lock:
                    self.save_handler(req, req_body, res, '')
                return

            res_body = res.read()
        except Exception as e:
            if origin in self.tls.conns:
                del self.tls.conns[origin]
            self.send_error(502)
            print("Connection to '{}' initiated with request to '{}://{}{}' failed: {}".format(
                replay_server, scheme, netloc, path, e))
            traceback.print_exc(file=sys.stdout)
            return

        setattr(res, 'headers', self.filter_headers(res.headers))

        status_line = "%s %d %s\r\n" % (self.protocol_version, res.status, res.reason)
        self.wfile.write(status_line.encode())
        for key, value in res.headers.items():
            self.wfile.write("{}:{}\r\n".format(key, value).encode())
        # End the headers.
        self.wfile.write(b"\r\n")
        self.wfile.write(res_body)
        self.wfile.flush()

        with self.lock:
            self.save_handler(req, req_body, res, res_body)

    # Map all the do_<method> commands to our do_GET because that has our
    # request implementation for all of them.
    do_get = do_GET
    do_HEAD = do_GET
    do_head = do_GET
    do_POST = do_GET
    do_post = do_GET
    do_PUT = do_GET
    do_put = do_GET
    do_DELETE = do_GET
    do_delete = do_GET
    do_OPTIONS = do_GET
    do_options = do_GET

    def relay_streaming(self, res):
        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for line in res.headers.headers:
            self.wfile.write(line)
        self.end_headers()
        try:
            while True:
                chunk = res.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)
            self.wfile.flush()
        except socket.error:
            # connection closed by client
            pass

    @staticmethod
    def filter_headers(headers):
        # http://tools.ietf.org/html/rfc2616#section-13.5.1
        hop_by_hop = ('connection', 'keep-alive', 'proxy-authenticate',
                      'proxy-authorization', 'te', 'trailers',
                      'transfer-encoding', 'upgrade')
        for k in hop_by_hop:
            del headers[k]

        # Apply our X-Proxy-Directive manipulations.
        directive_engine = DirectiveEngine(headers)
        return directive_engine.get_new_headers()

    def print_info(self, req, req_body, res, res_body):
        def parse_qsl(s):
            return '\n'.join("%-20s %s" % (k, v) for k, v in urllib.parse.parse_qsl(s, keep_blank_values=True))

        req_header_text = "%s %s %s\n%s" % (req.command, req.path, req.request_version, req.headers)
        res_header_text = "%s %d %s\n%s" % (res.response_version, res.status, res.reason, res.headers)

        print(req_header_text)

        u = urllib.parse.urlsplit(req.path)
        if u.query:
            query_text = parse_qsl(u.query)
            print("==== QUERY PARAMETERS ====\n%s\n" % query_text)

        cookie = req.headers.get('Cookie', '')
        if cookie:
            cookie = parse_qsl(re.sub(r';\s*', '&', cookie))
            print("==== COOKIE ====\n%s\n" % cookie)

        auth = req.headers.get('Authorization', '')
        if auth.lower().startswith('basic'):
            token = auth.split()[1].decode('base64')
            print("==== BASIC AUTH ====\n%s\n" % token)

        if req_body is not None:
            print("==== REQUEST BODY ====\n%s\n" % req_body)

        print(res_header_text)

        cookies = res.headers['Set-Cookie']
        if cookies:
            print("==== SET-COOKIE ====\n%s\n" % cookies)

        if res_body is not None:
            print("==== RESPONSE BODY ====\n%s\n" % res_body)

    def request_handler(self, req, req_body):
        pass

    def response_handler(self, req, req_body, res, res_body):
        pass

    def save_handler(self, req, req_body, res, res_body):
        self.print_info(req, req_body, res, res_body)


def servername_callback(sock, req_hostname, cb_context, as_callback=True):
    socket.client_sni = req_hostname


def configure_http1_server(HandlerClass, ServerClass, protocol,
                           listen_port, server_port, https_pem):

    listen_address = ('127.0.0.1', listen_port)

    HandlerClass.protocol_version = protocol
    HandlerClass.server_port = server_port
    HandlerClass.cert_file = https_pem
    httpd = ServerClass(listen_address, HandlerClass)
    if https_pem:
        client_to_proxy_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        client_to_proxy_context.load_cert_chain(certfile=https_pem)
        client_to_proxy_context.set_servername_callback(servername_callback)
        httpd.socket = client_to_proxy_context.wrap_socket(
                httpd.socket, server_side=True)

    sa = httpd.socket.getsockname()
    print("Serving HTTP Proxy on {}:{}, forwarding to {}:{}".format(sa[0], sa[1], "127.0.0.1", server_port))
    httpd.serve_forever()
