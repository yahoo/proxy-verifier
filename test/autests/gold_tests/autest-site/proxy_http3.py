'''
Implement HTTP/3 proxy behavior in Python.
'''
# @file
#
# Copyright 2021, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#
import argparse
import asyncio
import importlib
import json
import logging
import os
from pathlib import Path
import time
from collections import deque
from email.utils import formatdate
from typing import Callable, Deque, Dict, List, Optional, Union, cast

from proxy_http1 import ProxyRequestHandler

# For HTTP/1 to origin.
from email.message import EmailMessage as HttpHeaders
import http.client
import threading

import aioquic
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h0.connection import H0_ALPN, H0Connection
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, H3Event, Headers, HeadersReceived
from aioquic.h3.exceptions import NoAvailablePushIDError
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.logger import QuicLogger, QuicLoggerTrace
from aioquic.quic.events import DatagramFrameReceived, ProtocolNegotiated, QuicEvent
from aioquic.tls import SessionTicket

AsgiApplication = Callable
HttpConnection = Union[H0Connection, H3Connection]

SERVER_NAME = "aioquic/" + aioquic.__version__


class QuicDirectoryLogger(QuicLogger):
    """
    Custom QUIC logger which writes one trace per file.
    """

    def __init__(self, path: str) -> None:
        if not os.path.isdir(path):
            raise ValueError("QUIC log output directory '%s' does not exist" % path)
        self.path = path
        super().__init__()

    def end_trace(self, trace: QuicLoggerTrace) -> None:
        trace_dict = trace.to_dict()
        trace_path = os.path.join(
            self.path, trace_dict["common_fields"]["ODCID"] + ".qlog"
        )
        with open(trace_path, "w") as logger_fp:
            json.dump({"qlog_version": "draft-01", "traces": [trace_dict]}, logger_fp)
        self._traces.remove(trace)


class HttpRequestHandler:
    timeout = 5

    def __init__(
        self,
        *,
        authority: bytes,
        connection: HttpConnection,
        protocol: QuicConnectionProtocol,
        scope: Dict,
        stream_ended: bool,
        stream_id: int,
        transmit: Callable[[], None],
        is_h3_to_server: bool,
        server_port: int,
    ) -> None:
        self.authority = authority
        self.connection = connection
        self.protocol = protocol
        self.queue: asyncio.Queue[Dict] = asyncio.Queue()
        self.scope = scope
        self.stream_id = stream_id
        self.transmit = transmit
        self.is_h3_to_server = is_h3_to_server
        self.server_port = server_port

        self.client_request_done_event: asyncio.Event = asyncio.Event()
        self.request_headers: Headers = None
        self.request_body = b''

        self.response_headers: Headers
        self.response_body = b""

        self.local_thread = threading.local()
        self.local_thread.http_conns = {}

        if stream_ended:
            self.queue.put_nowait({"type": "http.request"})

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

    # TODO: Gah...this should be asynchronous. Punting on that for now. It will
    # currently block.
    def _send_http1_request_to_server(self, request_headers, req_body, stream_id):
        if not isinstance(request_headers, HttpHeaders):
            request_headers_message = HttpHeaders()
            for name, value in request_headers:
                request_headers_message.add_header(name.decode(), value.decode())
            request_headers = request_headers_message
        request_headers = ProxyRequestHandler.filter_headers(request_headers)

        # For all of these, for convenience, we simply talk HTTP (not HTTPS).
        scheme = 'http'
        replay_server = "127.0.0.1:{}".format(self.server_port)
        method = request_headers[':method']
        path = request_headers[':path']

        try:
            origin = (scheme, replay_server)
            if origin not in self.local_thread.http_conns:
                self.local_thread.http_conns[origin] = http.client.HTTPConnection(
                    replay_server, timeout=self.timeout)
            connection_to_server = self.local_thread.http_conns[origin]
            http1_headers = self.convert_headers_to_http1(request_headers)
            if req_body:
                http1_headers.add_header('Content-Length', str(len(req_body)))
            connection_to_server.request(method, path, req_body, http1_headers)
            res = connection_to_server.getresponse()

            version_table = {10: 'HTTP/1.0', 11: 'HTTP/1.1'}
            setattr(res, 'headers', res.msg)
            setattr(res, 'response_version', version_table[res.version])

            response_body = res.read()
        except Exception as e:
            print("Connection to '{}' initiated with request to '{}://{}{}' failed: {}".format(
                replay_server, scheme, request_headers.get(':authority', ''), path, e))
            traceback.print_exc(file=sys.stdout)
            raise e

        try:
            setattr(res, 'headers', ProxyRequestHandler.filter_headers(res.headers))

            response_headers = [
                (':status'.encode(), str(res.status).encode()),
            ]
            for k, v in res.headers.items():
                response_headers += ((k.encode(), v.encode()),)
            self.print_info(
                request_headers,
                req_body,
                response_headers,
                response_body,
                res.status,
                res.reason)

        except Exception as e:
            print("Curating the HTTP/1 response to proxy to HTTP/3 failed: {}".format(e))
            traceback.print_exc(file=sys.stdout)
            raise e
        return response_headers, response_body

    def print_info(self, request_headers, req_body, response_headers, res_body,
                   response_status, response_reason):
        def parse_qsl(s):
            return '\n'.join(
                "%-20s %s" %
                (k, v) for k, v in urllib.parse.parse_qsl(
                    s, keep_blank_values=True))

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

    def http_event_received(self, event: H3Event) -> None:
        if isinstance(event, DataReceived):
            self.request_body += event.data
            if event.stream_ended:
                self.client_request_done_event.set()
        elif isinstance(event, HeadersReceived):
            if self.request_headers is not None:
                self.request_headers.append(event.headers)
            else:
                self.request_headers = event.headers
            if event.stream_ended:
                self.client_request_done_event.set()
        self.transmit()

    async def send_response(self) -> None:

        await self.client_request_done_event.wait()
        if self.is_h3_to_server:
            raise RuntimeError(
                "Unexpectedly received HTTP/3 to origin configuration.")
        else:
            self.response_headers, self.response_body = self._send_http1_request_to_server(
                self.request_headers, self.request_body, self.stream_id)

        try:
            self.connection.send_headers(
                stream_id=self.stream_id,
                headers=self.response_headers,
                end_stream=not self.response_body
            )
            if self.response_body:
                self.connection.send_data(
                    stream_id=self.stream_id,
                    data=self.response_body,
                    end_stream=True
                )
            self.transmit()
        except Exception as e:
            print("Transmitting the HTTP/3 response to the client failed: {}".format(e))
            traceback.print_exc(file=sys.stdout)
            raise e


class HttpQuicServerHandler(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._handlers: Dict[int, HttpRequestHandler] = {}
        self._http: Optional[HttpConnection] = None

    def http_event_received(self, event: H3Event) -> None:
        if isinstance(event, HeadersReceived) and event.stream_id not in self._handlers:
            authority = None
            headers = []
            http_version = "0.9" if isinstance(self._http, H0Connection) else "3"
            raw_path = b""
            method = ""
            protocol = None
            for header, value in event.headers:
                if header == b":authority":
                    authority = value
                    headers.append((b"host", value))
                elif header == b":method":
                    method = value.decode()
                elif header == b":path":
                    raw_path = value
                elif header == b":protocol":
                    protocol = value.decode()
                elif header and not header.startswith(b":"):
                    headers.append((header, value))

            if b"?" in raw_path:
                path_bytes, query_string = raw_path.split(b"?", maxsplit=1)
            else:
                path_bytes, query_string = raw_path, b""
            path = path_bytes.decode()
            self._quic._logger.info("HTTP request %s %s", method, path)

            # FIXME: add a public API to retrieve peer address
            client_addr = self._http._quic._network_paths[0].addr
            client = (client_addr[0], client_addr[1])

            scope: Dict
            extensions: Dict[str, Dict] = {}
            if isinstance(self._http, H3Connection):
                extensions["http.response.push"] = {}
            scope = {
                "client": client,
                "extensions": extensions,
                "headers": headers,
                "http_version": http_version,
                "method": method,
                "path": path,
                "query_string": query_string,
                "raw_path": raw_path,
                "root_path": "",
                "scheme": "https",
                "type": "http",
            }
            handler = HttpRequestHandler(
                authority=authority,
                connection=self._http,
                protocol=self,
                scope=scope,
                stream_ended=event.stream_ended,
                stream_id=event.stream_id,
                transmit=self.transmit,
                is_h3_to_server=self.h3_to_server,
                server_port=self.server_port,
            )
            self._handlers[event.stream_id] = handler
            handler.http_event_received(event)
            self.send_response_task = asyncio.create_task(handler.send_response())
        elif (
            isinstance(event, (DataReceived, HeadersReceived))
            and event.stream_id in self._handlers
        ):
            handler = self._handlers[event.stream_id]
            handler.http_event_received(event)

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ProtocolNegotiated):
            if event.alpn_protocol.startswith("h3-"):
                self._http = H3Connection(self._quic)
            elif event.alpn_protocol.startswith("hq-"):
                self._http = H0Connection(self._quic)
        elif isinstance(event, DatagramFrameReceived):
            if event.data == b"quack":
                self._quic.send_datagram_frame(b"quack-ack")

        #  pass event to the HTTP layer
        if self._http is not None:
            for http_event in self._http.handle_event(event):
                self.http_event_received(http_event)


class SessionTicketStore:
    """
    Simple in-memory store for session tickets.
    """

    def __init__(self) -> None:
        self.tickets: Dict[bytes, SessionTicket] = {}

    def add(self, ticket: SessionTicket) -> None:
        self.tickets[ticket.ticket] = ticket

    def pop(self, label: bytes) -> Optional[SessionTicket]:
        return self.tickets.pop(label, None)


def configure_http3_server(
        listen_port,
        server_port,
        https_pem,
        ca_pem,
        listening_sentinel,
        h3_to_server=False):

    HttpQuicServerHandler.cert_file = https_pem
    HttpQuicServerHandler.ca_file = ca_pem
    HttpQuicServerHandler.h3_to_server = h3_to_server
    HttpQuicServerHandler.server_port = server_port

    try:
        os.mkdir('quic_log_directory')
    except FileExistsError:
        pass
    quic_logger = QuicDirectoryLogger('quic_log_directory')
    secrets_log_file = open('tls_secrets.log', "a")
    configuration = QuicConfiguration(
        alpn_protocols=H3_ALPN,
        is_client=False,
        max_datagram_frame_size=65536,
        quic_logger=quic_logger,
        secrets_log_file=secrets_log_file,
    )

    configuration.load_cert_chain(https_pem, ca_pem)
    ticket_store = SessionTicketStore()

    # TODO
    # In 3.7: how about asyncio.run(serve(...))
    loop = asyncio.get_event_loop()
    server_side_proto = "HTTP/3" if h3_to_server else "HTTP/1"
    print(
        f"Serving HTTP/3 Proxy on 127.0.0.1:{listen_port} with pem '{https_pem}', "
        f"forwarding to 127.0.0.1:{server_port} over {server_side_proto}")
    loop.run_until_complete(
        serve(
            '0.0.0.0',
            listen_port,
            configuration=configuration,
            create_protocol=HttpQuicServerHandler,
            session_ticket_fetcher=ticket_store.pop,
            session_ticket_handler=ticket_store.add
        )
    )

    # Indicate to the caller that the quic socket is configured and listening.
    Path(listening_sentinel).touch()

    try:
        loop.run_forever()
    except KeyboardInterrupt as e:
        # The calling test_proxy.py will handle this.
        print("Handling KeyboardInterrupt")
        raise e
    except SystemExit:
        pass
