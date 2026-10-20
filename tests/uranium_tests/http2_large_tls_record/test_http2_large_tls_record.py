'''
Verify that the server reads the end of a TLS record larger than its read buffer.
'''
# @file
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)

#
# Test 1: A proxy may coalesce frames from several HTTP/2 streams into one TLS
# record larger than the server's SSL_read buffer. OpenSSL then holds the end
# of the record decrypted after the first SSL_read, where poll(2) cannot see
# it. The server must still read it rather than wait for a socket that the
# peer, having sent everything, never makes readable again.
#
case = suite.case("Verify the server reads requests buffered by OpenSSL past a poll")
server = case.add_server("server", "http2_large_tls_record.yaml", other_args="--verbose diag")
sender_script = 'send_coalesced_h2_requests.py'
sender = case.add_process(
    "sender",
    ["python3", sender_script, "127.0.0.1", server.https_port],
    copies=[sender_script],
)
# The client runs the same replay after the helper finishes. It acts as a
# positive control for the replay file, and its presence also makes Uranium
# start the server and wait for its listener before the helper runs.
client = case.add_client("client", "http2_large_tls_record.yaml", https_ports=[server.https_port],
                         other_args="--no-proxy")

server.stdout.contains("Ready with 2 transactions.",
                       "The server should have parsed both transactions.")
sender.stdout.contains("Sending both requests in one .*-byte TLS record.",
                       "The helper should send both requests in a single TLS record.")
sender.stdout.contains("Received a complete response on stream 1.",
                       "The server should answer the request that ends early in the record.")
sender.stdout.contains("Received a complete response on stream 3.",
                       "The server should answer the request that ends past its read buffer.")
sender.stdout.excludes("Did not receive",
                       "The helper should receive every response it waits for.")
client.stdout.contains("2 transactions in 1 session ",
                       "The client should run both transactions of the replay.")
client.stdout.excludes("Violation:", "There should be no verification errors.")
server.stdout.excludes("Violation:", "There should be no verification errors.")


def test_uranium_suite(uranium):
    uranium.run(suite)
