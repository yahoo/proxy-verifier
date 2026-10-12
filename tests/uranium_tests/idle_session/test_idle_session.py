'''
Verify that an idle keep-alive connection does not hold a server thread.
'''
# @file
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)

case = suite.case("Verify the server serves other sessions while a connection is idle.")
# A single worker thread makes any thread held by the idle connection visible:
# the second session would then wait for the first session to finish. The
# client talks to the server directly so that each client session is exactly
# one server connection.
server = case.add_server("server", "idle-session.yaml",
                         other_args="--thread-limit 1 --verbose diag")
# The first session idles for 3 seconds. If its connection held the only
# server thread, the second session's response would not arrive within the
# client's 1 second poll timeout.
client = case.add_client("client", "idle-session.yaml", http_ports=[server.http_port],
                         other_args="--no-proxy --poll-timeout 1000")

server.stdout.contains("Ready with 3 transactions.",
                       "The server should have parsed 3 transactions.")

server.stdout.contains("Parking idle session.",
                       "The server should park the first session's idle connection.")

client.stdout.contains("3 transactions in 2 sessions",
                       "The client should have run all transactions.")

client.stdout.excludes("Poll timed out",
                       "The second session should get its response while the first session idles.")
client.stdout.excludes("Violation:", "There should be no verification errors.")
server.stdout.excludes("Violation:", "There should be no verification errors.")


def test_uranium_suite(uranium):
    uranium.run(suite)
