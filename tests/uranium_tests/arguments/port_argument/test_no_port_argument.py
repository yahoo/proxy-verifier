'''
Verify there is an error if the user provides no port arguments.
'''
# @file
#
# Copyright 2021-2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

#
# Test 1: Verify the client complains if no ports are provided.
#
case = suite.case('Verify the client complains if no ports are provided.')
client = case.add_client("client1", "not_used.yaml", configure_http=False, configure_https=False,
                         configure_http3=False)
client.stdout.contains(
    'Must provide at least one of "--connect-http", "--connect-https", or '
    '"--connect-http3" arguments', 'The client should explain that a port argument is required')
client.expect_return_codes(1)

#
# Test 2: Verify the server complains if no ports are provided.
#
case = suite.case('Verify the server complains if no ports are provided.')
server = case.add_server("server1", "not_used.yaml", configure_http=False, configure_https=False,
                         configure_http3=False)
server.stdout.contains(
    'Must provide at least one of "--listen-http", "--listen-https", or '
    '"--listen-http3" arguments', 'The server should explain that a port argument is required')
server.expect_return_codes(1)


def test_uranium_suite(uranium):
    uranium.run(suite)
