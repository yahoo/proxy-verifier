'''
Verify correct TLS client and server verification behavior.
'''
# @file
#
# Copyright 2021-2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

#
# Test 1: Verify that both the client and server can verify the proxy
#         if specified to do so in the "tls" node.
#
case = suite.case("Verify parsing of a YAML-specified replay file")
client = case.add_client("client1", "replay_files/mtls.yaml")
server = case.add_server("server1", "replay_files/mtls.yaml")
proxy = case.add_proxy("proxy1", listen_port=client.https_port, server_port=server.https_port,
                       use_ssl=True)

client.stdout.contains(r"Proxy TLS verification result: 0 \(X509_V_OK\)",
                       "Verify that the client verified the proxy's cert.")

server.stdout.contains("Sending a certificate request to client with SNI: bob",
                       "Verify that the server requested a cert from the proxy.")
server.stdout.contains("Client TLS verification result for client with SNI bob: passed",
                       "Verify that the proxy's cert was verified.")


def test_uranium_suite(uranium):
    uranium.run(suite)
