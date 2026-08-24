'''
Verify basic PROXY protocol functionality.
'''
# @file
#
# Copyright 2023-2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

import re


class PPTest:
    # static id for client, server and proxy processes
    test_id = 1

    def __init__(self, testBaseName, ppVersion, isHTTPS, testRunDesc=""):
        self.testRun = suite.case(testRunDesc)
        self.testBaseName = testBaseName
        self.ppVersion = ppVersion
        self.replayFile = f'replay_files/{testBaseName}_pp_v{ppVersion}.replay.yaml'
        self.isHTTPS = isHTTPS

    def setupClient(self, isHTTPS):
        self.client = self.testRun.add_client(
            f"client-{PPTest.test_id}",
            self.replayFile,
            configure_http=not isHTTPS,
            configure_https=isHTTPS,
        )

    def setupServer(self, isHTTPS):
        self.server = self.testRun.add_server(
            f"server-{PPTest.test_id}",
            self.replayFile,
            configure_http=not isHTTPS,
            configure_https=isHTTPS,
        )

    def setupProxy(self, isHTTPS):
        self.proxyListenPort = self.client.https_port if isHTTPS else self.client.http_port
        self.serverListenPort = self.server.https_port if isHTTPS else self.server.http_port
        self.proxy = self.testRun.add_proxy(
            f"proxy-{PPTest.test_id}",
            listen_port=self.proxyListenPort,
            server_port=self.serverListenPort,
            use_ssl=isHTTPS,
        )

    def setupTransactionLogsVerification(self):
        # Verify that the http trasactions are successful(not hindered by the
        # PROXY protocol processing).
        self.proxy.stdout.matches_gold(f"gold/{self.testBaseName}_proxy.gold")
        self.client.stdout.matches_gold(f"gold/{self.testBaseName}_client.gold")
        self.server.stdout.matches_gold(f"gold/{self.testBaseName}_server.gold")

    def setupPPLogsVerification(self):
        # Verify the PROXY protocol related logs
        self.client.stdout.contains(
            r"Sending PROXY header",
            "Verify that the PROXY header is sent from the client to the proxy.")

        self.proxy.stdout.contains(f"Received .* bytes of Proxy Protocol V{self.ppVersion}",
                                   "Verify that the PROXY header is received by the proxy.")
        self.proxy.stdout.contains(
            rf"PROXY TCP4 127\.0\.0\.1 127\.0\.0\.1 [0-9]+ {self.proxyListenPort}",
            "Verify the client sends a valid PROXY header.")

        self.server.stdout.contains(
            rf"Received PROXY header v{self.ppVersion}:.*\nPROXY TCP4 127\.0\.0\.1 127\.0\.0\.1 [0-9]+ {self.proxyListenPort}",
            "Verify that the server receives the PROXY header and parsed sucessfully.",
            reflags=re.MULTILINE)

    def run(self):
        self.setupClient(self.isHTTPS)
        self.setupServer(self.isHTTPS)
        self.setupProxy(self.isHTTPS)
        self.setupTransactionLogsVerification()
        self.setupPPLogsVerification()
        PPTest.test_id += 1


# Test 1: Verify the PROXY header v1 is sent and received in a HTTP transaction.
PPTest("http_single_transaction", ppVersion=1, isHTTPS=False,
       testRunDesc="Verify PROXY protocol v1 is sent and received in a HTTP connection").run()

# Test 2: Verify the PROXY header v2 is sent and received in a HTTP transaction.
PPTest("http_single_transaction", ppVersion=2, isHTTPS=False,
       testRunDesc="Verify PROXY protocol v2 is sent and received in a HTTP connection").run()

# Test 3: Verify the PROXY header v1 is sent and received in a HTTPS
# transaction.
PPTest("https_single_transaction", ppVersion=1, isHTTPS=True,
       testRunDesc="Verify PROXY protocol v1 is sent and received in a HTTPS connection").run()

# Test 4: Verify the PROXY header v2 is sent and received in a HTTPS
# transaction.
PPTest("https_single_transaction", ppVersion=2, isHTTPS=True,
       testRunDesc="Verify PROXY protocol v2 is sent and received in a HTTPS connection").run()

# Test 5: Verify the PROXY protocol is not sent when not specified in the replay
# file
case = suite.case("Verify the PROXY protocol is not sent when not specified in the replay file")

# Add configure_https=False to verify ATS client and server work when the https
# optional arguments are not provided.
client = case.add_client("no-pp-client1", "replay_files/http_single_transaction_no_pp.replay.yaml",
                         configure_https=False)
server = case.add_server("no-pp-server1", "replay_files/http_single_transaction_no_pp.replay.yaml",
                         configure_https=False)
proxy = case.add_proxy("no-pp-proxy1", listen_port=client.http_port, server_port=server.http_port)

# Verify the http transaction finishes successfully.
proxy.stdout.matches_gold("gold/http_single_transaction_proxy.gold")
client.stdout.matches_gold("gold/http_single_transaction_client.gold")
server.stdout.matches_gold("gold/http_single_transaction_server.gold")

# Verify the PROXY protocol related logs. Since the replay file does not have
# the PROXY protocol related configuration, the client, proxy and server should
# not have these logs
client.stdout.excludes("Sending PROXY header",
                       "Client should not send PROXY header if not asked to.")
proxy.stdout.excludes("Received .* bytes of Proxy Protocol",
                      "Proxy should not receive the PROXY header.")
server.stdout.excludes("Received PROXY header", "The server should not receive the PROXY header.")

#
# Test 6: Verify the PROXY v1 message can be sent and received on IPv6
# connection.
#
case = suite.case("Verify the PROXY message can be sent and received on IPv6 connection")
server = case.add_server("ipv6-server1", "replay_files/single_transaction_ipv6_pp_v1.replay.yaml",
                         use_ipv6=True)
client = case.add_client("ipv6-client1", "replay_files/single_transaction_ipv6_pp_v1.replay.yaml",
                         use_ipv6=True, http_ports=[server.http_port], other_args="--no-proxy")

# Verify successful transaction despite PROXY protocol processing
client.stdout.matches_gold("gold/ipv6_client.gold")
server.stdout.matches_gold("gold/ipv6_server.gold")

# Verify the PROXY protocol related logs
client.stdout.contains(r"Sending PROXY header",
                       "Verify that the PROXY header is sent from the client to the server.")

server.stdout.contains(f"Received PROXY header v1:.*\nPROXY TCP6 ::1 ::1 [0-9]+ {server.http_port}",
                       "Verify that the server receives the PROXY header and parsed sucessfully.",
                       reflags=re.MULTILINE)

#
# Test 7: Verify the PROXY v2 message can be sent and received on IPv6
# connection.
#
case = suite.case("Verify the PROXY message can be sent and received on IPv6 connection")
server = case.add_server("ipv6-server2", "replay_files/single_transaction_ipv6_pp_v2.replay.yaml",
                         use_ipv6=True)
client = case.add_client("ipv6-client2", "replay_files/single_transaction_ipv6_pp_v2.replay.yaml",
                         use_ipv6=True, http_ports=[server.http_port], other_args="--no-proxy")

# Verify successful transaction despite PROXY protocol processing
client.stdout.matches_gold("gold/ipv6_client.gold")
server.stdout.matches_gold("gold/ipv6_server.gold")

# Verify the PROXY protocol related logs
client.stdout.contains(r"Sending PROXY header",
                       "Verify that the PROXY header is sent from the client to the server.")

server.stdout.contains(f"Received PROXY header v2:.*\nPROXY TCP6 ::1 ::1 [0-9]+ {server.http_port}",
                       "Verify that the server receives the PROXY header and parsed sucessfully.",
                       reflags=re.MULTILINE)

# Test 8: Verify the PROXY protocol is sent with source and
# destination addresses specified in the replay file
case = suite.case(
    "Verify the PROXY protocol is sent with the source and destination specified addresses in the replay file"
)

EXPECTED_SRC_ADDRESS = "111.111.111.111"
EXPECTED_SRC_PORT = "11111"
EXPECTED_DST_ADDRESS = "222.222.222.222"
EXPECTED_DST_PORT = "22222"
EXPECTED_PROXY_HEADER = f"PROXY TCP4 {EXPECTED_SRC_ADDRESS} {EXPECTED_DST_ADDRESS} {EXPECTED_SRC_PORT} {EXPECTED_DST_PORT}"

# Add configure_https=False to verify ATS client and server work when the https
# optional arguments are not provided.
client = case.add_client("specified-addr-pp-client1",
                         "replay_files/http_pp_v1_with_address.replay.yaml", configure_https=False)
server = case.add_server("specified-addr-pp-server1",
                         "replay_files/http_pp_v1_with_address.replay.yaml", configure_https=False)
proxy = case.add_proxy("specified-addr-pp-proxy1", listen_port=client.http_port,
                       server_port=server.http_port)

# Verify the http transaction finishes successfully.
proxy.stdout.matches_gold("gold/http_single_transaction_proxy.gold")
client.stdout.matches_gold("gold/http_single_transaction_client.gold")
server.stdout.matches_gold("gold/http_single_transaction_server.gold")

# Verify the PROXY protocol related logs. Make sure the source and destination
# addresses of the PROXY header match the ones specified in the replay file
client.stdout.contains(r"Sending PROXY header",
                       "Verify that the PROXY header is sent from the client to the proxy.")

proxy.stdout.contains("Received .* bytes of Proxy Protocol",
                      "Verify that the PROXY header is received by the proxy.")
proxy.stdout.contains(
    rf"{EXPECTED_PROXY_HEADER}",
    "Verify the client sends a PROXY header with the specified source and destination addresses.")

server.stdout.contains(rf"Received PROXY header v1:.*\n{EXPECTED_PROXY_HEADER}",
                       "Verify that the server receives the PROXY header and parsed sucessfully.",
                       reflags=re.MULTILINE)


def test_uranium_suite(uranium):
    uranium.run(suite)
