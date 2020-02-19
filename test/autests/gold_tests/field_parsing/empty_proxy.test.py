'''
Verify correct handling of empty proxy nodes.
'''
# @file
#
# Copyright 2020, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#


Test.Summary = '''
Verify correct handling of empty proxy nodes.
'''

#
# Test 1: Verify correct handling of empty proxy-request and response nodes.
#
r = Test.AddTestRun("Verify correct handling of empty proxy nodes")
client = r.AddClientProcess("client1", "replay_files/empty_proxy",
                            http_ports=[8082], other_args="--verbose diag")
server = r.AddServerProcess("server1", "replay_files/empty_proxy",
                            http_ports=[8083], other_args="--verbose diag")
proxy = r.AddProxyProcess("proxy1", listen_port=8082, server_port=8083)

proxy.Streams.stdout = "gold/empty_proxy_proxy.gold"
client.Streams.stdout = "gold/empty_proxy_client.gold"
server.Streams.stdout = "gold/empty_proxy_server.gold"
