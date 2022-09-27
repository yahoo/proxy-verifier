'''
Specify h2 frame sequence.
'''
# @file
#
# Copyright 2022, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

Test.Summary = '''
Specify h2 frame sequence.
'''

#
# Test 1: Abort after DATA frame
#
r = Test.AddTestRun("Specify h2 frame sequence")
client = r.AddClientProcess("client1", "http2_frames.yaml")
server = r.AddServerProcess("server1", "http2_frames.yaml")
proxy = r.AddProxyProcess("proxy1", listen_port=client.Variables.https_port,
                          server_port=server.Variables.https_port,
                          use_ssl=True, use_http2_to_2=True)

client.Streams.stdout = "gold/client.gold"
server.Streams.stdout = "gold/server.gold"
proxy.Streams.stdout = "gold/proxy.gold"
