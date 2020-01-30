'''
Verify correct handling of duplicate fields in a message.
'''
# @file
#
# Copyright 2020, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#


Test.Summary = '''
Verify correct handling of duplicate fields in a message.
'''

#
# Test 1: Verify correct behavior with a YAML-specified replay file.
#
r = Test.AddTestRun("Verify correct handling of duplicate fields in a message.")
client = r.AddClientProcess("client1", "replay_files/duplicate_fields",
                            http_ports=[8082], other_args="--verbose diag")
server = r.AddServerProcess("server1", "replay_files/duplicate_fields",
                            http_ports=[8083], other_args="--verbose diag")
proxy = r.AddProxyProcess("proxy1", listen_port=8082, server_port=8083)


proxy.Streams.stdout = "gold/duplicate_fields_proxy.gold"
client.Streams.stdout = "gold/duplicate_fields_client.gold"
server.Streams.stdout = "gold/duplicate_fields_server.gold"
