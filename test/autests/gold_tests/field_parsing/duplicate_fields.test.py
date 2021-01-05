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
# Test 1: Verify correct behavior when there are duplicate HTTP fields.
#
r = Test.AddTestRun("Verify correct handling of duplicate fields in a message.")
client = r.AddClientProcess("client1", "replay_files/duplicate_fields.yaml",
                            other_args="--verbose diag")
server = r.AddServerProcess("server1", "replay_files/duplicate_fields.yaml",
                            other_args="--verbose diag")
proxy = r.AddProxyProcess("proxy1", listen_port=client.Variables.http_port,
                          server_port=server.Variables.http_port)


if Condition.IsPlatform("darwin"):
    proxy.Streams.stdout = "gold/duplicate_fields_proxy.gold_macos"
    client.Streams.stdout = "gold/duplicate_fields_client.gold_macos"
    server.Streams.stdout = "gold/duplicate_fields_server.gold_macos"
else:
    proxy.Streams.stdout = "gold/duplicate_fields_proxy.gold"
    client.Streams.stdout = "gold/duplicate_fields_client.gold"
    server.Streams.stdout = "gold/duplicate_fields_server.gold"
