'''
Verify correct parsing of YAML replay files.
'''
# @file
#
# Copyright 2020, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#


Test.Summary = '''
Verify correct parsing of a YAML replay files.
'''

#
# Test 1: Verify correct behavior with a YAML-specified replay file.
#
r = Test.AddTestRun("Verify parsing of a YAML-specified replay file")
client = r.AddClientProcess("client1", "replay_files/yaml_specified",
                            http_ports=[8082], other_args="--verbose diag")
server = r.AddServerProcess("server1", "replay_files/yaml_specified",
                            http_ports=[8083], other_args="--verbose diag")
proxy = r.AddProxyProcess("proxy1", listen_port=8082, server_port=8083)


if Condition.IsPlatform("darwin"):
    proxy.Streams.stdout = "gold/yaml_specified_proxy.gold_macos"
    client.Streams.stdout = "gold/yaml_specified_client.gold_macos"
    server.Streams.stdout = "gold/yaml_specified_server.gold_macos"
else:
    proxy.Streams.stdout = "gold/yaml_specified_proxy.gold"
    client.Streams.stdout = "gold/yaml_specified_client.gold"
    server.Streams.stdout = "gold/yaml_specified_server.gold"

# These expect verification errors.
client.ReturnCode = 1
server.ReturnCode = 1

#
# Test 2: Verify correct parsing of transaction-level fields.
#
r = Test.AddTestRun("Verify parsing of transaction-level fields")
client = r.AddClientProcess("client2", "replay_files/transaction_fields",
                            http_ports=[8082], other_args="--verbose diag")
server = r.AddServerProcess("server2", "replay_files/transaction_fields",
                            http_ports=[8083], other_args="--verbose diag")
proxy = r.AddProxyProcess("proxy2", listen_port=8082, server_port=8083)

if Condition.IsPlatform("darwin"):
    proxy.Streams.stdout = "gold/transaction_fields_proxy.gold_macos"
    client.Streams.stdout = "gold/transaction_fields_client.gold_macos"
    server.Streams.stdout = "gold/transaction_fields_server.gold_macos"
else:
    proxy.Streams.stdout = "gold/transaction_fields_proxy.gold"
    client.Streams.stdout = "gold/transaction_fields_client.gold"
    server.Streams.stdout = "gold/transaction_fields_server.gold"
