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
client = r.AddClientProcess("client1", "replay_files/yaml_specified.yaml")
server = r.AddServerProcess("server1", "replay_files/yaml_specified.yaml")
proxy = r.AddProxyProcess("proxy1", listen_port=client.Variables.http_port,
                          server_port=server.Variables.http_port)


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
client = r.AddClientProcess("client2", "replay_files/transaction_fields.yaml")
server = r.AddServerProcess("server2", "replay_files/transaction_fields.yaml")
proxy = r.AddProxyProcess("proxy2", listen_port=client.Variables.http_port,
                          server_port=server.Variables.http_port)

proxy.Streams.stdout = "gold/transaction_fields_proxy.gold"
client.Streams.stdout = "gold/transaction_fields_client.gold"
server.Streams.stdout = "gold/transaction_fields_server.gold"
