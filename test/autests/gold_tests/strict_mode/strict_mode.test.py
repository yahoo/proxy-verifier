'''
Verify strict mode functionality.
'''
# @file
#
# Copyright 2020, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#


Test.Summary = '''
Verify strict mode functionality.
'''

#
# Test 1: Verify there are no warnings when the fields match.
#
r = Test.AddTestRun("Verify strict mode is silent when the fields match.")
client = r.AddClientProcess("client1", "replay_files/fields_match",
                            http_ports=[8080], other_args="--verbose diag --strict")
server = r.AddServerProcess("server1", "replay_files/fields_match",
                            http_ports=[8081], other_args="--verbose diag --strict")
proxy = r.AddProxyProcess("proxy1", listen_port=8080, server_port=8081)

if Condition.IsPlatform("darwin"):
    proxy.Streams.stdout = "gold/fields_match_proxy.gold_macos"
else:
    proxy.Streams.stdout = "gold/fields_match_proxy.gold"

client.Streams.stdout = Testers.ExcludesExpression(
        "Violation:",
        "There should be no verification errors because there are none added.")

server.Streams.stdout = Testers.ExcludesExpression(
        "Violation:",
        "There should be no verification errors because there are none added.")

#
# Test 2: Verify there are warnings when the fields don't match.
#
r = Test.AddTestRun("Verify strict mode warns when the fields don't match")
client = r.AddClientProcess("client2", "replay_files/fields_differ",
                            http_ports=[8082], other_args="--verbose diag --strict")
server = r.AddServerProcess("server2", "replay_files/fields_differ",
                            http_ports=[8083], other_args="--verbose diag --strict")
proxy = r.AddProxyProcess("proxy2", listen_port=8082, server_port=8083)

if Condition.IsPlatform("darwin"):
    proxy.Streams.stdout = "gold/fields_differ_proxy.gold_macos"
else:
    proxy.Streams.stdout = "gold/fields_differ_proxy.gold"

client.Streams.stdout = Testers.ContainsExpression(
        'Violation: Absent. Key: "cb9b4e94-5d42-43d4-8545-320033298ba2-226381119", Name: "x-thisresponseheaderwontexist", Correct Value: "ThereforeTheClientShouldWarn',
        "There should be a warning about the missing response header")

server.Streams.stdout = Testers.ContainsExpression(
        'Violation: Absent. Key: "cb9b4e94-5d42-43d4-8545-320033298ba2-226381119", Name: "x-thisrequestheaderwontexist", Correct Value: "ThereforeTheServerShouldWarn',
        "There should be a warning about the missing proxy request header.")

client.ReturnCode = 1
server.ReturnCode = 1
