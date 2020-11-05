'''
Verify the user can white list transactions with --keys.
'''
# @file
#
# Copyright 2020, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#


Test.Summary = '''
Verify the user can white list transactions with --keys.
'''

#
# Test 1: Verify that without the keys argument, all transactions are sent.
#
r = Test.AddTestRun("Verify all keys are sent when --keys is not used.")
client = r.AddClientProcess("client1", "five_transactions.yaml",
                            http_ports=[8082],
                            other_args="--verbose diag")
server = r.AddServerProcess("server1", "five_transactions.yaml",
                            http_ports=[8083], other_args="--verbose diag")
proxy = r.AddProxyProcess("proxy1", listen_port=8082, server_port=8083)

for uuid in range(1, 6):
    client.Streams.stdout += Testers.ContainsExpression(
            '- "uuid": "{}"'.format(uuid),
            "Client has uuid {}.".format(uuid))

#
# Test 2: Verify a single transaction can be selected with --keys.
#
r = Test.AddTestRun("Verify all keys are sent when --keys is not used.")
client = r.AddClientProcess("client2", "five_transactions.yaml",
                            http_ports=[8082],
                            other_args="--keys 2 --verbose diag")
server = r.AddServerProcess("server2", "five_transactions.yaml",
                            http_ports=[8083], other_args="--verbose diag")
proxy = r.AddProxyProcess("proxy2", listen_port=8082, server_port=8083)

client.Streams.stdout += Testers.ContainsExpression(
        '- "uuid": "2"',
        "Client has uuid 2.")

for uuid in [1, 3, 4, 5, 6]:
    client.Streams.stdout += Testers.ExcludesExpression(
            '- "uuid": "{}"'.format(uuid),
            "Client has uuid {}.".format(uuid))

#
# Test 3: Verify a multiple transactions can be selected with --keys.
#
r = Test.AddTestRun("Verify all keys are sent when --keys is not used.")
client = r.AddClientProcess("client3", "five_transactions.yaml",
                            http_ports=[8082],
                            other_args="--keys 3 5 --verbose diag")
server = r.AddServerProcess("server3", "five_transactions.yaml",
                            http_ports=[8083], other_args="--verbose diag")
proxy = r.AddProxyProcess("proxy3", listen_port=8082, server_port=8083)

for uuid in [3, 5]:
    client.Streams.stdout += Testers.ContainsExpression(
            '- "uuid": "{}"'.format(uuid),
            "Client has uuid {}.".format(uuid))

for uuid in [1, 2, 4]:
    client.Streams.stdout += Testers.ExcludesExpression(
            '- "uuid": "{}"'.format(uuid),
            "Client has uuid {}.".format(uuid))
