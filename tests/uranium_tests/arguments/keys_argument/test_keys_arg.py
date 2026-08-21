'''
Verify the user can white list transactions with --keys.
'''
# @file
#
# Copyright 2022-2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

#
# Test 1: Verify that without the keys argument, all transactions are sent.
#
case = suite.case("Verify all keys are sent when --keys is not used.")
client = case.add_client("client1", "five_transactions.yaml")
server = case.add_server("server1", "five_transactions.yaml")
proxy = case.add_proxy("proxy1", listen_port=client.http_port, server_port=server.http_port)

for uuid in range(1, 6):
    client.stdout.contains(f'uuid: {uuid}', f"Client has uuid {uuid}.")

#
# Test 2: Verify a single transaction can be selected with --keys.
#
case = suite.case("Verify all keys are sent when --keys is not used.")
client = case.add_client("client2", "five_transactions.yaml", other_args="--keys 2")
server = case.add_server("server2", "five_transactions.yaml")
proxy = case.add_proxy("proxy2", listen_port=client.http_port, server_port=server.http_port)

client.stdout.contains('uuid: 2', "Client has uuid 2.")

for uuid in [1, 3, 4, 5, 6]:
    client.stdout.excludes(f'uuid: {uuid}', f"Client has uuid {uuid}.")

#
# Test 3: Verify a multiple transactions can be selected with --keys.
#
case = suite.case("Verify multiple transactions can be sent with --keys.")
client = case.add_client("client3", "five_transactions.yaml", other_args="--keys 3 5")
server = case.add_server("server3", "five_transactions.yaml")
proxy = case.add_proxy("proxy3", listen_port=client.http_port, server_port=server.http_port)

for uuid in [3, 5]:
    client.stdout.contains(f'uuid: {uuid}', f"Client has uuid {uuid}.")

for uuid in [1, 2, 4]:
    client.stdout.excludes(f'uuid: {uuid}', f"Client has uuid {uuid}.")

#
# Test 4: Verify we can handle the situation if no transactions exist for the
# key.
#
case = suite.case("Verify no transactions are sent if none match the key.")
client = case.add_client("client4", "five_transactions.yaml", other_args="--keys does_not_exist")
server = case.add_server("server4", "five_transactions.yaml")
proxy = case.add_proxy("proxy4", listen_port=client.http_port, server_port=server.http_port)

client.stdout.contains('Parsed 0 transactions', "Verify no transactions are found")


def test_uranium_suite(uranium):
    uranium.run(suite)
