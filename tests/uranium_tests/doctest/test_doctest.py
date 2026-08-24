'''
Verify the example replay file from the README.
'''
# @file
#
# Copyright 2021-2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

#
# Test 1: Verify that we're testing with the example replay file
# that is in the README.
#
case = suite.case("Verify the tested replay file is in README.md.")
verifier_script = 'verify_example_replay_contents.py'
readme_path = suite.module_path.parents[3] / 'README.md'
example_yaml = 'example_replay.yaml'
process = case.add_process(
    "verify-readme-example",
    ["python3", verifier_script, example_yaml, readme_path],
    copies=[verifier_script, example_yaml],
)
process.stdout.contains('Good', f'The contents of {example_yaml} should be in {readme_path}')

#
# Test 2: Verify correct behavior of a single client-side HTTP/2 transaction.
#
case = suite.case("Verify the example replay file from the README.")
client = case.add_client("client", example_yaml)
server = case.add_server("server", example_yaml)

# The test proxy is not featureful enough to handle both HTTP/1 and HTTP/2
# traffic. Thankfully this is easily addressed by running a separate process
# for each.
proxy = case.add_proxy("proxy_http", listen_port=client.http_port, server_port=server.http_port)
proxy = case.add_proxy("proxy_https", listen_port=client.https_port, server_port=server.https_port,
                       use_ssl=True, use_http2_to_2=True)

client.stdout.matches_gold("gold/doctest_client.gold")
server.stdout.matches_gold("gold/doctest_server.gold")

client.stdout.excludes("Violation:",
                       "There should be no verification errors because there are none added.")

server.stdout.excludes("Violation:",
                       "There should be no verification errors because there are none added.")


def test_uranium_suite(uranium):
    uranium.run(suite)
