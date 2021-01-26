'''
Verify the example replay file from the README.
'''
# @file
#
# Copyright 2021, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

import os
from os.path import dirname

Test.Summary = '''
Verify the example replay file from the README.
'''

#
# Test 1: Verify that we're testing with the example replay file
# that is in the README.
#
r = Test.AddTestRun("Verify the tested replay file is in README.md.")
verifier_script = 'verify_example_replay_contents.py'
repo_dir = dirname(dirname(dirname(Test.TestRoot)))
readme_path = os.path.join(repo_dir, 'README.md')
example_yaml = 'example_replay.yaml'
r.Processes.Default.Setup.Copy(verifier_script)
r.Processes.Default.Setup.Copy(example_yaml)

r.Processes.Default.Command = f'python3 {verifier_script} {example_yaml} {readme_path}'
r.ReturnCode = 0
r.Streams.stdout += Testers.ContainsExpression(
        'Good',
        f'The contents of {example_yaml} should be in {readme_path}')

#
# Test 2: Verify correct behavior of a single client-side HTTP/2 transaction.
#
r = Test.AddTestRun("Verify the example replay file from the README.")
client = r.AddClientProcess("client", example_yaml)
server = r.AddServerProcess("server", example_yaml)

# The test proxy is not featureful enough to handle both HTTP/1 and HTTP/2
# traffic. Thankfully this is easily addressed by running a separate process
# for each.
proxy = r.AddProxyProcess("proxy_http", listen_port=client.Variables.http_port,
                          server_port=server.Variables.http_port)
proxy = r.AddProxyProcess("proxy_https", listen_port=client.Variables.https_port,
                          server_port=server.Variables.https_port,
                          use_ssl=True, use_http2_to_2=True)

client.Streams.stdout = "gold/doctest_client.gold"
server.Streams.stdout = "gold/doctest_server.gold"

client.Streams.stdout += Testers.ExcludesExpression(
        "Violation:",
        "There should be no verification errors because there are none added.")

server.Streams.stdout += Testers.ExcludesExpression(
        "Violation:",
        "There should be no verification errors because there are none added.")
