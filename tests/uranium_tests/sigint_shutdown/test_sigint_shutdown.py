'''
Verify verifier-client and verifier-server honor SIGINT promptly during replay.
'''
# @file
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

verifier_script = 'verify_sigint_shutdown.py'

case = suite.case("Verify verifier-server exits promptly on SIGINT during replay.")
process = case.add_process(
    "server-sigint",
    ["python3", verifier_script, "--mode", "server", "--verifier-server", "{verifier-server}"],
    copies=[verifier_script],
)
process.stdout.contains(
    'OK: server exited promptly',
    'The helper script should confirm verifier-server shuts down quickly on SIGINT.')

case = suite.case("Verify verifier-client exits promptly on SIGINT during replay.")
process = case.add_process(
    "client-sigint",
    ["python3", verifier_script, "--mode", "client", "--verifier-client", "{verifier-client}"],
    copies=[verifier_script],
)
process.stdout.contains(
    'OK: client exited promptly',
    'The helper script should confirm verifier-client shuts down quickly on SIGINT.')


def test_uranium_suite(uranium):
    uranium.run(suite)
