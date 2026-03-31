'''
Verify verifier-client and verifier-server honor SIGINT promptly during replay.
'''
# @file
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

import os

Test.Summary = '''
Verify verifier-client and verifier-server honor SIGINT promptly during replay.
'''

verifier_script = 'verify_sigint_shutdown.py'
verifier_bin = os.environ['VERIFIER_BIN']
verifier_server = os.path.join(verifier_bin, 'verifier-server')
verifier_client = os.path.join(verifier_bin, 'verifier-client')

r = Test.AddTestRun("Verify verifier-server exits promptly on SIGINT during replay.")
r.Processes.Default.Setup.Copy(verifier_script)
r.Processes.Default.Command = \
    f'python3 {verifier_script} --mode server --verifier-server "{verifier_server}"'
r.ReturnCode = 0
r.Streams.stdout += Testers.ContainsExpression(
    'OK: server exited promptly',
    'The helper script should confirm verifier-server shuts down quickly on SIGINT.')

r = Test.AddTestRun("Verify verifier-client exits promptly on SIGINT during replay.")
r.Processes.Default.Setup.Copy(verifier_script)
r.Processes.Default.Command = \
    f'python3 {verifier_script} --mode client --verifier-client "{verifier_client}"'
r.ReturnCode = 0
r.Streams.stdout += Testers.ContainsExpression(
    'OK: client exited promptly',
    'The helper script should confirm verifier-client shuts down quickly on SIGINT.')
