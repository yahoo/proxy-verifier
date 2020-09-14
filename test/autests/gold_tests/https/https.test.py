'''
Verify basic HTTPS functionality.
'''
# @file
#
# Copyright 2020, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#


# The Python OpenSSL library used by the test proxy on the Mac fails with a
# not-implemented error:
# Traceback (most recent call last):
#   File "/tmp/sbpv/http2/proxy1/test_proxy.py", line 60, in <module>
#     sys.exit(main())
#   File "/tmp/sbpv/http2/proxy1/test_proxy.py", line 46, in main
#     proxy_http2.configure_http2_server(args.listen_port, args.server_port, args.https_pem)
#   File "/Users/bneradt/project_not_synced/src/proxy-verifier/test/autests/gold_tests/autest-site/proxy_http2.py", line 188, in configure_http2_server
#     context.set_npn_advertise_callback(npn_advertise_cb)
#   File "/Users/bneradt/.local/share/virtualenvs/autests-Wg7FsRw_/lib/python3.8/site-packages/OpenSSL/SSL.py", line 666, in explode
#     raise NotImplementedError(error)
# NotImplementedError: NPN not available
Test.SkipUnless(Condition.IsPlatform("linux"))

Test.Summary = '''
Verify basic HTTPS functionality.
'''

r = Test.AddTestRun("Verify processing of a simple HTTPS transaction")
client = r.AddClientProcess("client1", "replay_files/single_transaction", https_ports=[4443], other_args="--verbose diag")
server = r.AddServerProcess("server1", "replay_files/single_transaction", https_ports=[4444], other_args="--verbose diag")
proxy = r.AddProxyProcess("proxy1", listen_port=4443, server_port=4444, use_ssl=True)

proxy.Streams.stdout = "gold/single_transaction_proxy.gold"

client.Streams.stdout = "gold/single_transaction_client.gold"
client.Streams.stdout += Testers.ExcludesExpression(
        "Violation:",
        "There should be no verification errors because there are none added.")

server.Streams.stdout = "gold/single_transaction_server.gold"
server.Streams.stdout += Testers.ExcludesExpression(
        "Violation:",
        "There should be no verification errors because there are none added.")
