'''
Verify basic HTTP/3 functionality.
'''
# @file
#
# Copyright 2021, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

Test.Summary = '''
Verify basic HTTP/3 functionality.
'''

r_http3_args = "--poll-timeout 10000"

#
# Test 1: Verify correct behavior of a various HTTP/3 transactions.
#
r = Test.AddTestRun("Verify HTTP/3")
client = r.AddClientProcess("client1", "replay_files/http3_to_http1.yaml", other_args=r_http3_args,
                            verbose=False)
server = r.AddServerProcess("server1", "replay_files/http3_to_http1.yaml", other_args=r_http3_args,
                            verbose=False)
proxy = r.AddProxyProcess("proxy1", listen_port=client.Variables.http3_port,
                          server_port=server.Variables.http_port, use_ssl=True, use_http3_to_1=True)

client.Streams.stdout += Testers.ExcludesExpression(
    "Violation:", "There should be no verification errors because there are none added.")

server.Streams.stdout += Testers.ExcludesExpression(
    "Violation:", "There should be no verification errors because there are none added.")

#
# Filter stable verification lines before comparing against gold. Raw HTTP/3
# output includes asynchronous debug ordering and large generated bodies that
# are both expensive and noisy to compare directly.
#
r = Test.AddTestRun("Verify filtered HTTP/3 output")
client_output = client.Streams.stdout.AbsTestPath
server_output = server.Streams.stdout.AbsTestPath
r.Processes.Default.Setup.Copy("filter_http3_output.py")
r.Processes.Default.Command = f"python3 filter_http3_output.py {client_output} {server_output}"
r.Streams.stdout = "gold/http3_to_http1_client_server.gold"

#
# Keep the proxy coverage focused on request and response headers. The proxy
# output includes generated body bytes, so filtering avoids comparing the large
# 300 KB payloads while still catching missing or incorrect headers.
#
r = Test.AddTestRun("Verify filtered HTTP/3 proxy output")
proxy_output = proxy.Streams.stdout.AbsTestPath
r.Processes.Default.Setup.Copy("filter_http3_output.py")
r.Processes.Default.Command = f"python3 filter_http3_output.py --proxy-output {proxy_output}"
r.Streams.stdout = "gold/http3_to_http1_proxy.gold"

#
# Test 2: Verify correct verification failure behaviors.
#
r = Test.AddTestRun("Verify HTTP/3 with verification failures")
client = r.AddClientProcess("client2", "replay_files/http3_to_http1_failures.yaml",
                            other_args=r_http3_args)
server = r.AddServerProcess("server2", "replay_files/http3_to_http1_failures.yaml",
                            other_args=r_http3_args)
proxy = r.AddProxyProcess("proxy2", listen_port=client.Variables.http3_port,
                          server_port=server.Variables.http_port, use_ssl=True, use_http3_to_1=True)

client.ReturnCode = 1

client.Streams.stdout += Testers.ContainsExpression(
    'Equals Violation: Different. .* Field Name: "x-equal-header", Correct Value: "other_content", Actual Value: "some_content"',
    "There should be an equal violation for x-equal-header.")

client.Streams.stdout += Testers.ContainsExpression(
    'Equals Success: .* Field Name: "x-response-header", Value: "response"',
    "Verification should be happy with the X-Response-Header.")

client.Streams.stdout += Testers.ContainsExpression(
    'Absence Violation: Present. .* Field Name: "x-added-header", Value: "1"',
    "There should be an absence violation for X-Added-Header because it will be present.")

client.Streams.stdout += Testers.ContainsExpression(
    'Presence Violation: Absent. .* Field Name: "x-deleted-header"',
    "There should be an presence violation for X-Deleted-Header because it will be absent.")

client.Streams.stdout += Testers.ContainsExpression(
    'HTTP/3 Status Violation: expected 502 got 200',
    "There should a status violation for an unexpected 502 response.")
