'''
Verify server-side request presence expectation behavior.
'''
# @file
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

Test.Summary = '''
Verify server-side request presence expectation behavior.
'''

missing_present_message = ('never reached the verifier-server before shutdown even though "expect" '
                           'was explicitly set to "present"')

r = Test.AddTestRun("Verify expect: absent succeeds when the proxy replies directly")
client = r.AddClientProcess("client1", "replay_files/http1_cache_hit.yaml", configure_https=False)
server = r.AddServerProcess("server1", "replay_files/http1_cache_hit.yaml", configure_https=False)
proxy = r.AddProxyProcess("proxy1", listen_port=client.Variables.http_port,
                          server_port=server.Variables.http_port)

client.Streams.stdout += Testers.ContainsExpression(
    "Received an HTTP/1 200 response for key cache-hit-1",
    "The client should receive the direct cached response.")
server.Streams.stdout += Testers.ExcludesExpression(
    'unexpectedly reached the verifier-server',
    "The server should not report a forbidden request arrival.")
server.Streams.stdout += Testers.ExcludesExpression(
    'were never processed before shutdown',
    "An absent expectation should not count as an unprocessed verification.")
proxy.Streams.stdout += Testers.ContainsExpression(
    'Serving local response for key cache-hit-1 with status 200.',
    "The shared proxy should synthesize the cached response locally.")

client.ReturnCode = 0
server.ReturnCode = 0

r = Test.AddTestRun("Verify expect: present succeeds when the proxy forwards the request")
client = r.AddClientProcess("client2", "replay_files/http1_present_success.yaml",
                            configure_https=False)
server = r.AddServerProcess("server2", "replay_files/http1_present_success.yaml",
                            configure_https=False)
r.AddProxyProcess("proxy2", listen_port=client.Variables.http_port,
                  server_port=server.Variables.http_port)

client.Streams.stdout += Testers.ContainsExpression(
    "Received an HTTP/1 200 response for key present-http1-1",
    "The client should receive the upstream response when the request is forwarded.")
server.Streams.stdout += Testers.ExcludesExpression(
    missing_present_message,
    "The server should not report a missing request when the request arrives.")

client.ReturnCode = 0
server.ReturnCode = 0

r = Test.AddTestRun("Verify expect: present fails when the proxy replies directly")
client = r.AddClientProcess("client3", "replay_files/http1_present_cache_hit.yaml",
                            configure_https=False)
server = r.AddServerProcess("server3", "replay_files/http1_present_cache_hit.yaml",
                            configure_https=False)
proxy = r.AddProxyProcess("proxy3", listen_port=client.Variables.http_port,
                          server_port=server.Variables.http_port)

client.Streams.stdout += Testers.ContainsExpression(
    "Received an HTTP/1 200 response for key present-cache-hit-1",
    "The client should still receive the direct cached response.")
server.Streams.stdout += Testers.ContainsExpression(
    missing_present_message, "The server should fail when an expected request never arrives.")
server.Streams.stdout += Testers.ExcludesExpression(
    'were never processed before shutdown',
    "The explicit present failure should not fall back to the generic unprocessed check.")
proxy.Streams.stdout += Testers.ContainsExpression(
    'Serving local response for key present-cache-hit-1 with status 200.',
    "The shared proxy should synthesize the cached response locally.")

client.ReturnCode = 0
server.ReturnCode = 1

r = Test.AddTestRun("Verify expect: present still fails with --allow-unprocessed-verifications")
client = r.AddClientProcess("client4", "replay_files/http1_present_cache_hit.yaml",
                            configure_https=False)
server = r.AddServerProcess("server4", "replay_files/http1_present_cache_hit.yaml",
                            configure_https=False, other_args="--allow-unprocessed-verifications")
proxy = r.AddProxyProcess("proxy4", listen_port=client.Variables.http_port,
                          server_port=server.Variables.http_port)

server.Streams.stdout += Testers.ContainsExpression(
    missing_present_message, "The allow flag should not suppress explicit present failures.")
server.Streams.stdout += Testers.ExcludesExpression(
    'were never processed before shutdown',
    "The allow flag is not involved because this is not a generic "
    "unprocessed verification failure.")
proxy.Streams.stdout += Testers.ContainsExpression(
    'Serving local response for key present-cache-hit-1 with status 200.',
    "The shared proxy should synthesize the cached response locally.")

client.ReturnCode = 0
server.ReturnCode = 1

r = Test.AddTestRun("Verify omitted expect allows the proxy to reply directly")
client = r.AddClientProcess("client5", "replay_files/http1_unspecified_cache_hit.yaml",
                            configure_https=False)
server = r.AddServerProcess("server5", "replay_files/http1_unspecified_cache_hit.yaml",
                            configure_https=False)
proxy = r.AddProxyProcess("proxy5", listen_port=client.Variables.http_port,
                          server_port=server.Variables.http_port)

client.Streams.stdout += Testers.ContainsExpression(
    "Received an HTTP/1 200 response for key unspecified-cache-hit-1",
    "The client should receive the direct cached response.")
server.Streams.stdout += Testers.ExcludesExpression(
    missing_present_message,
    "No explicit presence expectation should mean no missing-request failure.")
server.Streams.stdout += Testers.ExcludesExpression(
    'were never processed before shutdown',
    "Without request verification rules, omitting expect should not trigger "
    "an unprocessed verification failure.")
proxy.Streams.stdout += Testers.ContainsExpression(
    'Serving local response for key unspecified-cache-hit-1 with status 200.',
    "The shared proxy should synthesize the cached response locally.")

client.ReturnCode = 0
server.ReturnCode = 0

r = Test.AddTestRun("Verify expect: absent fails when HTTP/1 traffic reaches the server")
client = r.AddClientProcess("client6", "replay_files/http1_violation.yaml", configure_https=False)
server = r.AddServerProcess("server6", "replay_files/http1_violation.yaml", configure_https=False)
r.AddProxyProcess("proxy6", listen_port=client.Variables.http_port,
                  server_port=server.Variables.http_port)

client.Streams.stdout += Testers.ContainsExpression(
    "Received an HTTP/1 404 response for key absent-http1-1",
    "The client should receive the fallback 404 when the forbidden request arrives upstream.")
server.Streams.stdout += Testers.ContainsExpression(
    'Proxy request with key "absent-http1-1" unexpectedly reached the verifier-server',
    "The server should fail as soon as the forbidden request arrives.")

client.ReturnCode = 0
server.ReturnCode = 1

r = Test.AddTestRun("Verify expect: absent still honors an explicit server-response")
client = r.AddClientProcess("client7", "replay_files/http1_explicit_response.yaml",
                            configure_https=False)
server = r.AddServerProcess("server7", "replay_files/http1_explicit_response.yaml",
                            configure_https=False)
r.AddProxyProcess("proxy7", listen_port=client.Variables.http_port,
                  server_port=server.Variables.http_port)

client.Streams.stdout += Testers.ContainsExpression(
    "Received an HTTP/1 418 response for key absent-http1-explicit",
    "The client should receive the configured response when the forbidden request arrives.")
server.Streams.stdout += Testers.ContainsExpression(
    'Proxy request with key "absent-http1-explicit" unexpectedly reached the verifier-server',
    "The server should still fail when the forbidden request arrives.")

client.ReturnCode = 0
server.ReturnCode = 1

r = Test.AddTestRun("Verify expect: absent fails for HTTP/2 traffic reaching the server")
client = r.AddClientProcess("client8", "replay_files/http2_violation.yaml")
server = r.AddServerProcess("server8", "replay_files/http2_violation.yaml")
r.AddProxyProcess("proxy8", listen_port=client.Variables.https_port,
                  server_port=server.Variables.https_port, use_ssl=True, use_http2_to_2=True)

client.Streams.stdout += Testers.ContainsExpression(
    "Received an HTTP/2 response for key absent-http2-1 with stream id 1:",
    "The HTTP/2 client should receive the response generated for the forbidden upstream arrival.")
server.Streams.stdout += Testers.ContainsExpression(
    'Proxy request with key "absent-http2-1" unexpectedly reached the verifier-server',
    "The server should fail when the forbidden HTTP/2 request arrives.")

client.ReturnCode = 0
server.ReturnCode = 1

r = Test.AddTestRun("Verify present expectations still require server-response")
server = r.AddDefaultServerProcess("server9", "replay_files/missing_server_response.yaml",
                                   configure_https=False)

server.Streams.stdout += Testers.ContainsExpression(
    'does not have a server response',
    "Transactions without expect: absent should still require a server-response node.")
server.ReturnCode = 1
