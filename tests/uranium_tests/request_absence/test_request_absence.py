'''
Verify server-side request presence expectation behavior.
'''
# @file
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

missing_present_message = ('never reached the verifier-server before shutdown even though "expect" '
                           'was explicitly set to "present"')

case = suite.case("Verify expect: absent succeeds when the proxy replies directly")
client = case.add_client("client1", "replay_files/http1_cache_hit.yaml", configure_https=False)
server = case.add_server("server1", "replay_files/http1_cache_hit.yaml", configure_https=False)
proxy = case.add_proxy("proxy1", listen_port=client.http_port, server_port=server.http_port)

client.stdout.contains("Received an HTTP/1 200 response for key cache-hit-1",
                       "The client should receive the direct cached response.")
server.stdout.excludes('unexpectedly reached the verifier-server',
                       "The server should not report a forbidden request arrival.")
server.stdout.excludes('were never processed before shutdown',
                       "An absent expectation should not count as an unprocessed verification.")
proxy.stdout.contains('Serving local response for key cache-hit-1 with status 200.',
                      "The shared proxy should synthesize the cached response locally.")

client.expect_return_codes(0)
server.expect_return_codes(0)

case = suite.case("Verify expect: present succeeds when the proxy forwards the request")
client = case.add_client("client2", "replay_files/http1_present_success.yaml",
                         configure_https=False)
server = case.add_server("server2", "replay_files/http1_present_success.yaml",
                         configure_https=False)
case.add_proxy("proxy2", listen_port=client.http_port, server_port=server.http_port)

client.stdout.contains(
    "Received an HTTP/1 200 response for key present-http1-1",
    "The client should receive the upstream response when the request is forwarded.")
server.stdout.excludes(missing_present_message,
                       "The server should not report a missing request when the request arrives.")

client.expect_return_codes(0)
server.expect_return_codes(0)

case = suite.case("Verify expect: present fails when the proxy replies directly")
client = case.add_client("client3", "replay_files/http1_present_cache_hit.yaml",
                         configure_https=False)
server = case.add_server("server3", "replay_files/http1_present_cache_hit.yaml",
                         configure_https=False)
proxy = case.add_proxy("proxy3", listen_port=client.http_port, server_port=server.http_port)

client.stdout.contains("Received an HTTP/1 200 response for key present-cache-hit-1",
                       "The client should still receive the direct cached response.")
server.stdout.contains(missing_present_message,
                       "The server should fail when an expected request never arrives.")
server.stdout.excludes(
    'were never processed before shutdown',
    "The explicit present failure should not fall back to the generic unprocessed check.")
proxy.stdout.contains('Serving local response for key present-cache-hit-1 with status 200.',
                      "The shared proxy should synthesize the cached response locally.")

client.expect_return_codes(0)
server.expect_return_codes(1)

case = suite.case("Verify expect: present still fails with --allow-unprocessed-verifications")
client = case.add_client("client4", "replay_files/http1_present_cache_hit.yaml",
                         configure_https=False)
server = case.add_server("server4", "replay_files/http1_present_cache_hit.yaml",
                         configure_https=False, other_args="--allow-unprocessed-verifications")
proxy = case.add_proxy("proxy4", listen_port=client.http_port, server_port=server.http_port)

server.stdout.contains(missing_present_message,
                       "The allow flag should not suppress explicit present failures.")
server.stdout.excludes(
    'were never processed before shutdown',
    "The allow flag is not involved because this is not a generic "
    "unprocessed verification failure.")
proxy.stdout.contains('Serving local response for key present-cache-hit-1 with status 200.',
                      "The shared proxy should synthesize the cached response locally.")

client.expect_return_codes(0)
server.expect_return_codes(1)

case = suite.case("Verify omitted expect allows the proxy to reply directly")
client = case.add_client("client5", "replay_files/http1_unspecified_cache_hit.yaml",
                         configure_https=False)
server = case.add_server("server5", "replay_files/http1_unspecified_cache_hit.yaml",
                         configure_https=False)
proxy = case.add_proxy("proxy5", listen_port=client.http_port, server_port=server.http_port)

client.stdout.contains("Received an HTTP/1 200 response for key unspecified-cache-hit-1",
                       "The client should receive the direct cached response.")
server.stdout.excludes(missing_present_message,
                       "No explicit presence expectation should mean no missing-request failure.")
server.stdout.excludes(
    'were never processed before shutdown',
    "Without request verification rules, omitting expect should not trigger "
    "an unprocessed verification failure.")
proxy.stdout.contains('Serving local response for key unspecified-cache-hit-1 with status 200.',
                      "The shared proxy should synthesize the cached response locally.")

client.expect_return_codes(0)
server.expect_return_codes(0)

case = suite.case("Verify expect: absent fails when HTTP/1 traffic reaches the server")
client = case.add_client("client6", "replay_files/http1_violation.yaml", configure_https=False)
server = case.add_server("server6", "replay_files/http1_violation.yaml", configure_https=False)
case.add_proxy("proxy6", listen_port=client.http_port, server_port=server.http_port)

client.stdout.contains(
    "Received an HTTP/1 404 response for key absent-http1-1",
    "The client should receive the fallback 404 when the forbidden request arrives upstream.")
server.stdout.contains(
    'Proxy request with key "absent-http1-1" unexpectedly reached the verifier-server',
    "The server should fail as soon as the forbidden request arrives.")

client.expect_return_codes(0)
server.expect_return_codes(1)

case = suite.case("Verify expect: absent still honors an explicit server-response")
client = case.add_client("client7", "replay_files/http1_explicit_response.yaml",
                         configure_https=False)
server = case.add_server("server7", "replay_files/http1_explicit_response.yaml",
                         configure_https=False)
case.add_proxy("proxy7", listen_port=client.http_port, server_port=server.http_port)

client.stdout.contains(
    "Received an HTTP/1 418 response for key absent-http1-explicit",
    "The client should receive the configured response when the forbidden request arrives.")
server.stdout.contains(
    'Proxy request with key "absent-http1-explicit" unexpectedly reached the verifier-server',
    "The server should still fail when the forbidden request arrives.")

client.expect_return_codes(0)
server.expect_return_codes(1)

case = suite.case("Verify expect: absent fails for HTTP/2 traffic reaching the server")
client = case.add_client("client8", "replay_files/http2_violation.yaml")
server = case.add_server("server8", "replay_files/http2_violation.yaml")
case.add_proxy("proxy8", listen_port=client.https_port, server_port=server.https_port, use_ssl=True,
               use_http2_to_2=True)

client.stdout.contains(
    "Received an HTTP/2 response for key absent-http2-1 with stream id 1:",
    "The HTTP/2 client should receive the response generated for the forbidden upstream arrival.")
server.stdout.contains(
    'Proxy request with key "absent-http2-1" unexpectedly reached the verifier-server',
    "The server should fail when the forbidden HTTP/2 request arrives.")

client.expect_return_codes(0)
server.expect_return_codes(1)

case = suite.case("Verify present expectations still require server-response")
server = case.add_server("server9", "replay_files/missing_server_response.yaml",
                         configure_https=False)

server.stdout.contains(
    'does not have a server response',
    "Transactions without expect: absent should still require a server-response node.")
server.expect_return_codes(1)


def test_uranium_suite(uranium):
    uranium.run(suite)
