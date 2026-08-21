'''
Verify shutdown handling for unprocessed verification rules.
'''
# @file
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

HTTP3_ARGS = "--poll-timeout 10000"

SERVER_SUMMARY = 'Shutdown occurred with 1 transaction whose verification rules were never processed.'
CLIENT_SUMMARY = 'Replay completed with 1 transaction whose verification rules were never processed.'


def add_server_failure_run(description, client_name, client_replay, server_name, server_replay,
                           proxy_name, client_port_attr, server_port_attr, expected_key,
                           **proxy_kwargs):
    case = suite.case(description)
    client = case.add_client(client_name, client_replay, **proxy_kwargs.pop('client_kwargs', {}))
    server = case.add_server(server_name, server_replay, **proxy_kwargs.pop('server_kwargs', {}))
    case.add_proxy(
        proxy_name,
        listen_port=getattr(client, client_port_attr),
        server_port=getattr(server, server_port_attr),
        **proxy_kwargs,
    )

    server.stdout.contains(
        f'Verification rules for transaction key "{expected_key}" were never processed before shutdown.',
        "The server should report the transaction whose verification rules were skipped.")
    server.stdout.contains(SERVER_SUMMARY, "The server should summarize the shutdown failure.")
    client.expect_return_codes(0)
    server.expect_return_codes(1)


def add_client_failure_run(description, client_name, replay_file, proxy_name, listen_port_attr,
                           expected_key, **proxy_kwargs):
    case = suite.case(description)
    client_kwargs = proxy_kwargs.pop('client_kwargs', {})
    client = case.add_client(client_name, replay_file, **client_kwargs)
    proxy = case.add_proxy(
        proxy_name,
        listen_port=getattr(client, listen_port_attr),
        server_port=1,
        **proxy_kwargs,
    )

    client.stdout.contains(
        f'Verification rules for transaction key "{expected_key}" were never processed before replay completed.',
        "The client should report the response verification rules that were skipped.")
    client.stdout.contains(CLIENT_SUMMARY,
                           "The client should summarize the replay completion failure.")
    proxy.stdout.contains(
        f'Closing downstream connection for key {expected_key} without sending a response.',
        "The proxy should close the connection before sending any response bytes.")
    client.expect_return_codes(1)


add_server_failure_run(
    "Verify shutdown fails when request verification rules were never processed.",
    "client1",
    "replay_files/client_subset_http1.yaml",
    "server1",
    "replay_files/server_superset_http1.yaml",
    "proxy1",
    "http_port",
    "http_port",
    "unprocessed-1",
    client_kwargs={"configure_https": False},
)

case = suite.case("Verify shutdown can allow unprocessed verification rules when requested.")
client = case.add_client("client2", "replay_files/client_subset_http1.yaml", configure_https=False)
server = case.add_server("server2", "replay_files/server_superset_http1.yaml",
                         other_args="--allow-unprocessed-verifications")
case.add_proxy("proxy2", listen_port=client.http_port, server_port=server.http_port)

server.stdout.excludes('were never processed before shutdown',
                       "The opt-out should suppress the unprocessed verification error.")
client.expect_return_codes(0)
server.expect_return_codes(0)

add_server_failure_run(
    "Verify HTTP/2 shutdown fails when request verification rules were never processed.",
    "client3",
    "replay_files/client_subset_http2.yaml",
    "server3",
    "replay_files/server_superset_http2.yaml",
    "proxy3",
    "https_port",
    "https_port",
    "unprocessed-h2-1",
    use_ssl=True,
    use_http2_to_2=True,
)

add_client_failure_run(
    "Verify the client fails when response verification rules were never processed.",
    "client4",
    "replay_files/verify_unprocessed_response_http1.yaml",
    "proxy4",
    "http_port",
    "unprocessed-response-1",
    client_kwargs={"configure_https": False},
)

case = suite.case(
    "Verify the client can allow unprocessed response verification rules when requested.")
client = case.add_client("client5", "replay_files/verify_unprocessed_response_http1.yaml",
                         configure_https=False, other_args="--allow-unprocessed-verifications")
proxy = case.add_proxy("proxy5", listen_port=client.http_port, server_port=1)
client.stdout.excludes('were never processed before replay completed',
                       "The client opt-out should suppress the unprocessed verification error.")
proxy.stdout.contains(
    'Closing downstream connection for key unprocessed-response-1 without sending a response.',
    "The proxy should close the connection before sending any response bytes.")
client.expect_return_codes(1)

add_client_failure_run(
    "Verify the HTTP/2 client fails when response verification rules were never processed.",
    "client6",
    "replay_files/verify_unprocessed_response_http2.yaml",
    "proxy6",
    "https_port",
    "unprocessed-response-h2-1",
    use_ssl=True,
    use_http2_to_1=True,
)

add_client_failure_run(
    "Verify the HTTP/3 client fails when response verification rules were never processed.",
    "client7",
    "replay_files/verify_unprocessed_response_http3.yaml",
    "proxy7",
    "http3_port",
    "unprocessed-response-h3-1",
    client_kwargs={"other_args": HTTP3_ARGS},
    use_ssl=True,
    use_http3_to_1=True,
)


def test_uranium_suite(uranium):
    uranium.run(suite)
