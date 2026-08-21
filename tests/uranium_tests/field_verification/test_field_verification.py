'''
Verify correct field verification behavior.
'''
# @file
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0

from tools.uranium import CaseSuite

suite = CaseSuite(__file__)
#

#
# Test 1: Verify field verification in a JSON replay file.
#
case = suite.case("Verify field verification works for a simple HTTP transaction")
client = case.add_client("client1", "replay_files/various_verification.json")
server = case.add_server("server1", "replay_files/various_verification.json")
proxy = case.add_proxy("proxy1", listen_port=client.http_port, server_port=server.http_port)

# Verify a success and failure of each validation in the request.
server.stdout.contains('Absence Success: Key: "1", Field Name: "x-candy"',
                       'Validation should be happy that the proxy removed X-CANDY.')
server.stdout.contains(
    'Absence Violation: Present. Key: "1", Field Name: "content-type", Value: "application/octet-stream"',
    'Validation should complain that "content-type" is present')
server.stdout.contains('Presence Success: Key: "1", Field Name: "content-length", Value: "399"',
                       'Validation should be happy that "content-length" is present.')
server.stdout.contains(
    'Presence Success: Key: "1", Field Name: "exampleremoteip", Value: "10.10.10.4"',
    'Validation should be happy that "ExampleRemoteIP" is present even though its value differs.')
server.stdout.contains('Presence Violation: Absent. Key: "1", Field Name: "client-ip"',
                       'Validation should complain that "client-ip" is misssing')
server.stdout.contains('Equals Success: Key: "1", Field Name: "x-someid", Value: "21djfk39jfkds"',
                       'Validation should be happy that "S-SomeId" has the expected value.')
server.stdout.contains(
    'Equals Violation: Different. Key: "1", Field Name: "host", Correct Value: "example.com", Actual Value: "test.example.com"',
    'Validation should complain that the "Host" value differs from the expected value.')
server.stdout.contains(
    'Equals Violation: Different. Key: "1", Field Name: "x-test-case", Correct Value: "CASEmatters", Actual Value: "caseMATTERS"',
    'Equals validation must be case-sensitive.')

# Verify a success and failure of each validation in the response.
client.stdout.contains('Absence Success: Key: "1", Field Name: "x-newtestheader"',
                       'Validation should be happy that the proxy removed X-NewTestHeader.')
client.stdout.contains(
    'Absence Violation: Present. Key: "1", Field Name: "x-shouldexist", Value: "trustme; it=will"',
    'Validation should complain that "X-ShouldExist" is present')
client.stdout.contains('Presence Success: Key: "1", Field Name: "content-length", Value: "0"',
                       'Validation should be happy that "content-length" is present.')
client.stdout.contains(
    'Presence Success: Key: "1", Field Name: "age", Value: "4"',
    'Validation should be happy that "Age" is present even though its value differs.')
client.stdout.contains('Presence Violation: Absent. Key: "1", Field Name: "x-request-id"',
                       'Validation should complain that "x-request-id" is misssing')
client.stdout.contains(
    'Equals Success: Key: "1", Field Name: "date", Value: "Sat, 16 Mar 2019 03:11:36 GMT"',
    'Validation should be happy that "date" has the expected value.')
client.stdout.contains(
    ('Equals Violation: Different. Key: "1", Field Name: "x-testheader", '
     'Correct Value: "from_proxy_response", Actual Value: "from_server_response"'),
    'Validation should complain that the "x-testheader" value differs from the expected value.')

client.expect_return_codes(1)
server.expect_return_codes(1)

#
# Test 2: Verify field verification in a YAML replay file.
#
case = suite.case("Verify field verification works for a simple HTTP transaction")
client = case.add_client("client2", "replay_files/cookie_equal.yaml")
server = case.add_server("server2", "replay_files/cookie_equal.yaml")
proxy = case.add_proxy("proxy2", listen_port=client.http_port, server_port=server.http_port)

client.stdout.contains('Absence Success: Key: "5", Field Name: "x-not-a-header"',
                       'Validation should be happy that "X-Not-A-Header" is missing.')

client.stdout.contains('Equals Success: Key: "5", Field Name: "set-cookie", Value: "ABCD"',
                       'Validation should be happy that "Set-Cookie" had the expected header.')

client.stdout.contains('Equals Success: Key: "5", Field Name: "set-cookie", Value: "ABCD"',
                       'Validation should be happy that "Set-Cookie" had the expected header.')

client.stdout.contains('Presence Violation: Absent. Key: "5", Field Name: "x-does-not-exist"',
                       'Validation should complain that "X-Does-Not-Exist" is not present.')

server.stdout.contains(
    'Equals Violation: Different. Key: "5", Field Name: "x-test-request", Correct Value: "rEQUESTdATA", Actual Value: "RequestData"',
    'Validation should complain that "X-Test-Request" is different.')

server.stdout.contains(
    'Absence Violation: Present. Key: "5", Field Name: "x-test-present", Value: "It\'s there"',
    'Validation should complain that "X-Test-Pressent" is present.')

server.stdout.contains('Equals Success: Key: "5", Field Name: "cookie", Value: "',
                       'Validation should be happy with the cookie value.')

client.expect_return_codes(1)
server.expect_return_codes(1)

#
# Test 3: Verify repeated RFC-combinable header fields are normalized for verification.
#
case = suite.case("Verify repeated RFC-combinable header fields are normalized for verification")
client = case.add_client("client3", "replay_files/duplicate_fields.yaml")
server = case.add_server("server3", "replay_files/duplicate_fields.yaml")
proxy = case.add_proxy("proxy3", listen_port=client.http_port, server_port=server.http_port)

client.stdout.contains(
    'Equals Success: Key: "1", Field Name: "cache-control", Value: "no-store, max-age=0"',
    'Validation should combine repeated Cache-Control field lines before comparing them.')

client.stdout.contains(
    ('Equals Violation: Different. Key: "1", Field Name: "cache-control", '
     'Correct Value: "max-age=0, no-store", Actual Value: "no-store, max-age=0"'),
    'Validation should preserve the order of repeated Cache-Control values.')

client.stdout.contains(
    'Equals Success: Key: "1", Field Name: "vary", Value: "accept-encoding, accept-language"',
    'Validation should treat a single comma-separated Vary field line like repeated field lines.')

server.stdout.contains(
    'Equals Success: Key: "1", Field Name: "x-join", Value: "alpha, beta"',
    'Validation should join repeated request field lines with comma SP before equality checks.')

server.stdout.contains(('Equals Violation: Different. Key: "1", Field Name: "x-join", '
                        'Correct Value: "beta, alpha", Actual Value: "alpha, beta"'),
                       'Validation should fail when the repeated request field order changes.')

server.stdout.contains(
    'Contains Success: Key: "1", Field Name: "x-join", Required Value: "beta", Value: "alpha, beta"',
    'Validation should run substring checks against the combined request field value.')

client.expect_return_codes(1)
server.expect_return_codes(1)

# Test 4: Verify Set-Cookie verification uses the dedicated set-cookie-verifications node.
case = suite.case(
    "Verify Set-Cookie verification works with the dedicated set-cookie-verifications node")
client = case.add_client("client4", "replay_files/multi_value_includes.yaml")
server = case.add_server("server4", "replay_files/multi_value_includes.yaml")
proxy = case.add_proxy("proxy4", listen_port=client.https_port, server_port=server.https_port,
                       use_ssl=True, use_http2_to_2=True)

client.stdout.contains(
    'Equals Success: Key: "1", Field Name: "set-cookie", Value: "B1=333"',
    "Verification should match a Set-Cookie rule even when the replay lists it out of order.")

client.stdout.contains(
    'Equals Success: Key: "1", Field Name: "set-cookie", Value: "A1=111"',
    "Verification should match the remaining Set-Cookie rule after the first match is consumed.")

client.expect_return_codes(0)
server.expect_return_codes(0)

# Test 5: Verify Set-Cookie verification allows extra cookies after the expected list.
case = suite.case("Verify Set-Cookie verification allows extra cookies after the expected list")
client = case.add_client("client5", "replay_files/multi_value_equal.yaml")
server = case.add_server("server5", "replay_files/multi_value_equal.yaml")
proxy = case.add_proxy("proxy5", listen_port=client.https_port, server_port=server.https_port,
                       use_ssl=True, use_http2_to_2=True)

client.stdout.contains(
    'Contains Success: Key: "1", Field Name: "set-cookie", Required Value: "A1=", Value: "A1=111"',
    "Verification should match the first expected Set-Cookie rule.")

client.stdout.contains(
    'Equals Success: Key: "1", Field Name: "set-cookie", Value: "B1=333"',
    "Verification should match the second expected Set-Cookie rule and ignore later cookies.")

client.expect_return_codes(0)
server.expect_return_codes(0)

# Test 6: Verify Set-Cookie negative checks do not consume cookies and value arrays expand.
case = suite.case("Verify negative Set-Cookie checks assert no matching cookie line")
client = case.add_client("client6", "replay_files/set_cookie_negative.yaml")
server = case.add_server("server6", "replay_files/set_cookie_negative.yaml")
proxy = case.add_proxy("proxy6", listen_port=client.https_port, server_port=server.https_port,
                       use_ssl=True, use_http2_to_2=True)

client.stdout.contains(
    'Contains Success: Key: "1", Field Name: "set-cookie", Required Value: "A1=", Value: "A1=111"',
    "Verification should expand a Set-Cookie contains array into individual checks.")

client.stdout.contains(
    'Contains Success: Key: "1", Field Name: "set-cookie", Required Value: "A1S=", Value: "A1S=555"',
    "Verification should match each expanded Set-Cookie contains rule independently.")

client.stdout.contains(
    'Not Contains Success: Absent. Key: "1", Field Name: "set-cookie", Required Missing Value: "D1="',
    "Verification should treat Set-Cookie absent-with-value as a negative non-consuming match.")

client.stdout.contains(
    'Not Contains Success: Absent. Key: "1", Field Name: "set-cookie", Required Missing Value: "_ebd"',
    "Verification should expand a Set-Cookie absent array into individual negative checks.")

client.expect_return_codes(0)
server.expect_return_codes(0)

# Test 7: Verify legacy Set-Cookie absence and negative pattern checks still work.
case = suite.case("Verify Set-Cookie absence works in both legacy and dedicated syntax")
client = case.add_client("client7", "replay_files/set_cookie_absent.yaml")
server = case.add_server("server7", "replay_files/set_cookie_absent.yaml")
proxy = case.add_proxy("proxy7", listen_port=client.https_port, server_port=server.https_port,
                       use_ssl=True, use_http2_to_2=True)

client.stdout.contains('Absence Success: Key: "1", Field Name: "set-cookie"',
                       "Legacy Set-Cookie absence verification under fields should still work.")

client.expect_return_codes(0)
server.expect_return_codes(0)

# Test 8: Verify a negative Set-Cookie pattern check fails on a matching cookie line.
case = suite.case("Verify a negative Set-Cookie pattern fails when a cookie matches")
client = case.add_client("client8", "replay_files/set_cookie_negative_failure.yaml")
server = case.add_server("server8", "replay_files/set_cookie_negative_failure.yaml")
proxy = case.add_proxy("proxy8", listen_port=client.https_port, server_port=server.https_port,
                       use_ssl=True, use_http2_to_2=True)

client.stdout.contains('Equals Success: Key: "1", Field Name: "set-cookie", Value: "A1=111"',
                       "Verification should still match the positive Set-Cookie rule.")

client.stdout.contains(
    'Not Contains Violation: Key: "1", Field Name: "set-cookie", Required Missing Value: "B1=333", Value: "B1=333"',
    "Verification should fail when an absent Set-Cookie pattern matches a received cookie.")

client.expect_return_codes(1)
server.expect_return_codes(0)


def test_uranium_suite(uranium):
    uranium.run(suite)
