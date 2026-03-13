/** @file
 * Unit tests for HttpReplay.h.
 *
 * Copyright 2020, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "catch.hpp"
#include "core/http.h"

struct ParseUrlTestCase
{
  std::string const description;
  std::string const url_input;

  std::string const expected_scheme;
  std::string const expected_authority;
  std::string const expected_path;

  std::string const expected_uri_scheme;
  std::string const expected_uri_host;
  std::string const expected_uri_port;
  std::string const expected_uri_authority;
  std::string const expected_uri_path;
  std::string const expected_uri_query;
  std::string const expected_uri_fragment;
};

std::initializer_list<ParseUrlTestCase> parse_url_test_cases = {
    {
        .description = "Verify an empty URL can be parsed.",
        .url_input = "",

        .expected_scheme = "",
        .expected_authority = "",
        .expected_path = "",

        .expected_uri_scheme = "",
        .expected_uri_host = "",
        .expected_uri_port = "",
        .expected_uri_authority = "",
        .expected_uri_path = "",
        .expected_uri_query = "",
        .expected_uri_fragment = "",
    },
    {
        .description = "Verify scheme only is parsed correctly.",
        .url_input = "http://",

        .expected_scheme = "http",
        .expected_authority = "",
        .expected_path = "",

        .expected_uri_scheme = "http",
        .expected_uri_host = "",
        .expected_uri_port = "",
        .expected_uri_authority = "",
        .expected_uri_path = "",
        .expected_uri_query = "",
        .expected_uri_fragment = "",
    },
    {
        .description = "Verify a scheme and authority is parsed correctly.",
        .url_input = "https://www.example.com",

        .expected_scheme = "https",
        .expected_authority = "www.example.com",
        .expected_path = "",

        .expected_uri_scheme = "https",
        .expected_uri_host = "www.example.com",
        .expected_uri_port = "",
        .expected_uri_authority = "www.example.com",
        .expected_uri_path = "",
        .expected_uri_query = "",
        .expected_uri_fragment = "",
    },
    {
        .description = "Verify a scheme and authority with port is parsed correctly.",
        .url_input = "https://www.example.com:443",

        .expected_scheme = "https",
        .expected_authority = "www.example.com:443",
        .expected_path = "",

        .expected_uri_scheme = "https",
        .expected_uri_host = "www.example.com",
        .expected_uri_port = "443",
        .expected_uri_authority = "www.example.com:443",
        .expected_uri_path = "",
        .expected_uri_query = "",
        .expected_uri_fragment = "",
    },
    {
        .description = "Verify correct parsing of authority-only targets.",
        .url_input = "www.example.com:443",

        .expected_scheme = "",
        .expected_authority = "www.example.com:443",
        .expected_path = "",

        .expected_uri_scheme = "",
        .expected_uri_host = "www.example.com",
        .expected_uri_port = "443",
        .expected_uri_authority = "www.example.com:443",
        .expected_uri_path = "",
        .expected_uri_query = "",
        .expected_uri_fragment = "",
    },
    {
        .description = "Verify a path can be parsed.",
        .url_input = "/a/path.yaml",

        .expected_scheme = "",
        .expected_authority = "",
        .expected_path = "/a/path.yaml",

        .expected_uri_scheme = "",
        .expected_uri_host = "",
        .expected_uri_port = "",
        .expected_uri_authority = "",
        .expected_uri_path = "/a/path.yaml",
        .expected_uri_query = "",
        .expected_uri_fragment = "",
    },
    {
        .description = "Verify a path with a fragment can be parsed.",
        .url_input = "/a/path.json#Fraggle",

        .expected_scheme = "",
        .expected_authority = "",
        .expected_path = "/a/path.json#Fraggle",

        .expected_uri_scheme = "",
        .expected_uri_host = "",
        .expected_uri_port = "",
        .expected_uri_authority = "",
        .expected_uri_path = "/a/path.json",
        .expected_uri_query = "",
        .expected_uri_fragment = "Fraggle",
    },
    {
        .description = "Verify a path with a query and fragment can be parsed.",
        .url_input = "/a/path?q=q#F",

        .expected_scheme = "",
        .expected_authority = "",
        .expected_path = "/a/path?q=q#F",

        .expected_uri_scheme = "",
        .expected_uri_host = "",
        .expected_uri_port = "",
        .expected_uri_authority = "",
        .expected_uri_path = "/a/path",
        .expected_uri_query = "q=q",
        .expected_uri_fragment = "F",
    },
    {
        .description = "Verify parsing of a URI containing all the URI parts.",
        .url_input = "https://example-ab.candy.com/xy?zab=123456789:98765432#candy?cane",

        .expected_scheme = "https",
        .expected_authority = "example-ab.candy.com",
        .expected_path = "/xy?zab=123456789:98765432#candy?cane",

        .expected_uri_scheme = "https",
        .expected_uri_host = "example-ab.candy.com",
        .expected_uri_port = "",
        .expected_uri_authority = "example-ab.candy.com",
        .expected_uri_path = "/xy",
        .expected_uri_query = "zab=123456789:98765432",
        .expected_uri_fragment = "candy?cane",
    },
    {
        .description = "Verify parsing of a path with a colon.",
        .url_input = "https://example-ab.candy.com/xy/path:.yaml?zab=123456789:98765432#candy?cane",

        .expected_scheme = "https",
        .expected_authority = "example-ab.candy.com",
        .expected_path = "/xy/path:.yaml?zab=123456789:98765432#candy?cane",

        .expected_uri_scheme = "https",
        .expected_uri_host = "example-ab.candy.com",
        .expected_uri_port = "",
        .expected_uri_authority = "example-ab.candy.com",
        .expected_uri_path = "/xy/path:.yaml",
        .expected_uri_query = "zab=123456789:98765432",
        .expected_uri_fragment = "candy?cane",
    },
    {
        .description = "Verify URL parsing with a port.",
        .url_input = "http://example-ab.candy.com:8080/xy/yx?zab=123456789:98765432#Frag",

        .expected_scheme = "http",
        .expected_authority = "example-ab.candy.com:8080",
        .expected_path = "/xy/yx?zab=123456789:98765432#Frag",

        .expected_uri_scheme = "http",
        .expected_uri_host = "example-ab.candy.com",
        .expected_uri_port = "8080",
        .expected_uri_authority = "example-ab.candy.com:8080",
        .expected_uri_path = "/xy/yx",
        .expected_uri_query = "zab=123456789:98765432",
        .expected_uri_fragment = "Frag",
    },
    {
        .description = "Verify an empty path can be parsed.",
        .url_input = "http://example-ab.candy.com:8080?zab=123456789:98765432#Frag",

        .expected_scheme = "http",
        .expected_authority = "example-ab.candy.com:8080",
        .expected_path = "?zab=123456789:98765432#Frag",

        .expected_uri_scheme = "http",
        .expected_uri_host = "example-ab.candy.com",
        .expected_uri_port = "8080",
        .expected_uri_authority = "example-ab.candy.com:8080",
        .expected_uri_path = "",
        .expected_uri_query = "zab=123456789:98765432",
        .expected_uri_fragment = "Frag",
    },
    {
        .description = "Verify an empty path and just a fragment can be parsed.",
        .url_input = "http://example-ab.candy.com:8080#Frag",

        .expected_scheme = "http",
        .expected_authority = "example-ab.candy.com:8080",
        .expected_path = "#Frag",

        .expected_uri_scheme = "http",
        .expected_uri_host = "example-ab.candy.com",
        .expected_uri_port = "8080",
        .expected_uri_authority = "example-ab.candy.com:8080",
        .expected_uri_path = "",
        .expected_uri_query = "",
        .expected_uri_fragment = "Frag",
    },
};

TEST_CASE("Test path parsing", "[ParseUrl]")
{
  auto const &test_case = GENERATE(values(parse_url_test_cases));
  HttpHeader header;
  header.parse_url(test_case.url_input);

  CHECK(header._scheme == test_case.expected_scheme);
  CHECK(header._path == test_case.expected_path);
  CHECK(header._authority == test_case.expected_authority);

  CHECK(header.uri_scheme == test_case.expected_uri_scheme);
  CHECK(header.uri_host == test_case.expected_uri_host);
  CHECK(header.uri_port == test_case.expected_uri_port);
  CHECK(header.uri_authority == test_case.expected_uri_authority);
  CHECK(header.uri_path == test_case.expected_uri_path);
  CHECK(header.uri_query == test_case.expected_uri_query);
  CHECK(header.uri_fragment == test_case.expected_uri_fragment);
}

TEST_CASE("Verify HTTP/1 request methods participate in request verification", "[HttpHeader]")
{
  HttpHeader actual_request;
  auto const parse_result = actual_request.parse_request(
      "GET /method-verification HTTP/1.1\r\nHost: example.com\r\nuuid: 1\r\n\r\n");
  REQUIRE(parse_result.is_ok());

  HttpHeader expected_request;
  expected_request.set_is_http1();
  expected_request.set_is_request();
  expected_request._method = "GET";

  CHECK_FALSE(actual_request.verify_request("1", expected_request));

  expected_request._method = "POST";
  CHECK(actual_request.verify_request("1", expected_request));
}

TEST_CASE("Verify only HTTP/1 scalar methods count as request verification rules", "[Txn]")
{
  Txn http1_txn{false};
  http1_txn._req.set_is_http1();
  http1_txn._req.set_is_request();
  http1_txn._req._method = "GET";

  CHECK(http1_txn.request_has_verification_rules());

  Txn http2_txn{false};
  http2_txn._req.set_is_http2();
  http2_txn._req.set_is_request();
  http2_txn._req._method = "GET";

  CHECK_FALSE(http2_txn.request_has_verification_rules());
}
