/** @file
 * Unit tests for HttpReplay.h.
 *
 * Copyright 2026, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "catch.hpp"
#include "core/http.h"

#include <chrono>
#include <string>
#include <thread>
#include <sys/socket.h>
#include <unistd.h>

using namespace std::literals;

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

TEST_CASE(
    "Verify expect: absent transactions do not count as unprocessed request verifications",
    "[Txn]")
{
  Txn negative_txn{false};
  negative_txn._req.set_is_http1();
  negative_txn._req.set_is_request();
  negative_txn._req.set_key("absent-key");
  negative_txn._request_expectation = Txn::RequestPresenceExpectation::ABSENT;
  negative_txn._req._method = "GET";
  negative_txn._req._fields_rules->add_field("uuid", "absent-key");

  std::vector<Txn const *> transactions{&negative_txn};
  auto errata = check_for_unprocessed_verifications(
      transactions,
      UnprocessedVerificationTarget::Request,
      "before shutdown",
      "Shutdown occurred");

  CHECK(errata.is_ok());
  CHECK_FALSE(negative_txn.request_has_verification_rules());
}

TEST_CASE("Verify expect: present transactions fail if the request never arrives", "[Txn]")
{
  Txn positive_txn{false};
  positive_txn._req.set_is_http1();
  positive_txn._req.set_is_request();
  positive_txn._req.set_key("present-key");
  positive_txn._request_expectation = Txn::RequestPresenceExpectation::PRESENT;

  std::vector<Txn const *> transactions{&positive_txn};
  auto errata =
      check_for_missing_expected_requests(transactions, "before shutdown", "Shutdown occurred");

  CHECK_FALSE(errata.is_ok());
}

TEST_CASE(
    "Verify expect: present missing requests do not duplicate unprocessed verification failures",
    "[Txn]")
{
  Txn positive_txn{false};
  positive_txn._req.set_is_http1();
  positive_txn._req.set_is_request();
  positive_txn._req.set_key("present-key");
  positive_txn._request_expectation = Txn::RequestPresenceExpectation::PRESENT;
  positive_txn._req._method = "GET";

  std::vector<Txn const *> transactions{&positive_txn};
  auto const missing_request_errata =
      check_for_missing_expected_requests(transactions, "before shutdown", "Shutdown occurred");
  auto const unprocessed_errata = check_for_unprocessed_verifications(
      transactions,
      UnprocessedVerificationTarget::Request,
      "before shutdown",
      "Shutdown occurred");

  CHECK_FALSE(missing_request_errata.is_ok());
  CHECK(unprocessed_errata.is_ok());
}

TEST_CASE(
    "Verify unspecified transactions still fail unprocessed request verification checks",
    "[Txn]")
{
  Txn unspecified_txn{false};
  unspecified_txn._req.set_is_http1();
  unspecified_txn._req.set_is_request();
  unspecified_txn._req.set_key("unspecified-key");
  unspecified_txn._req._method = "GET";

  std::vector<Txn const *> transactions{&unspecified_txn};
  auto errata = check_for_unprocessed_verifications(
      transactions,
      UnprocessedVerificationTarget::Request,
      "before shutdown",
      "Shutdown occurred");

  CHECK_FALSE(errata.is_ok());
}

namespace
{
/// The generated body size used by the content delay tests.
constexpr size_t CONTENT_DELAY_BODY_SIZE = 16;

/// The content delay used by the content delay tests. This is long enough to
/// be distinguishable from scheduling jitter but short enough to keep the unit
/// tests fast.
constexpr auto CONTENT_DELAY_DURATION = std::chrono::milliseconds{300};

/// The observed arrival times of the two halves of an HTTP/1 response.
struct ResponseArrival
{
  /// How long after the write began the end of the headers was observed.
  std::chrono::steady_clock::duration headers;
  /// How long after the write began the last body byte was observed.
  std::chrono::steady_clock::duration body;
};

/** Build a minimal HTTP/1 response with a generated body.
 *
 * @param[in] content_delay The delay to apply between the headers and the body.
 * @return A response ready to be handed to @c Session::write.
 */
HttpHeader
make_content_delay_response(std::chrono::microseconds content_delay)
{
  HttpHeader response;
  response.set_is_http1();
  response.set_is_response();
  response.set_key("content-delay-key");
  response._http_version = "1.1";
  response._status = 200;
  response._reason = "OK";
  response._content_length = CONTENT_DELAY_BODY_SIZE;
  response._content_length_p = true;
  response._content_delay = content_delay;
  response._fields_rules->add_field("Content-Length", "16");
  return response;
}

/** Write a response to one end of a socket pair and time its arrival.
 *
 * The response is written from a separate thread so the reader can observe
 * when the headers arrive relative to the body.
 *
 * @param[in] content_delay The content delay to apply to the response.
 * @return When the headers and the body were observed by the peer.
 */
ResponseArrival
time_response_arrival(std::chrono::microseconds content_delay)
{
  int fd_pair[2];
  REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, fd_pair) == 0);

  Session session;
  REQUIRE(session.set_fd(fd_pair[0]).is_ok());

  auto const response = make_content_delay_response(content_delay);
  auto const start_time = std::chrono::steady_clock::now();

  swoc::Rv<ssize_t> write_result{0};
  std::thread writer{
      [&session, &response, &write_result]() { write_result = session.write(response); }};

  std::string received;
  ResponseArrival arrival{};
  constexpr swoc::TextView HEADER_TERMINATOR = "\r\n\r\n";
  size_t expected_total = 0;
  while (true) {
    char buffer[256];
    auto const n = ::read(fd_pair[1], buffer, sizeof(buffer));
    REQUIRE(n > 0);
    received.append(buffer, n);

    if (arrival.headers == std::chrono::steady_clock::duration::zero()) {
      if (auto const header_end = received.find(HEADER_TERMINATOR); header_end != std::string::npos)
      {
        arrival.headers = std::chrono::steady_clock::now() - start_time;
        expected_total = header_end + HEADER_TERMINATOR.size() + CONTENT_DELAY_BODY_SIZE;
      }
    }
    if (expected_total != 0 && received.size() >= expected_total) {
      arrival.body = std::chrono::steady_clock::now() - start_time;
      break;
    }
  }

  writer.join();
  CHECK(write_result.is_ok());
  CHECK(write_result.result() == static_cast<ssize_t>(expected_total));

  session.close();
  ::close(fd_pair[1]);
  return arrival;
}
} // namespace

TEST_CASE("Verify the HTTP/1 write path honors a content delay", "[content_delay]")
{
  HttpHeader::global_init();
  HttpHeader::set_max_content_length(CONTENT_DELAY_BODY_SIZE);

  SECTION("A response without a content delay sends its body immediately")
  {
    auto const arrival = time_response_arrival(0us);

    CHECK(arrival.headers < CONTENT_DELAY_DURATION);
    CHECK(arrival.body < CONTENT_DELAY_DURATION);
  }

  SECTION("A response with a content delay sends its headers before waiting")
  {
    auto const arrival = time_response_arrival(CONTENT_DELAY_DURATION);

    CHECK(arrival.headers < CONTENT_DELAY_DURATION);
    CHECK(arrival.body >= CONTENT_DELAY_DURATION);
  }
}
