/** @file
 * Unit tests for HttpReplay.h.
 *
 * Copyright 2026, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "catch.hpp"
#include "core/ProxyVerifier.h"
#include "core/YamlParser.h"

#include <chrono>
#include <string>

using namespace std::literals;
using std::chrono::microseconds;

constexpr bool IS_VALID = true;

namespace
{
class ReplayFileHandlerTester : public ReplayFileHandler
{
public:
  using ReplayFileHandler::HttpProtocol;
  using ReplayFileHandler::ParsedProtocolNode;
  using ReplayFileHandler::parse_protocol_node;
};
} // namespace

struct ParseDelaySpecificationTestCase
{
  std::string const description;
  std::string const delay_specification;

  bool is_valid;
  microseconds const expected_delay;
};

std::initializer_list<ParseDelaySpecificationTestCase> parse_delay_specification_test_cases = {
    {
        .description = "Verify a microseconds specification.",
        .delay_specification = "10us",
        .is_valid = IS_VALID,
        .expected_delay = 10us,
    },
    {
        .description = "Verify a milliseconds specification.",
        .delay_specification = "12ms",
        .is_valid = IS_VALID,
        .expected_delay = 12'000us,
    },
    {
        .description = "Verify a seconds specification.",
        .delay_specification = "22s",
        .is_valid = IS_VALID,
        .expected_delay = 22'000'000us,
    },
    {
        .description = "Verify that the value 0 is allowed.",
        .delay_specification = "0us",
        .is_valid = IS_VALID,
        .expected_delay = 0us,
    },
    {
        .description = "Verify correct handling of surrounding white space.",
        .delay_specification = " \t  8us\t\n",
        .is_valid = IS_VALID,
        .expected_delay = 8us,
    },
    {
        .description = "Verify correct handling of internal white space.",
        .delay_specification = "8  \t  us",
        .is_valid = IS_VALID,
        .expected_delay = 8us,
    },
    {
        .description = "Verify correct handling of internal and surrounding white space.",
        .delay_specification = "\t  8  \t  us  \t \r\n",
        .is_valid = IS_VALID,
        .expected_delay = 8us,
    },

    /*
     * Failure parsing cases.
     */
    {
        .description = "Verify an empty string fails parsing.",
        .delay_specification = "",
        .is_valid = !IS_VALID,
        .expected_delay = 0us,
    },
    {
        .description = "Verify omission of a suffix fails parsing.",
        .delay_specification = "10",
        .is_valid = !IS_VALID,
        .expected_delay = 0us,
    },
    {
        .description = "Verify omission of a number fails parsing.",
        .delay_specification = "us",
        .is_valid = !IS_VALID,
        .expected_delay = 0us,
    },
    {
        .description = "Verify a decimal value fails parsing.",
        .delay_specification = "10.2ms",
        .is_valid = !IS_VALID,
        .expected_delay = 0us,
    },
    {
        .description = "Verify an unrecognized suffix fails parsing.",
        .delay_specification = "10ns",
        .is_valid = !IS_VALID,
        .expected_delay = 0us,
    },
};

TEST_CASE("Verify interpretation of delay specification strings", "[delay_specification]")
{
  auto const &test_case = GENERATE(values(parse_delay_specification_test_cases));
  auto &&[parsed_delay_value, delay_errata] = interpret_delay_string(test_case.delay_specification);
  if (test_case.is_valid) {
    CHECK(delay_errata.is_ok());
    CHECK(parsed_delay_value == test_case.expected_delay);
  } else {
    CHECK(parsed_delay_value == 0us);
    CHECK_FALSE(delay_errata.is_ok());
  }
}

struct ParseOnConnectActionTestCase
{
  std::string const description;
  std::string const yaml;
  bool is_valid;
  Txn::ConnectAction const expected_action;
};

std::initializer_list<ParseOnConnectActionTestCase> parse_on_connect_action_test_cases = {
    {
        .description = "Verify the on_connect directive defaults to accept.",
        .yaml = "{}",
        .is_valid = IS_VALID,
        .expected_action = Txn::ConnectAction::ACCEPT,
    },
    {
        .description = "Verify accept is parsed.",
        .yaml = "{ on_connect: accept }",
        .is_valid = IS_VALID,
        .expected_action = Txn::ConnectAction::ACCEPT,
    },
    {
        .description = "Verify refuse is parsed.",
        .yaml = "{ on_connect: refuse }",
        .is_valid = IS_VALID,
        .expected_action = Txn::ConnectAction::REFUSE,
    },
    {
        .description = "Verify reset is parsed.",
        .yaml = "{ on_connect: reset }",
        .is_valid = IS_VALID,
        .expected_action = Txn::ConnectAction::RESET,
    },
    {
        .description = "Verify invalid values fail parsing.",
        .yaml = "{ on_connect: later }",
        .is_valid = !IS_VALID,
        .expected_action = Txn::ConnectAction::ACCEPT,
    },
    {
        .description = "Verify non-scalar values fail parsing.",
        .yaml = "{ on_connect: [reset] }",
        .is_valid = !IS_VALID,
        .expected_action = Txn::ConnectAction::ACCEPT,
    },
};

TEST_CASE("Verify interpretation of on_connect actions", "[on_connect]")
{
  auto const &test_case = GENERATE(values(parse_on_connect_action_test_cases));
  auto const node = YAML::Load(test_case.yaml);
  auto &&[action, action_errata] = get_on_connect_action(node);
  if (test_case.is_valid) {
    CHECK(action_errata.is_ok());
    CHECK(action == test_case.expected_action);
  } else {
    CHECK_FALSE(action_errata.is_ok());
  }
}

struct ServerResponseValidationTestCase
{
  std::string const description;
  std::string const yaml;
  bool is_valid;
};

std::initializer_list<ServerResponseValidationTestCase> server_response_validation_test_cases = {
    {
        .description = "Verify status is required without on_connect.",
        .yaml = "{ reason: OK }",
        .is_valid = !IS_VALID,
    },
    {
        .description = "Verify status is required with on_connect accept.",
        .yaml = "{ on_connect: accept }",
        .is_valid = !IS_VALID,
    },
    {
        .description = "Verify status is optional with on_connect refuse.",
        .yaml = "{ on_connect: refuse }",
        .is_valid = IS_VALID,
    },
    {
        .description = "Verify status is optional with on_connect reset.",
        .yaml = "{ on_connect: reset }",
        .is_valid = IS_VALID,
    },
};

TEST_CASE("Verify server-response validation for on_connect", "[on_connect]")
{
  auto const &test_case = GENERATE(values(server_response_validation_test_cases));
  auto const node = YAML::Load(test_case.yaml);
  HttpHeader response{true};
  response.set_is_response();
  auto errata = YamlParser::populate_http_message(node, response);
  auto &&[action, action_errata] = get_on_connect_action(node);
  errata.note(std::move(action_errata));
  if (response._status == 0 && action == Txn::ConnectAction::ACCEPT) {
    errata.note(S_ERROR, "server-response node is missing a required status.");
  }

  if (test_case.is_valid) {
    CHECK(errata.is_ok());
  } else {
    CHECK_FALSE(errata.is_ok());
  }
}

TEST_CASE("Verify verbose protocol sequences parse into a common protocol object", "[protocol]")
{
  auto const protocol_node = YAML::Load(R"(
[
  { name: http, version: 2 },
  { name: tls, sni: test_sni, verify-mode: 1 },
  { name: proxy-protocol, version: 2, src-addr: 127.0.0.1:1000, dst-addr: 127.0.0.1:2000 },
  { name: tcp },
  { name: ip }
]
)");

  ReplayFileHandlerTester::ParsedProtocolNode parsed_protocol{protocol_node};
  REQUIRE(parsed_protocol.is_valid());
  CHECK(parsed_protocol.get_http_protocol() == ReplayFileHandlerTester::HttpProtocol::HTTP2);
  CHECK(parsed_protocol.is_tls());
  REQUIRE(parsed_protocol.get_tls_sni_name().has_value());
  CHECK(parsed_protocol.get_tls_sni_name().value() == "test_sni");
  REQUIRE(parsed_protocol.get_tls_verify_mode().has_value());
  CHECK(parsed_protocol.get_tls_verify_mode().value() == 1);
  REQUIRE(parsed_protocol.get_proxy_protocol_version().has_value());
  CHECK(parsed_protocol.get_proxy_protocol_version().value() == 2);
  REQUIRE(parsed_protocol.get_proxy_protocol_src_addr().has_value());
  CHECK(parsed_protocol.get_proxy_protocol_src_addr().value() == "127.0.0.1:1000");
  REQUIRE(parsed_protocol.get_proxy_protocol_dst_addr().has_value());
  CHECK(parsed_protocol.get_proxy_protocol_dst_addr().value() == "127.0.0.1:2000");
}

TEST_CASE("Verify protocol stack shorthand parses into a common protocol object", "[protocol]")
{
  auto const protocol_node = YAML::Load(R"(
stack: http2
tls:
  sni: test_sni
  verify-mode: 1
proxy-protocol: 2
)");

  auto const parsed_protocol = ReplayFileHandlerTester::parse_protocol_node(protocol_node);
  REQUIRE(parsed_protocol.is_ok());
  CHECK(
      parsed_protocol.result().get_http_protocol() == ReplayFileHandlerTester::HttpProtocol::HTTP2);
  CHECK(parsed_protocol.result().is_tls());
  REQUIRE(parsed_protocol.result().get_tls_sni_name().has_value());
  CHECK(parsed_protocol.result().get_tls_sni_name().value() == "test_sni");
  REQUIRE(parsed_protocol.result().get_tls_verify_mode().has_value());
  CHECK(parsed_protocol.result().get_tls_verify_mode().value() == 1);
  REQUIRE(parsed_protocol.result().get_proxy_protocol_version().has_value());
  CHECK(parsed_protocol.result().get_proxy_protocol_version().value() == 2);
}

TEST_CASE("Verify http stack synthesizes HTTP/1 defaults", "[protocol]")
{
  auto const protocol_node = YAML::Load("{ stack: http }");
  ReplayFileHandlerTester::ParsedProtocolNode parsed_protocol{protocol_node};
  REQUIRE(parsed_protocol.is_valid());
  CHECK(parsed_protocol.get_http_protocol() == ReplayFileHandlerTester::HttpProtocol::HTTP);
  CHECK_FALSE(parsed_protocol.is_tls());
}

TEST_CASE("Verify https stack synthesizes TLS defaults", "[protocol]")
{
  auto const protocol_node = YAML::Load("{ stack: https }");
  ReplayFileHandlerTester::ParsedProtocolNode parsed_protocol{protocol_node};
  REQUIRE(parsed_protocol.is_valid());
  CHECK(parsed_protocol.get_http_protocol() == ReplayFileHandlerTester::HttpProtocol::HTTPS);
  CHECK(parsed_protocol.is_tls());
}

TEST_CASE("Verify conflicting protocol stack and TLS options are rejected", "[protocol]")
{
  SECTION("flattened TLS shorthand")
  {
    auto const protocol_node = YAML::Load("{ stack: http2, sni: test_sni }");
    ReplayFileHandlerTester::ParsedProtocolNode parsed_protocol{protocol_node};
    CHECK_FALSE(parsed_protocol.is_valid());
  }

  SECTION("explicit tls map")
  {
    auto const protocol_node = YAML::Load("{ stack: http, tls: { sni: test_sni } }");
    ReplayFileHandlerTester::ParsedProtocolNode parsed_protocol{protocol_node};
    CHECK_FALSE(parsed_protocol.is_valid());
  }

  SECTION("explicit http layer override")
  {
    auto const protocol_node = YAML::Load("{ stack: http2, http: { version: 3 } }");
    ReplayFileHandlerTester::ParsedProtocolNode parsed_protocol{protocol_node};
    CHECK_FALSE(parsed_protocol.is_valid());
  }
}

TEST_CASE("Verify explicit TLS maps can be combined with stack shorthand", "[protocol]")
{
  auto const protocol_node = YAML::Load(R"(
stack: http2
tls:
  sni: test_sni_with_map
  request-certificate: true
)");

  auto const parsed_protocol = ReplayFileHandlerTester::parse_protocol_node(protocol_node);
  REQUIRE(parsed_protocol.is_ok());
  CHECK(parsed_protocol.result().is_tls());
  REQUIRE(parsed_protocol.result().get_tls_sni_name().has_value());
  CHECK(parsed_protocol.result().get_tls_sni_name().value() == "test_sni_with_map");
  REQUIRE(parsed_protocol.result().should_request_certificate().has_value());
  CHECK(parsed_protocol.result().should_request_certificate().value());
}
