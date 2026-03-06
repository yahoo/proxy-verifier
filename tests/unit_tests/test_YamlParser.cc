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
