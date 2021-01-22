/** @file
 * Unit tests for HttpReplay.h.
 *
 * Copyright 2020, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "catch.hpp"
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
