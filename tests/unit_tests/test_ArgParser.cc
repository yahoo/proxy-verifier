/** @file
 * Unit tests for ArgParser.
 *
 * Copyright 2026, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "catch.hpp"
#include "core/ArgParser.h"

#include <string>

namespace
{
class CommandTester : public ts::ArgParser::Command
{
public:
  using ts::ArgParser::Command::append_option_data;
};
} // namespace

TEST_CASE("Verify append_option_data tolerates empty tokens", "[args]")
{
  CommandTester command;
  command.add_option("--flag", "-f", "test flag");

  ts::Arguments arguments;
  ts::AP_StrVec args{"prog", "", "-", "--flag"};

  REQUIRE_NOTHROW(command.append_option_data(arguments, args, 0));
  CHECK(args == ts::AP_StrVec({"prog", "", "-"}));
}

struct ParseIntegerOptionTestCase
{
  std::string const description;
  std::string const text;
  std::string const option_name;
  int const minimum;
  bool const is_valid;
  int const expected_value;
};

std::initializer_list<ParseIntegerOptionTestCase> parse_integer_option_test_cases = {
    {
        .description = "Verify zero is accepted.",
        .text = "0",
        .option_name = "--repeat",
        .minimum = 0,
        .is_valid = true,
        .expected_value = 0,
    },
    {
        .description = "Verify positive integers are accepted.",
        .text = "4000",
        .option_name = "--rate",
        .minimum = 0,
        .is_valid = true,
        .expected_value = 4000,
    },
    {
        .description = "Verify trailing junk is rejected.",
        .text = "0foo",
        .option_name = "--repeat",
        .minimum = 0,
        .is_valid = false,
        .expected_value = 0,
    },
    {
        .description = "Verify merged option text is rejected.",
        .text = "4000--repeat",
        .option_name = "--rate",
        .minimum = 0,
        .is_valid = false,
        .expected_value = 0,
    },
    {
        .description = "Verify negative values are rejected for non-negative options.",
        .text = "-1",
        .option_name = "--thread-limit",
        .minimum = 0,
        .is_valid = false,
        .expected_value = 0,
    },
};

TEST_CASE("Verify strict parsing of integer option values", "[args]")
{
  auto const &test_case = GENERATE(values(parse_integer_option_test_cases));

  int parsed_value = -1;
  std::string error;
  auto const is_valid = ts::parse_integer_option(
      test_case.text,
      parsed_value,
      error,
      test_case.option_name,
      test_case.minimum);

  CHECK(is_valid == test_case.is_valid);
  if (test_case.is_valid) {
    CHECK(parsed_value == test_case.expected_value);
    CHECK(error.empty());
  } else {
    CHECK_FALSE(error.empty());
    CHECK(error.find(test_case.option_name) != std::string::npos);
  }
}
