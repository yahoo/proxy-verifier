/** @file
 * Unit tests for ArgParser.
 *
 * Copyright 2026, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "catch.hpp"
#include "core/ArgParser.h"

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
