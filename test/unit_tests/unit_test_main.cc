/** @file
 * This file used for catch based tests. It is the main() stub.
 *
 * Copyright 2026, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#define CATCH_CONFIG_RUNNER
#include "catch.hpp"

#include <chrono>

using namespace std::chrono_literals;

std::chrono::milliseconds Poll_Timeout{5s};

int
main(int argc, char *argv[])
{
  int result = Catch::Session().run(argc, argv);

  return result;
}
