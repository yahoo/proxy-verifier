/** @file
 * Unit tests for HttpReplay.h.
 *
 * Copyright 2021, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "catch.hpp"
#include "core/https.h"

TEST_CASE("ALPN string formatting", "[alpn]")
{
  SECTION("empty alpn")
  {
    const unsigned char no_protos[] = {0};
    CHECK(std::string("") == get_printable_alpn_string({(char *)no_protos, sizeof(no_protos)}));
  }
  SECTION("Single protocol")
  {
    const unsigned char one_protos[] = {2, 'h', '2'};
    CHECK(std::string("h2") == get_printable_alpn_string({(char *)one_protos, sizeof(one_protos)}));
  }
  SECTION("Two protocols")
  {
    const unsigned char two_protos[] = {2, 'h', '2', 7, 'h', 't', 't', 'p', '1', '.', '1'};
    CHECK(
        std::string("h2,http1.1") ==
        get_printable_alpn_string({(char *)two_protos, sizeof(two_protos)}));
  }
}
