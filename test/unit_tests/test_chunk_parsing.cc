/** @file
 * Unit tests for HttpReplay.h.
 *
 * Copyright 2020, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "catch.hpp"
#include "core/ProxyVerifier.h"

using swoc::TextView;

TEST_CASE("Check parsing of a chunked body", "[RuleCheck]") {
  size_t num_body_bytes = 0;
  ChunkCodex codex;
  std::string accumulated_body;
  ChunkCodex::ChunkCallback cb{
      [&num_body_bytes, &accumulated_body](TextView block, size_t offset,
                                           size_t size) -> bool {
        num_body_bytes += block.size();
        accumulated_body += block;
        return true;
      }};

  REQUIRE(ChunkCodex::CONTINUE == codex.parse("1", cb));
  REQUIRE(num_body_bytes == 0);
  REQUIRE(accumulated_body.empty());

  REQUIRE(ChunkCodex::CONTINUE == codex.parse("0", cb));
  REQUIRE(num_body_bytes == 0);
  REQUIRE(accumulated_body.empty());

  // Keep in mind that chunk length is in hex, so 10 means 0x10 which is 16
  // bytes.

  REQUIRE(ChunkCodex::CONTINUE == codex.parse("\r", cb));
  REQUIRE(num_body_bytes == 0);
  REQUIRE(accumulated_body.empty());

  REQUIRE(ChunkCodex::CONTINUE == codex.parse("\n", cb));
  REQUIRE(num_body_bytes == 0);
  REQUIRE(accumulated_body.empty());

  REQUIRE(ChunkCodex::CONTINUE == codex.parse("1", cb));
  REQUIRE(num_body_bytes == 1);
  REQUIRE(accumulated_body == "1");

  REQUIRE(ChunkCodex::CONTINUE == codex.parse("2", cb));
  REQUIRE(num_body_bytes == 2);
  REQUIRE(accumulated_body == "12");

  REQUIRE(ChunkCodex::CONTINUE == codex.parse("3456", cb));
  REQUIRE(num_body_bytes == 6);
  REQUIRE(accumulated_body == "123456");

  REQUIRE(ChunkCodex::CONTINUE == codex.parse("78901234", cb));
  REQUIRE(num_body_bytes == 14);
  REQUIRE(accumulated_body == "12345678901234");

  REQUIRE(ChunkCodex::CONTINUE == codex.parse("5", cb));
  REQUIRE(num_body_bytes == 15);
  REQUIRE(accumulated_body == "123456789012345");

  REQUIRE(ChunkCodex::CONTINUE == codex.parse("6", cb));
  REQUIRE(num_body_bytes == 16);
  REQUIRE(accumulated_body == "1234567890123456");

  REQUIRE(ChunkCodex::CONTINUE == codex.parse("\r", cb));
  REQUIRE(num_body_bytes == 16);
  REQUIRE(accumulated_body == "1234567890123456");

  REQUIRE(ChunkCodex::CONTINUE == codex.parse("\n", cb));
  REQUIRE(num_body_bytes == 16);
  REQUIRE(accumulated_body == "1234567890123456");

  // Add a second chunk.
  REQUIRE(ChunkCodex::CONTINUE == codex.parse("5\r\n78901\r\n", cb));
  REQUIRE(num_body_bytes == 21);
  REQUIRE(accumulated_body == "123456789012345678901");

  // This will represent a header for a new chunk. We'll make it the final
  // chunk by specifying a zero-length header.
  REQUIRE(ChunkCodex::CONTINUE == codex.parse("0", cb));
  REQUIRE(num_body_bytes == 21);
  REQUIRE(accumulated_body == "123456789012345678901");

  REQUIRE(ChunkCodex::CONTINUE == codex.parse("\r", cb));
  REQUIRE(num_body_bytes == 21);
  REQUIRE(accumulated_body == "123456789012345678901");

  REQUIRE(ChunkCodex::CONTINUE == codex.parse("\n", cb));
  REQUIRE(num_body_bytes == 21);
  REQUIRE(accumulated_body == "123456789012345678901");

  REQUIRE(ChunkCodex::CONTINUE == codex.parse("\r", cb));
  REQUIRE(num_body_bytes == 21);
  REQUIRE(accumulated_body == "123456789012345678901");

  // Only now, after this very final linefeed is sent, should the parser tell
  // us that the chunked content is done.
  REQUIRE(ChunkCodex::DONE == codex.parse("\n", cb));
  REQUIRE(num_body_bytes == 21);
  REQUIRE(accumulated_body == "123456789012345678901");
}
