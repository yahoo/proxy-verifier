/** @file
 * Unit tests for PROXY protocol header parsing.
 *
 * Copyright 2026, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "catch.hpp"

#include "core/proxy_protocol_util.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "swoc/BufferWriter.h"
#include "swoc/swoc_ip.h"

namespace
{
constexpr uint8_t VERSION_2_PROXY_COMMAND = 0x21;
constexpr uint8_t FAMILY_TCP4 = 0x11;
constexpr uint8_t FAMILY_TCP6 = 0x21;
constexpr uint16_t TCP4_ADDRESS_LENGTH = 12;
constexpr uint16_t TCP6_ADDRESS_LENGTH = 36;

/** Build a PROXY v2 header whose body is @a declared_length zero bytes.
 *
 * @param[in] family The address family byte.
 * @param[in] declared_length The value of the header's length field.
 * @return The serialized header.
 */
std::string
build_v2_header(uint8_t family, uint16_t declared_length)
{
  std::string header{V2SIG};
  header.push_back(static_cast<char>(VERSION_2_PROXY_COMMAND));
  header.push_back(static_cast<char>(family));
  header.push_back(static_cast<char>(declared_length >> 8));
  header.push_back(static_cast<char>(declared_length & 0xFF));
  header.append(declared_length, '\0');
  return header;
}
} // namespace

TEST_CASE("PROXY v2 headers too short for their address family are rejected", "[proxy_protocol]")
{
  struct ShortHeader
  {
    std::string description;
    uint8_t family;
    uint16_t declared_length;
  };
  std::vector<ShortHeader> const short_headers = {
      {.description = "TCP4 with no address block", .family = FAMILY_TCP4, .declared_length = 0},
      {.description = "TCP4 with a truncated address block",
       .family = FAMILY_TCP4,
       .declared_length = TCP4_ADDRESS_LENGTH - 1},
      {.description = "TCP6 with no address block", .family = FAMILY_TCP6, .declared_length = 0},
      {.description = "TCP6 with a TCP4-sized address block",
       .family = FAMILY_TCP6,
       .declared_length = TCP4_ADDRESS_LENGTH},
      {.description = "TCP6 with a truncated address block",
       .family = FAMILY_TCP6,
       .declared_length = TCP6_ADDRESS_LENGTH - 1},
  };
  for (auto const &test : short_headers) {
    SECTION(test.description)
    {
      // Pad the storage with non-zero bytes past the header so any read past
      // the declared length would produce a non-zero address.
      std::array<char, MAX_PP_HDR_SIZE> storage;
      storage.fill('\xFF');
      auto const header = build_v2_header(test.family, test.declared_length);
      REQUIRE(header.size() <= storage.size());
      std::copy(header.begin(), header.end(), storage.begin());

      ProxyProtocolMsg msg;
      auto const &&[num_bytes, errata] = msg.parse_header({storage.data(), header.size()});
      CHECK(num_bytes == -1);
      CHECK_FALSE(errata.is_ok());
      CHECK(msg.get_version() == ProxyProtocolVersion::NONE);
    }
  }
}

TEST_CASE("PROXY v2 headers with complete address blocks are parsed", "[proxy_protocol]")
{
  swoc::IPEndpoint const src{swoc::IPSrv{swoc::IPAddr{"10.1.2.3"}, 1111}};
  swoc::IPEndpoint const dst{swoc::IPSrv{swoc::IPAddr{"10.4.5.6"}, 2222}};
  ProxyProtocolMsg const sent{src, dst, ProxyProtocolVersion::V2};
  swoc::LocalBufferWriter<MAX_PP_HDR_SIZE> w;
  REQUIRE(sent.serialize(w).is_ok());

  ProxyProtocolMsg received;
  auto const &&[num_bytes, errata] = received.parse_header(w.view());
  CHECK(num_bytes == PP_V2_FIXED_HDR_SIZE + TCP4_ADDRESS_LENGTH);
  CHECK(received.get_version() == ProxyProtocolVersion::V2);
  CHECK(swoc::IPAddr{received.get_src_ep()} == swoc::IPAddr{src});
  CHECK(received.get_src_ep().host_order_port() == src.host_order_port());
  CHECK(swoc::IPAddr{received.get_dst_ep()} == swoc::IPAddr{dst});
  CHECK(received.get_dst_ep().host_order_port() == dst.host_order_port());
}
