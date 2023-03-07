/** @file
 * Common data structures and definitions for the PROXY protocol utility
 *
 * Copyright 2023, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "swoc/Errata.h"
#include "swoc/BufferWriter.h"
#include "swoc/TextView.h"
#include "swoc/swoc_ip.h"

/// PROXY header version
enum class ProxyProtocolVersion { NONE = 0, V1 = 1, V2 = 2 };

/// PROXY header v1 end of header.
static constexpr swoc::TextView PROXY_V1_EOH{"\r\n"};

/// The maximum size of a PROXY header(v1 and v2) without the TLV support.  This
/// is used to specify the data size to peek from the socket.
static constexpr size_t MAX_PP_HDR_SIZE = 108;

/// V1 and V2 header signatures
using namespace std::literals;
static const swoc::TextView V1SIG("PROXY");
constexpr swoc::TextView V2SIG = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"sv;

static constexpr char PP_V1_DELIMITER = ' ';

/// This is the union structure taken from the PROXY protocol specification that
/// defines v1 and v2 PROXY header:
/// https://github.com/haproxy/haproxy/blob/master/doc/proxy-protocol.txt. Note
/// that the linux socket address is removed from the v2 header, as it is not
/// supported in Proxy Verifier.
union ProxyHdr {
  struct
  {
    char line[108];
  } v1;
  struct
  {
    uint8_t sig[12];
    uint8_t ver_cmd;
    uint8_t fam;
    uint16_t len;
    union {
      struct
      { /* for TCP/UDP over IPv4, len = 12 */
        uint32_t src_addr;
        uint32_t dst_addr;
        uint16_t src_port;
        uint16_t dst_port;
      } ip4;
      struct
      { /* for TCP/UDP over IPv6, len = 36 */
        uint8_t src_addr[16];
        uint8_t dst_addr[16];
        uint16_t src_port;
        uint16_t dst_port;
      } ip6;
    } addr;
  } v2;
};

class ProxyProtocolUtil
{
public:
  ProxyProtocolUtil() = default;
  ProxyProtocolUtil(swoc::IPEndpoint src_ep, swoc::IPEndpoint dst_ep, ProxyProtocolVersion version)
    : _version(version)
    , _src_addr(src_ep)
    , _dst_addr(dst_ep){};

  /** Parse the data as a PROXY header
   *
   * @param[in] data The data to parse.
   * @return return the number of bytes of parsed PROXY header if it is valid or
   * -1 otherwise.
   */
  swoc::Rv<ssize_t> parse_header(swoc::TextView data);

  /** Serialize the PROXY header into the buffer.
   *
   * @param[out] buf The buffer to write the PROXY header.
   */
  swoc::Errata serialize(swoc::BufferWriter &buf) const;

  /** Return the version of the parsed PROXY header.
   *
   * @return the version of the PROXY header.
   */
  ProxyProtocolVersion get_version() const;

  /** Return the IP endpoint representing the source address
   * in the PROXY header.
   *
   * @return the source IP endpoint.
   */
  swoc::IPEndpoint get_src_ep() const;

  /** Return the IP endpoint representing the destination address
   * in the PROXY header.
   *
   * @return the destination IP endpoint.
   */
  swoc::IPEndpoint get_dst_ep() const;

private:
  swoc::Rv<ssize_t> parse_pp_header_v1(swoc::TextView data);
  swoc::Rv<ssize_t> parse_pp_header_v2(swoc::TextView data);
  swoc::Errata construct_v1_header(swoc::BufferWriter &buf) const;
  swoc::Errata construct_v2_header(swoc::BufferWriter &buf) const;

  ProxyProtocolVersion _version = ProxyProtocolVersion::NONE;
  swoc::IPEndpoint _src_addr;
  swoc::IPEndpoint _dst_addr;
};

inline ProxyProtocolVersion
ProxyProtocolUtil::get_version() const
{
  return _version;
}

inline swoc::IPEndpoint
ProxyProtocolUtil::get_src_ep() const
{
  return _src_addr;
}

inline swoc::IPEndpoint
ProxyProtocolUtil::get_dst_ep() const
{
  return _dst_addr;
}
