#include "core/proxy_protocol_util.h"
#include "core/ProxyVerifier.h"
#include <codecvt>
#include <locale>
#include "swoc/bwf_ex.h"
#include "swoc/bwf_ip.h"
#include "swoc/swoc_ip.h"

using swoc::Errata;
using swoc::TextView;
using swoc::IPAddr;
using swoc::IP4Addr;
using swoc::IP6Addr;
using swoc::IPEndpoint;

swoc::Rv<ssize_t>
ProxyProtocolUtil::parse_pp_header_v1(swoc::TextView data)
{
  // parse the data as a PROXY header v1. The data is expected to contain the v1
  // signature to to enter this function
  swoc::Rv<ssize_t> zret{-1};
  size_t size = 0;
  auto offset = data.find(PROXY_V1_EOH);
  if (offset == TextView::npos) {
    // partial or invalid header
    zret.note(S_ERROR, "Incomplete or invalid PROXY header");
    return zret;
  }

  size = offset + PROXY_V1_EOH.size();
  // Assuming the PROXY header has already been validated, we can just skip the
  // "PROXY "
  data += V1SIG.size() + 1;
  // parse family
  auto familyView = data.split_prefix_at(PP_V1_DELIMITER);
  if (familyView.empty()) {
    zret.note(S_ERROR, "Invalid PROXY header: expecting network family");
    return zret;
  }

  // parse source IP address
  auto srcIPView = data.split_prefix_at(PP_V1_DELIMITER);
  if (srcIPView.empty()) {
    zret.note(S_ERROR, "Invalid PROXY header: expecting source IP");
    return zret;
  }
  IPAddr srcIP(srcIPView);

  // parse dest IP address
  auto dstIPView = data.split_prefix_at(PP_V1_DELIMITER);
  if (dstIPView.empty()) {
    zret.note(S_ERROR, "Invalid PROXY header: expecting destination IP");
    return zret;
  }
  IPAddr dstIP(dstIPView);

  // parse the port
  zret.note(S_DIAG, "before the source port content: {}", data);
  auto srcPortView = data.split_prefix_at(PP_V1_DELIMITER);
  if (srcPortView.empty()) {
    zret.note(S_ERROR, "Invalid PROXY header: expecting source port");
    return zret;
  }
  auto srcPort = swoc::svto_radix<10>(srcPortView);
  // parse the dest port
  zret.note(S_DIAG, "before the dest port content: {:x}", data);
  auto dstPortView = data.split_prefix_at('\r');
  if (dstPortView.empty()) {
    zret.note(S_ERROR, "Invalid PROXY header: expecting destination port");
    return zret;
  }
  auto dstPort = swoc::svto_radix<10>(dstPortView);
  // assign the source and destination addresses
  _src_addr.assign(srcIP, htons(srcPort));
  _dst_addr.assign(dstIP, htons(dstPort));
  if (!_src_addr.is_valid() || !_dst_addr.is_valid()) {
    zret.note(S_ERROR, "Invalid PROXY header: IP address not valid");
    return zret;
  }
  // valid PORXY header, return the size of it
  _version = ProxyProtocolVersion::V1;
  zret = size;
  return zret;
}

swoc::Rv<ssize_t>
ProxyProtocolUtil::parse_pp_header_v2(swoc::TextView data)
{
  // parse the data as a PROXY header v2. The data is expected to contain the v2
  // signature to to enter this function
  swoc::Rv<ssize_t> zret{-1};
  auto receivedBytes = data.size();
  auto const *hdr = reinterpret_cast<const ProxyHdr *>(data.data());
  size_t size = 0;
  // this size of the header
  size = 16 + ntohs(hdr->v2.len);
  if (receivedBytes < size) {
    // truncated or too large header
    return zret;
  }
  switch (hdr->v2.ver_cmd & 0xF) {
  case 0x01: /* PROXY command */
    switch (hdr->v2.fam) {
    case 0x11: /* TCPv4 */
      // the ntohl() is needed because the address is stored in network byte
      // order and IPAddr expects a host byte order, which would in turn get
      // converted to network byte order in IPEndpoint.assign()
      _src_addr.assign(
          IPAddr(reinterpret_cast<in_addr_t>(ntohl(hdr->v2.addr.ip4.src_addr))),
          hdr->v2.addr.ip4.src_port);
      _dst_addr.assign(
          IPAddr(reinterpret_cast<in_addr_t>(ntohl(hdr->v2.addr.ip4.dst_addr))),
          hdr->v2.addr.ip4.dst_port);
      break;
    case 0x21: /* TCPv6 */
    {
      // IPv6 address doesn't have to handle endianess
      IPAddr srcAddr(reinterpret_cast<const in6_addr&>(hdr->v2.addr.ip6.src_addr));
      IPAddr dstAddr(reinterpret_cast<const in6_addr&>(hdr->v2.addr.ip6.dst_addr));
      _src_addr.assign(srcAddr, hdr->v2.addr.ip6.src_port);
      _dst_addr.assign(dstAddr, hdr->v2.addr.ip6.dst_port);
      break;
    }
    default:
      /* unsupported transport protocol */
      zret.note(S_DIAG, "unsupported transport found in PROXY header");
      break;
    }
    break;
  default:
    zret.note(S_DIAG, "unsupported command found in PROXY header");
    return zret; /* not a supported command */
  }
  if (!_src_addr.is_valid() || !_dst_addr.is_valid()) {
    zret.note(S_ERROR, "Invalid PROXY header: IP address not valid");
    return zret;
  }
  // valid PORXY header, return the size of it
  _version = ProxyProtocolVersion::V2;
  zret = size;
  return zret;
}

swoc::Rv<ssize_t>
ProxyProtocolUtil::parse_header(swoc::TextView data)
{
  swoc::Rv<ssize_t> zret{-1};
  auto receivedBytes = data.size();
  if (receivedBytes >= 16 && (data.starts_with(V2SIG))) {
    return parse_pp_header_v2(data);
  } else if (receivedBytes >= 8 && data.starts_with(V1SIG)) {
    return parse_pp_header_v1(data);
  }
  zret.note(S_DIAG, "No valid PROXY protocol detected.");
  return zret;
}

swoc::Errata
ProxyProtocolUtil::serialize(swoc::BufferWriter &buf) const
{
  swoc::Errata errata;
  if (_version == ProxyProtocolVersion::V1) {
    return construct_v1_header(buf);
  } else if (_version == ProxyProtocolVersion::V2) {
    return construct_v2_header(buf);
  }
  errata.note(S_ERROR, "unknown proxy protocol version.");
  return errata;
};

swoc::Errata
ProxyProtocolUtil::construct_v1_header(swoc::BufferWriter &buf) const
{
  swoc::Errata errata;
  buf.print(
      "PROXY {}{} {2::a} {3::a} {2::p} {3::p}\r\n",
      swoc::bwf::If(_src_addr.is_ip4(), "TCP4"),
      swoc::bwf::If(_src_addr.is_ip6(), "TCP6"),
      _src_addr,
      _dst_addr);
  errata.note(
      S_DIAG,
      "construcuting {} bytes of proxy protocol v1 header content:\n{}",
      buf.size(),
      buf);
  return errata;
}

swoc::Errata
ProxyProtocolUtil::construct_v2_header(swoc::BufferWriter &buf) const
{
  swoc::Errata errata;
  ProxyHdr proxy_hdr;
  memcpy(proxy_hdr.v2.sig, V2SIG.data(), V2SIG.size());
  // only support the PROXY command
  proxy_hdr.v2.ver_cmd = 0x21;
  int addr_len = 0;
  if (_src_addr.is_ip4()) {
    proxy_hdr.v2.fam = 0x11;
    addr_len = sizeof(proxy_hdr.v2.addr.ip4);
    proxy_hdr.v2.len = htons(addr_len);
    proxy_hdr.v2.addr.ip4.src_addr = _src_addr.sa4.sin_addr.s_addr;
    proxy_hdr.v2.addr.ip4.dst_addr = _dst_addr.sa4.sin_addr.s_addr;
    proxy_hdr.v2.addr.ip4.src_port = _src_addr.network_order_port();
    proxy_hdr.v2.addr.ip4.dst_port = _dst_addr.network_order_port();
  } else {
    // ipv6
    proxy_hdr.v2.fam = 0x21;
    addr_len = sizeof(proxy_hdr.v2.addr.ip6);
    proxy_hdr.v2.len = htons(addr_len);
    memcpy(proxy_hdr.v2.addr.ip6.src_addr, _src_addr.sa6.sin6_addr.s6_addr, 16);
    memcpy(proxy_hdr.v2.addr.ip6.dst_addr, _dst_addr.sa6.sin6_addr.s6_addr, 16);
    proxy_hdr.v2.addr.ip6.src_port = _src_addr.network_order_port();
    proxy_hdr.v2.addr.ip6.dst_port = _dst_addr.network_order_port();
  }
  buf.write(&proxy_hdr, addr_len + 16);
  errata.note(S_DIAG, "construcuting {} bytes of proxy protocol v2 header", buf.size());
  return errata;
}
