/** @file
 * Common implementation for Proxy Verifier
 *
 * Copyright 2021, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "core/http.h"
#include "core/verification.h"
#include "core/ProxyVerifier.h"

#include <arpa/inet.h>
#include <cassert>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netinet/tcp.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <thread>
#include <unistd.h>

#include "swoc/bwf_ex.h"
#include "swoc/bwf_ip.h"
#include "swoc/bwf_std.h"

using swoc::Errata;
using swoc::TextView;
using namespace swoc::literals;
using namespace std::literals;
using std::this_thread::sleep_until;
using std::this_thread::sleep_for;

namespace chrono = std::chrono;
using ClockType = std::chrono::system_clock;
using chrono::duration_cast;
using chrono::milliseconds;

constexpr int MAX_NOFILE = 300000;

std::string HttpHeader::_key_format{"{field.uuid}"};
swoc::MemSpan<char> HttpHeader::_content;
std::bitset<600> HttpHeader::STATUS_NO_CONTENT;

memoized_ip_endpoints_t InterfaceNameToEndpoint::memoized_ip_endpoints;

namespace swoc
{
inline namespace SWOC_VERSION_NS
{
BufferWriter &
bwformat(BufferWriter &w, bwf::Spec const & /* spec */, HttpHeader const &h)
{
  if (h.is_http2() || h.is_http3()) {
    if (h._status) {
      w.print(R"(- ":status": "{}"{})", h._status_string, '\n');
    } else {
      w.print(R"(- ":method": "{}"{})", h._method, '\n');
      w.print(R"(- ":scheme": "{}"{})", h._scheme, '\n');
      w.print(R"(- ":authority": "{}"{})", h._authority, '\n');
      w.print(R"(- ":path": "{}"{})", h._path, '\n');
    }
  }
  for (auto const &[key, value] : h._fields_rules->_fields_sequence) {
    if (key.starts_with(":")) {
      // Pseudo headers are handled specially above. Do not reprint them here.
      continue;
    }
    w.print(R"(- "{}": "{}"{})", key, value, '\n');
  }
  return w;
}
} // namespace SWOC_VERSION_NS
} // namespace swoc

void
HttpHeader::global_init()
{
  STATUS_NO_CONTENT[100] = true;
  STATUS_NO_CONTENT[204] = true;
  STATUS_NO_CONTENT[304] = true;

  RuleCheck::options_init();
}

swoc::Errata
Ssn::post_process_transactions()
{
  swoc::Errata errata;
  _transactions.sort([](Txn const &txn1, Txn const &txn2) { return txn1._start < txn2._start; });
  auto const offset_time = _transactions.front()._start;
  for (auto &txn : _transactions) {
    if (txn._start >= offset_time) {
      txn._start -= offset_time;
    }
  }
  return errata;
}

void
HttpHeader::set_max_content_length(size_t n)
{
  n = swoc::round_up<16>(n);
  _content.assign(static_cast<char *>(malloc(n)), n);
  for (size_t k = 0; k < n; k += 8) {
    swoc::FixedBufferWriter w{_content.data() + k, 8};
    w.print("{:07x} ", k / 8);
  };
}

swoc::Errata
HttpHeader::update_content_length(swoc::TextView method)
{
  swoc::Errata errata;
  size_t cl = std::numeric_limits<size_t>::max();
  _content_length_p = false;
  // Some methods ignore the Content-Length for the current transaction
  if (strcasecmp(method, "HEAD") == 0) {
    // Don't try chunked encoding later
    _content_size = 0;
    _content_length_p = true;
  } else if (auto spot{_fields_rules->_fields.find(FIELD_CONTENT_LENGTH)};
             spot != _fields_rules->_fields.end())
  {
    cl = swoc::svtou(spot->second);
    _content_size = cl;
    _content_length_p = true;
  }
  return errata;
}

swoc::Errata
HttpHeader::update_transfer_encoding()
{
  _chunked_p = false;
  if (auto spot{_fields_rules->_fields.find(FIELD_TRANSFER_ENCODING)};
      spot != _fields_rules->_fields.end())
  {
    if (0 == strcasecmp("chunked", spot->second)) {
      _chunked_p = true;
      _has_transfer_encoding_chunked = true;
    }
  }
  return {};
}

swoc::Errata
HttpHeader::serialize(swoc::BufferWriter &w) const
{
  swoc::Errata errata;

  if (is_response()) {
    w.print("HTTP/{} {} {}{}", _http_version, _status, _reason, HTTP_EOL);
  } else if (is_request()) {
    w.print("{} {} HTTP/{}{}", _method, _url, _http_version, HTTP_EOL);
  } else {
    errata.error(R"(Unable to write header: could not determine request/response state.)");
  }

  for (auto const &[name, value] : _fields_rules->_fields_sequence) {
    w.write(name).write(": ").write(value).write(HTTP_EOL);
  }
  w.write(HTTP_EOL);

  return errata;
}

HttpFields::HttpFields()
{
  _fields_sequence.reserve(num_fields_to_reserve);
}

void
HttpFields::add_field(swoc::TextView name, swoc::TextView value)
{
  _fields.emplace(name, value);
  _fields_sequence.push_back({name, value});
}

void
HttpFields::merge(HttpFields const &other)
{
  for (auto const &field : other._fields) {
    _fields.emplace(field.first, field.second);
  }
  for (auto const &field : other._fields_sequence) {
    _fields_sequence.push_back({field.name, field.value});
  }
  for (auto const &rule : other._rules) {
    _rules.emplace(rule.first, rule.second);
  }
}

void
HttpFields::add_fields_to_ngnva(nghttp2_nv *l) const
{
  int offset = 0;
  for (auto const &[key, value] : _fields_sequence) {
    if (key.starts_with(":")) {
      // Pseudo header fields are handled specially via the _method, _status
      // HttpHeader member variables. This provides continuity in
      // implementation with HTTP/1. In any case, they are added to the vector
      // independently.
      continue;
    }
    l[offset++] = nghttp2_nv{
        const_cast<uint8_t *>((uint8_t *)key.data()),
        const_cast<uint8_t *>((uint8_t *)value.data()),
        key.length(),
        value.length(),
        NGHTTP2_NV_FLAG_NONE};
  }
}

void
HttpFields::add_fields_to_ngnva(nghttp3_nv *l) const
{
  int offset = 0;
  for (auto const &[key, value] : _fields_sequence) {
    if (key.starts_with(":")) {
      // Pseudo header fields are handled specially via the _method, _status
      // HttpHeader member variables. This provides continuity in
      // implementation with HTTP/1. In any case, they are added to the vector
      // independently.
      continue;
    }
    l[offset++] = nghttp3_nv{
        const_cast<uint8_t *>((uint8_t *)key.data()),
        const_cast<uint8_t *>((uint8_t *)value.data()),
        key.length(),
        value.length(),
        NGHTTP2_NV_FLAG_NONE};
  }
}

swoc::Errata
HttpHeader::parse_url(TextView url)
{
  swoc::Errata errata;

  // URI parsing
  std::size_t scheme_end = url.find("://");
  std::size_t host_start = 0;
  if (scheme_end != std::string::npos) {
    host_start = scheme_end + 3; // "://" is 3 characters
  }
  std::size_t path_start = url.find("/", host_start); // / begins path
  std::size_t query_start = url.find("?", host_start);
  std::size_t fragment_start = url.find("#", host_start);
  std::size_t authority_end = std::min({path_start, query_start, fragment_start});

  std::size_t port_start = url.find(":", host_start); // : begins port
  if (port_start > path_start && path_start != std::string::npos) {
    port_start = std::string::npos;
  }

  std::size_t host_end = port_start;
  if (port_start == std::string::npos) {
    host_end = authority_end;
  }
  std::size_t port_end = authority_end;
  if (port_start != std::string::npos) {
    ++port_start;
  }

  if (scheme_end != std::string::npos) {
    uri_scheme = url.substr(0, scheme_end);
  }
  uri_host = url.substr(host_start, host_end - host_start);
  if (port_start != std::string::npos) {
    uri_port = url.substr(port_start, port_end - port_start);
  } else {
    port_end = host_end;
  }
  uri_authority = url.substr(host_start, port_end - host_start);
  std::size_t path_end = std::min({query_start, fragment_start});
  if (path_end == std::string::npos) {
    path_end = url.length();
  }
  std::size_t query_end = fragment_start;
  if (fragment_start == std::string::npos) {
    query_end = url.length();
  }
  std::size_t fragment_end = url.length();
  if (query_start != std::string::npos) {
    ++query_start;
  }
  if (fragment_start != std::string::npos) {
    ++fragment_start;
  }

  if (path_start != std::string::npos) {
    uri_path = url.substr(path_start, path_end - path_start);
  }
  if (query_start != std::string::npos) {
    uri_query = url.substr(query_start, query_end - query_start);
  }
  if (fragment_start != std::string::npos) {
    uri_fragment = url.substr(fragment_start, fragment_end - fragment_start);
  }

  _fields_rules->_url_parts[static_cast<size_t>(UrlPart::Scheme)] = uri_scheme;
  _fields_rules->_url_parts[static_cast<size_t>(UrlPart::Host)] = uri_host;
  _fields_rules->_url_parts[static_cast<size_t>(UrlPart::Port)] = uri_port;
  _fields_rules->_url_parts[static_cast<size_t>(UrlPart::Authority)] = uri_authority;
  _fields_rules->_url_parts[static_cast<size_t>(UrlPart::Path)] = uri_path;
  _fields_rules->_url_parts[static_cast<size_t>(UrlPart::Query)] = uri_query;
  _fields_rules->_url_parts[static_cast<size_t>(UrlPart::Fragment)] = uri_fragment;

  // Non-URI parsing
  // Split out the path and scheme for http/2 required headers
  // See rfc3986 section-3.2.
  std::size_t end_scheme = url.find("://");
  std::size_t start_auth = 0;
  if (end_scheme == std::string::npos) {
    start_auth = 0;
  } else {
    start_auth = end_scheme + 3; // "://" is 3 characters.
    _scheme = url.substr(0, end_scheme);
  }
  std::size_t end_host = start_auth;
  // Look for the ':' for the port.
  std::size_t next_slash = url.find("/", start_auth);
  std::size_t next_query = url.find("?", start_auth);
  std::size_t next_fragment = url.find("#", start_auth);
  end_host = std::min({next_slash, next_query, next_fragment});
  if (end_host == std::string::npos) {
    // No ':' nor '/', '?', or '#'. Assume the rest of the string is the host.
    end_host = url.length();
  }
  _authority = url.substr(start_auth, end_host - start_auth);
  // _path is the value used for HTTP/2 ':path' and thus includes everything past
  // the authority.
  if (end_host != url.length()) {
    _path = url.substr(end_host);
  }
  return errata;
}

UrlPart
HttpHeader::parse_url_part(swoc::TextView name)
{
  return URL_PART_NAMES[name];
}

void
HttpHeader::set_key(TextView new_key)
{
  _key = new_key;
}

std::string
HttpHeader::get_key() const
{
  return _key;
}

void
HttpHeader::derive_key()
{
  if (_key != TRANSACTION_KEY_NOT_SET) {
    // Key has already been derived or has been explicitly set by the user.
    return;
  }
  swoc::FixedBufferWriter w{nullptr};
  Binding binding(*this);
  w.print_n(binding, _key_format);
  _key.resize(w.extent());
  swoc::FixedBufferWriter{_key.data(), _key.size()}.print_n(binding, _key_format);
}

// Verify that the fields in 'this' correspond to the provided rules.
bool
HttpHeader::verify_headers(swoc::TextView transaction_key, HttpFields const &rules_) const
{
  // Remains false if no issue is observed
  // Setting true does not break loop because test() calls errata.diag()
  bool issue_exists = false;
  auto const &rules = rules_._rules;
  auto const *url_rules = rules_._url_rules;
  auto const &fields = _fields_rules->_fields;
  auto const *url_parts = _fields_rules->_url_parts;
  for (auto const &[name, rule_check] : rules) {
    auto name_range = fields.equal_range(name);
    auto field_iter = name_range.first;
    if (rule_check->expects_duplicate_fields()) {
      if (field_iter == name_range.second) {
        if (!rule_check->test(transaction_key, swoc::TextView(), std::vector<TextView>{})) {
          // We supply the empty name and value for the absence check which
          // expects this to indicate an absent field.
          issue_exists = true;
        }
      } else {
        std::vector<TextView> values;
        while (field_iter != name_range.second) {
          values.emplace_back(field_iter->second);
          ++field_iter;
        }
        if (!rule_check->test(transaction_key, name, values)) {
          issue_exists = true;
        }
      }
    } else {
      if (field_iter == name_range.second) {
        if (!rule_check->test(transaction_key, swoc::TextView(), swoc::TextView())) {
          // We supply the empty name and value for the absence check which
          // expects this to indicate an absent field.
          issue_exists = true;
        }
      } else {
        if (!rule_check
                 ->test(transaction_key, field_iter->first, swoc::TextView(field_iter->second))) {
          issue_exists = true;
        }
      }
    }
  }
  for (std::size_t i = 0; i < URL_PART_NAMES.count(); ++i) {
    const std::vector<std::shared_ptr<RuleCheck>> &v = url_rules[i];
    for (size_t j = 0; j < v.size(); ++j) {
      const std::shared_ptr<RuleCheck> rule_check = v[j];
      swoc::TextView value = url_parts[i];
      if (rule_check == nullptr) {
        continue;
      }
      if (value.empty()) {
        if (!rule_check->test(transaction_key, swoc::TextView(), swoc::TextView())) {
          // We supply the empty name and value for the absence check which
          // expects this to indicate an absent field.
          issue_exists = true;
        }
      } else {
        if (!rule_check->test(transaction_key, URL_PART_NAMES[static_cast<UrlPart>(i)], value)) {
          issue_exists = true;
        }
      }
    }
  }
  return issue_exists;
}

void
HttpHeader::merge(HttpFields const &other)
{
  _fields_rules->merge(other);
  derive_key();
}

HttpHeader::HttpHeader(bool verify_strictly)
  : _fields_rules{std::make_shared<HttpFields>()}
  , _verify_strictly{verify_strictly}
  , _key{TRANSACTION_KEY_NOT_SET}
{
}

HTTP_PROTOCOL_TYPE
HttpHeader::get_http_protocol() const
{
  return _http_protocol;
}

void
HttpHeader::set_http_protocol(HTTP_PROTOCOL_TYPE protocol)
{
  _http_protocol = protocol;
}

void
HttpHeader::set_is_http1()
{
  _http_protocol = HTTP_PROTOCOL_TYPE::HTTP_1;
}

bool
HttpHeader::is_http1() const
{
  return _http_protocol == HTTP_PROTOCOL_TYPE::HTTP_1;
}

void
HttpHeader::set_is_http2()
{
  _http_protocol = HTTP_PROTOCOL_TYPE::HTTP_2;
}

bool
HttpHeader::is_http2() const
{
  return _http_protocol == HTTP_PROTOCOL_TYPE::HTTP_2;
}

void
HttpHeader::set_is_http3()
{
  _http_protocol = HTTP_PROTOCOL_TYPE::HTTP_3;
}

bool
HttpHeader::is_http3() const
{
  return _http_protocol == HTTP_PROTOCOL_TYPE::HTTP_3;
}

void
HttpHeader::set_is_request(HTTP_PROTOCOL_TYPE protocol)
{
  _is_request = true;
  _http_protocol = protocol;
}

void
HttpHeader::set_is_request()
{
  _is_request = true;
}

bool
HttpHeader::is_request() const
{
  return _is_request;
}

void
HttpHeader::set_is_response(HTTP_PROTOCOL_TYPE protocol)
{
  _is_request = false;
  _http_protocol = protocol;
}

void
HttpHeader::set_is_response()
{
  _is_request = false;
}

bool
HttpHeader::is_response() const
{
  return !_is_request;
}

bool
icompare_pred(unsigned char a, unsigned char b)
{
  return std::tolower(a) == std::tolower(b);
}

bool
icompare(swoc::TextView const &a, swoc::TextView const &b)
{
  if (a.length() == b.length()) {
    return std::equal(b.begin(), b.end(), a.begin(), icompare_pred);
  } else {
    return false;
  }
}

swoc::Rv<HttpHeader::ParseResult>
HttpHeader::parse_request(swoc::TextView data)
{
  swoc::Rv<ParseResult> zret{PARSE_OK};

  if (swoc::TextView::npos == data.rfind(HTTP_EOH)) {
    zret = PARSE_INCOMPLETE;
  } else {
    data.remove_suffix(HTTP_EOH.size());

    auto first_line{data.take_prefix_at('\n')};
    if (first_line) {
      first_line.remove_suffix_if(&isspace);
      _method = first_line.take_prefix_if(&isspace);
      _url = first_line.ltrim_if(&isspace).take_prefix_if(&isspace);
      parse_url(_url);
      set_is_request();

      while (data) {
        auto field{data.take_prefix_at('\n').rtrim_if(&isspace)};
        if (field.empty()) {
          continue;
        }
        auto value{field};
        auto name{value.take_prefix_at(':')};
        value.trim_if(&isspace);
        if (name) {
          _fields_rules->add_field(name, value);
          if (icompare(name, "expect") && icompare(value, "100-continue")) {
            _send_continue = true;
          }
        } else {
          zret = PARSE_ERROR;
          zret.error(R"(Malformed field "{}".)", field);
        }
      }
      derive_key();
    } else {
      zret = PARSE_ERROR;
      zret.error("Empty first line in request.");
    }
  }
  return zret;
}

swoc::Rv<HttpHeader::ParseResult>
HttpHeader::parse_response(swoc::TextView data)
{
  swoc::Rv<ParseResult> zret{PARSE_OK};
  auto eoh = data.find(HTTP_EOH);

  if (swoc::TextView::npos == eoh) {
    zret = PARSE_INCOMPLETE;
  } else {
    data = data.prefix(eoh);

    auto first_line{data.take_prefix_at('\n').rtrim_if(&isspace)};
    if (first_line) {
      first_line.take_prefix_if(&isspace); // Remove the "HTTP/<version>" prefix.
      auto status{first_line.ltrim_if(&isspace).take_prefix_if(&isspace)};
      _status = swoc::svtou(status);
      _status_string = std::string(status);
      set_is_response();

      if (_status < 1 || _status > 599) {
        zret.error(
            "Unexpected response status: expected an integer in the range [1..599], got: {}",
            _status);
      }

      while (data) {
        auto field{data.take_prefix_at('\n').rtrim_if(&isspace)};
        if (field.empty()) {
          continue;
        }
        auto value{field};
        auto name{value.take_prefix_at(':')};
        value.trim_if(&isspace);
        if (name) {
          _fields_rules->add_field(name, value);
        } else {
          zret = PARSE_ERROR;
          zret.error(R"(Malformed field "{}".)", field);
        }
      }
      derive_key();
    } else {
      zret = PARSE_ERROR;
      zret.error("Empty first line in response.");
    }
  }
  return zret;
}

swoc::BufferWriter &
HttpHeader::Binding::operator()(BufferWriter &w, const swoc::bwf::Spec &spec) const
{
  static constexpr TextView FIELD_PREFIX{"field."};
  TextView name{spec._name};
  if (name.starts_with_nocase(FIELD_PREFIX)) {
    name.remove_prefix(FIELD_PREFIX.size());
    if (auto spot{_hdr._fields_rules->_fields.find(name)};
        spot != _hdr._fields_rules->_fields.end()) {
      bwformat(w, spec, spot->second);
    } else {
      bwformat(w, spec, TRANSACTION_KEY_NOT_SET);
    }
  } else if (0 == strcasecmp("url"_tv, name)) {
    if (_hdr._url.empty()) {
      bwformat(w, spec, TRANSACTION_KEY_NOT_SET);
    } else {
      bwformat(w, spec, _hdr._url);
    }
  } else {
    bwformat(w, spec, TRANSACTION_KEY_NOT_SET);
  }
  return w;
}

Session::Session() { }

Session::~Session()
{
  this->close();
}

swoc::Rv<ssize_t>
Session::read(swoc::MemSpan<char> span)
{
  swoc::Rv<ssize_t> zret{::read(_fd, span.data(), span.size())};
  if (zret == 0) {
    // End of file.
    this->close();
  } else if (zret < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      auto &&[poll_return, poll_errata] = poll_for_data_on_socket(Poll_Timeout);
      zret.note(std::move(poll_errata));
      if (!zret.is_ok()) {
        zret.note(std::move(poll_errata));
        zret.error("Failed to poll for data.");
        this->close();
      } else if (poll_return > 0) {
        // Simply repeat the read now that poll says something is ready.
        return read(span);
      } else if (poll_return == 0) {
        zret.error("Poll timed out waiting for content.");
        this->close();
      } else if (poll_return < 0) {
        // Connection was closed. Nothing to do.
        zret.diag("The peer closed the connection while reading during poll.");
      }
    } else if (errno == ECONNRESET) {
      // The other end closed the connection.
      zret.diag("The peer closed the connection while reading.");
      this->close();
    } else {
      zret.error("Error reading from socket: {}", swoc::bwf::Errno{});
      this->close();
    }
  }
  return zret;
}

swoc::Rv<std::shared_ptr<HttpHeader>>
Session::read_and_parse_request(swoc::FixedBufferWriter &buffer)
{
  swoc::Rv<std::shared_ptr<HttpHeader>> zret{nullptr};
  auto &&[header_bytes_read, read_header_errata] = read_headers(buffer);
  zret.note(read_header_errata);
  if (!read_header_errata.is_ok()) {
    zret.error("Could not read the header.");
    return zret;
  }

  _body_offset = header_bytes_read;
  if (_body_offset == 0) {
    return zret;
  }

  zret = std::make_shared<HttpHeader>();
  auto &hdr = zret.result();
  auto received_data = TextView(buffer.data(), _body_offset);
  auto &&[parse_result, parse_errata] = hdr->parse_request(received_data);
  zret.note(parse_errata);

  if (parse_result != HttpHeader::PARSE_OK || !zret.is_ok()) {
    zret.error(R"(The received request was malformed.)");
    zret.diag(R"(Received data: {}.)", received_data);
  }
  auto const key = hdr->get_key();
  zret.diag("Received an HTTP/1 request with key {}:\n{}", key, *hdr);
  return zret;
}

swoc::Rv<ssize_t>
Session::write(TextView view)
{
  swoc::Rv<ssize_t> zret{0};
  TextView remaining = view;
  while (!remaining.empty()) {
    if (this->is_closed()) {
      zret.diag("write failed: session is closed");
      break;
    }
    auto const n = ::write(_fd, remaining.data(), remaining.size());
    if (n > 0) {
      remaining = remaining.suffix(remaining.size() - n);
      zret.result() += n;
    } else if (n == 0) {
      zret.error("Write failed to write any bytes to the socket.");
      break;
    } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
      // Poll on the socket for writeability.
      auto &&[poll_return, poll_errata] = poll_for_data_on_socket(Poll_Timeout, POLLOUT);
      zret.note(std::move(poll_errata));
      if (poll_return > 0) {
        // The socket is available again for writing. Simply repeat the write.
        continue;
      } else if (!zret.is_ok()) {
        zret.error("Error polling on a socket to write: {}", swoc::bwf::Errno{});
        break;
      } else if (poll_return == 0) {
        zret.error("Timed out waiting to write to a socket.");
        break;
      } else if (poll_return < 0) {
        zret.diag("write failed during poll: session is closed");
        break;
      }
    } else {
      zret.error("Write failed: {}", swoc::bwf::Errno{});
      break;
    }
  }
  return zret;
}

swoc::Rv<ssize_t>
Session::write(HttpHeader const &hdr)
{
  // 1. header.serialize, write it out
  // 2. transmit the body
  swoc::LocalBufferWriter<MAX_HDR_SIZE> w;
  swoc::Rv<ssize_t> zret{-1};

  zret.errata() = hdr.serialize(w);

  if (!zret.is_ok()) {
    zret.error("Header serialization failed for key: {}", hdr.get_key());
    return zret;
  }

  auto &&[header_bytes_written, header_write_errata] = write(w.view());
  zret.note(std::move(header_write_errata));

  if (header_bytes_written == static_cast<ssize_t>(w.size())) {
    zret.result() = header_bytes_written;
    auto &&[body_bytes_written, body_write_errata] = write_body(hdr);
    zret.note(std::move(body_write_errata));
    zret.result() += body_bytes_written;
  } else {
    zret.error(
        R"(Header write for key {} failed with {} of {} bytes written: {}.)",
        hdr.get_key(),
        zret.result(),
        w.size(),
        swoc::bwf::Errno{});
  }
  return zret;
}

swoc::Rv<int>
Session::poll_for_data_on_socket(chrono::milliseconds timeout, short events)
{
  if (is_closed()) {
    return {-1, Errata().diag("Poll called on a closed connection.")};
  }
  struct pollfd pfd = {.fd = _fd, .events = events, .revents = 0};
  return ::poll(&pfd, 1, timeout.count());
}

swoc::Rv<int>
Session::poll_for_headers(chrono::milliseconds timeout)
{
  return poll_for_data_on_socket(timeout);
}

swoc::Rv<ssize_t>
Session::read_headers(swoc::FixedBufferWriter &w)
{
  swoc::Rv<ssize_t> zret{-1};
  while (w.remaining() > 0) {
    auto n = read(w.aux_span());
    if (!is_closed()) {
      // Where to start searching for the EOH string.
      size_t start = std::max<size_t>(w.size(), HTTP_EOH.size()) - HTTP_EOH.size();
      w.commit(n);
      size_t offset = w.view().substr(start).find(HTTP_EOH);
      if (TextView::npos != offset) {
        zret = start + offset + HTTP_EOH.size();
        break;
      }
    } else {
      if (w.size()) {
        zret.error(
            R"(Connection closed unexpectedly after {} bytes while waiting for header: {}.)",
            w.size(),
            swoc::bwf::Errno{});
      } else {
        zret = 0; // clean close between transactions.
      }
      break;
    }
  }
  if (zret.is_ok() && zret == -1) {
    zret.error(R"(Header exceeded maximum size {}.)", w.capacity());
  }
  return zret;
}

swoc::Rv<size_t>
Session::drain_body_internal(HttpHeader &rsp_hdr_from_wire, Txn const &json_txn, TextView initial)
{
  // The number of body bytes strictly considered. This does not include
  // any chunk headers, if present.
  swoc::Rv<size_t> num_drained_body_bytes = 0;
  rsp_hdr_from_wire.update_content_length(json_txn._req._method);
  rsp_hdr_from_wire.update_transfer_encoding();
  // The following helps set an expectation for chunked-encoded responses.
  size_t expected_content_size = json_txn._rsp._content_size;
  if (rsp_hdr_from_wire._content_length_p) {
    // The response specifies the content length. Use that specified length.
    expected_content_size = rsp_hdr_from_wire._content_size;
  }
  auto &&[bytes_drained, drain_errata] =
      this->drain_body(rsp_hdr_from_wire, expected_content_size, initial);
  num_drained_body_bytes = bytes_drained;
  num_drained_body_bytes.note(std::move(drain_errata));
  return num_drained_body_bytes;
}

swoc::Rv<size_t>
Session::drain_body(HttpHeader const &hdr, size_t expected_content_size, TextView bytes_read)
{
  // The number of content body bytes drained. initial contains the body bytes
  // already drained, so we initialize it to that size.
  TextView initial{bytes_read.substr(_body_offset)};
  swoc::Rv<size_t> num_drained_body_bytes = initial.size();
  // Check whether we got all the content already. Note that the expected size,
  // which is the expected body size, should not equal the received size if it
  // is chunked because chunked content will include extra chunk header
  // content. Thus if the expected and received sizes are equal and the body is
  // chunked, then the equality of size is a coincidence and a few more bytes
  // are needed.
  if (expected_content_size == num_drained_body_bytes && !hdr._chunked_p) {
    num_drained_body_bytes.diag(
        "Drained with headers body of {} bytes with content: {}",
        num_drained_body_bytes.result(),
        initial);
    return num_drained_body_bytes;
  }
  if (expected_content_size < initial.size()) {
    if (hdr._chunked_p) {
      // See the comment below for why chunked responses are special. Since we
      // don't know how much content will come in, arbitrarily initialize our
      // expectations to twice what we've received already for the body.
      expected_content_size = initial.size() * 2;
    } else {
      // We do not emit this error for chunked responses as a concession. If
      // the response has a Content-Length header, we already adjusted the
      // expected size of the body based upon the value of that header in the
      // response (see the calling function). If the response is chunked, there
      // is no such advertised value in the response headers to use. In this
      // case, expected_content_size is the content:size value in the dump. But
      // the proxy may use a slightly different body with a different size. For
      // this reason, we do not fail the transaction based upon such chunked
      // responses having a larger than recorded body size.
      num_drained_body_bytes.error(
          R"(Body overrun: received {} bytes of content, expected {}.)",
          initial.size(),
          expected_content_size);
      return num_drained_body_bytes;
    }
  }

  // If there's a status, and it indicates no body, we're done. This is true
  // regardless of the presence of a non-zero Content-Length header. Consider
  // a 304 response, for example: the Content-Length indicates the size of
  // the cached response, but the body is intentionally omitted.
  if (hdr._status && HttpHeader::STATUS_NO_CONTENT[hdr._status]) {
    return num_drained_body_bytes;
  }

  // Read the above conditionals: they should guaranteed that
  // expected_content_size > initial.size()
  assert(expected_content_size > num_drained_body_bytes);
  auto buff_storage_size = expected_content_size;
  if (expected_content_size > MAX_DRAIN_BUFFER_SIZE) {
    num_drained_body_bytes.diag(
        "Truncating the number of body bytes to store from {} to {}.",
        expected_content_size,
        MAX_DRAIN_BUFFER_SIZE);
    buff_storage_size = MAX_DRAIN_BUFFER_SIZE;
  }
  if (hdr._chunked_p) {
    // Allow a bit of extra room on top of the body size for chunk headers and trailers.
    buff_storage_size += 50;
  }
  std::string body{initial};
  body.reserve(buff_storage_size);

  if (is_closed()) {
    num_drained_body_bytes.error(
        R"(Stream closed before finishing reading the body. Read {} bytes of {} expected bytes)",
        num_drained_body_bytes.result(),
        expected_content_size);
    return num_drained_body_bytes;
  }

  if (hdr._chunked_p) {
    ChunkCodex::ChunkCallback cb{
        // TODO: Note that @a block is the set of body bytes in this chunk and
        // does not include chunk header content. It would be more accurate to
        // make @a body populated from @a block, and if we add body validation
        // we'll need to consider that. However we're using @a body as our read
        // buffer (thus it includes the entire body stream, including chunk
        // headers), and it would be expensive to have two buffers holding
        // copies of this same memory.
        [&num_drained_body_bytes](TextView block, size_t /* offset */, size_t /* size */) -> bool {
          num_drained_body_bytes.result() += block.size();
          return true;
        }};
    ChunkCodex codex;

    // num_drained_body_bytes was initialized to initial.size(), which was
    // sufficient and handy in the above code. However, for chunked content it
    // is slightly inaccurate because it includes chunk headers and EOL
    // trailers.  We reset it to zero here and count the body bytes accurately
    // via the chunk parsing callback.
    num_drained_body_bytes = 0;
    auto result = codex.parse(initial, cb);
    while (result == ChunkCodex::CONTINUE) {
      if (buff_storage_size <= body.size()) {
        // We've filled up our buffer. Try to expand it.
        if (buff_storage_size == MAX_DRAIN_BUFFER_SIZE) {
          // We do not want to expand it passed the MAX_DRAIN_BUFFER_SIZE. But
          // we have to read the rest of the body bytes from the socket. To do
          // this, we just start our buffer over from the beginning. We
          // currently don't validate body bytes anyway and just print the
          // buffer for debug purposes, so nothing critical depends upon an
          // accurate body content. We did the best we could. The
          // num_drained_body_bytes value will, however, be accurate.
          body.resize(0);
          num_drained_body_bytes.diag(
              "Drained {} bytes of a chunked body. "
              "Resetting storage since we hit capacity limit: {}.",
              num_drained_body_bytes.result(),
              buff_storage_size);
        } else {
          // Since it is chunked, there's no way for us to know how much is
          // coming in. We continue by using the doubling heuristic we
          // previously used to initialize the buffer.
          buff_storage_size = std::min<size_t>(buff_storage_size * 2, MAX_DRAIN_BUFFER_SIZE);
          body.reserve(buff_storage_size);
        }
      }
      auto const old_size = body.size();
      body.resize(buff_storage_size);
      ssize_t const n = read({body.data() + old_size, buff_storage_size - old_size});
      if (n > 0) {
        body.resize(old_size + n);
        result = codex.parse(TextView(body.data() + old_size, n), cb);
      } else {
        body.resize(old_size);
      }
      if (is_closed()) {
        if (num_drained_body_bytes < expected_content_size) {
          num_drained_body_bytes.error(
              R"(Body underrun: received {} bytes of content, expected {}, when file closed because {}.)",
              num_drained_body_bytes.result(),
              expected_content_size,
              swoc::bwf::Errno{});
        }
        break;
      }
    }
    // We finished draining. Make sure we got to the DONE chunk.
    if (result != ChunkCodex::DONE && num_drained_body_bytes != expected_content_size) {
      num_drained_body_bytes.error(
          R"(Unexpected chunked content: expected {} bytes, drained {} bytes.)",
          expected_content_size,
          num_drained_body_bytes.result());
    }
    // As described above in the chunk callback comment, this will print the
    // entire chunk stream, including chunk headers.
    num_drained_body_bytes.diag(
        "Drained {} chunked body bytes with chunk stream: {}",
        num_drained_body_bytes.result(),
        body);
  } else { // Content-Length instead of chunked.
    while (num_drained_body_bytes < expected_content_size) {
      if (buff_storage_size <= body.size()) {
        // See the comment above in the corresponding chunk code for an
        // explanation of the logic here.
        body.resize(0);
        num_drained_body_bytes.diag(
            "Drained {} of {} expected bytes. Not storing any more since we hit buffer capacity: "
            "{}.",
            num_drained_body_bytes.result(),
            expected_content_size,
            buff_storage_size);
      }
      auto const old_size = body.size();
      body.resize(buff_storage_size);
      ssize_t const n = read({body.data() + old_size, buff_storage_size - old_size});
      if (n > 0) {
        body.resize(old_size + n);
        num_drained_body_bytes.result() += n;
      } else {
        body.resize(old_size);
      }
      if (is_closed()) {
        num_drained_body_bytes.error(
            R"(Body underrun: received {} bytes of content, expected {}, when file closed because {}.)",
            num_drained_body_bytes.result(),
            expected_content_size,
            swoc::bwf::Errno{});
        break;
      }
    }
    if (num_drained_body_bytes > expected_content_size) {
      num_drained_body_bytes.error(
          R"(Body overrun while reading it: received {} bytes of content, expected {}.)",
          num_drained_body_bytes.result(),
          expected_content_size);
    }
    num_drained_body_bytes.diag("Drained body of {} bytes with content: {}", body.size(), body);
  }
  return num_drained_body_bytes;
}

swoc::Rv<ssize_t>
Session::write_body(HttpHeader const &hdr)
{
  swoc::Rv<ssize_t> bytes_written{0};
  std::error_code ec;
  auto const key = hdr.get_key();

  bytes_written.diag(
      "Transmit {} byte body {}{} for key {}.",
      hdr._content_size,
      swoc::bwf::If(hdr._content_length_p, "[CL]"),
      swoc::bwf::If(hdr._chunked_p, "[chunked]"),
      key);

  /* Observe that by this point, hdr._content_size will have been adjusted to 0
   * for HEAD requests via update_content_length. */
  auto const message_type_permits_body =
      (hdr.is_request() || (hdr._status && !HttpHeader::STATUS_NO_CONTENT[hdr._status]));
  // Note that zero-length chunked bodies must send a zero-length encoded chunk.
  if (message_type_permits_body && (hdr._content_size > 0 || hdr._chunked_p)) {
    TextView content;
    if (hdr._content_data) {
      content = TextView{hdr._content_data, hdr._content_size};
    } else {
      // If hdr._content_data is null, then there was no explicit description
      // of the body data via the data node. Instead we'll use our generated
      // HttpHeader::_content.
      content = TextView{HttpHeader::_content.data(), hdr._content_size};
    }

    if (hdr._chunked_p) {
      ChunkCodex codex;
      std::tie(bytes_written, ec) = codex.transmit(*this, content);
    } else {
      auto &&[n, write_errata] = write(content);
      bytes_written.note(write_errata);
      bytes_written.result() += n;
      ec = std::error_code(errno, std::system_category());

      if (!hdr._content_length_p && !hdr._has_transfer_encoding_chunked) {
        // Since there is no content-length, close the connection to signal the
        // end of body.
        bytes_written.diag(
            "No content length, status {}. Closing the connection for key {}.",
            hdr._status,
            key);
        close();
      }
    }

    if (bytes_written != static_cast<ssize_t>(hdr._content_size) &&
        bytes_written != static_cast<ssize_t>(hdr._recorded_content_size))
    {
      bytes_written.error(
          R"(Body write{} failed for key {} with {} of {} bytes written: {}.)",
          swoc::bwf::If(hdr._chunked_p, " [chunked]"),
          key,
          bytes_written.result(),
          hdr._content_size,
          ec);
    }
  } else if (
      hdr._status && !HttpHeader::STATUS_NO_CONTENT[hdr._status] && !hdr._chunked_p &&
      !hdr._content_length_p)
  {
    // Note the conditions:
    //
    //   1. This is a response since there is a hdr._status. Only responses
    //   have a status.
    //
    //   2. There's no body since hdr._content_size must be zero in this code
    //   block (see the if condition matching this else).
    //
    //   3. The response headers give no indication that there is no more body
    //   forthcoming since there is neither a zero-value Content-Length header
    //   nor a Transfer-Encoding header which would have a zero-length chunk.
    //
    // This being the case, we must close this connection lest the client
    // timeout waiting for a body it will never receive. Unfortunately, this
    // will result in the client needing to reconnect more frequently than it
    // would otherwise need to, but we have logic for handling this in
    // run_transaction.
    bytes_written.diag("No CL or TE, status {}: closing conection for key {}.", hdr._status, key);
    close();
  }

  return bytes_written;
}

Errata
Session::run_transaction(Txn const &json_txn)
{
  Errata errata;
  auto &&[bytes_written, write_errata] = this->write(json_txn._req);
  errata.note(std::move(write_errata));
  errata.diag("Sent the following HTTP/1 {} request:\n{}", json_txn._req._method, json_txn._req);

  if (errata.is_ok()) {
    auto const key{json_txn._req.get_key()};
    HttpHeader rsp_hdr_from_wire;
    rsp_hdr_from_wire.set_is_response();
    // The response headers are not required to have the key. For logging
    // purposes, explicitly make sure it is set with the expected value we have
    // from the client-request.
    rsp_hdr_from_wire.set_key(key);
    swoc::LocalBufferWriter<MAX_HDR_SIZE> w;
    errata.diag("Reading response header.");

    auto read_result{this->read_headers(w)};
    errata.note(read_result);

    if (read_result.is_ok()) {
      _body_offset = read_result;
      auto result{rsp_hdr_from_wire.parse_response(TextView(w.data(), _body_offset))};
      errata.note(result);

      if (result.is_ok()) {
        if (result != HttpHeader::PARSE_OK) {
          // We don't expect this since read_headers loops on reading until we
          // get HTTP_EOH.
          errata.error(
              R"(Failed to find a well-formed, completed HTTP response: {})",
              (result == HttpHeader::PARSE_INCOMPLETE ? "PARSE_INCOMPLETE" : "PARSE_ERROR"));
          return errata;
        }
        if (rsp_hdr_from_wire._status == 100) {
          errata.diag("100-Continue response. Read another header.");
          rsp_hdr_from_wire = HttpHeader{};
          w.clear();
          auto read_result{this->read_headers(w)};

          if (read_result.is_ok()) {
            _body_offset = read_result;
            auto result{rsp_hdr_from_wire.parse_response(TextView(w.data(), _body_offset))};

            if (!result.is_ok()) {
              errata.error(R"(Failed to parse post 100 header.)");
              return errata;
            }
          } else {
            errata.error(R"(Failed to read post 100 header.)");
            return errata;
          }
        }
        errata.diag(
            "Received an HTTP/1 {} response for key {} with headers:\n{}",
            rsp_hdr_from_wire._status,
            key,
            rsp_hdr_from_wire);
        if (json_txn._rsp._status != 0 && rsp_hdr_from_wire._status != json_txn._rsp._status &&
            (rsp_hdr_from_wire._status != 200 || json_txn._rsp._status != 304) &&
            (rsp_hdr_from_wire._status != 304 || json_txn._rsp._status != 200))
        {
          errata.error(
              R"(HTTP/1 Status Violation: expected {} got {}, key={}.)",
              json_txn._rsp._status,
              rsp_hdr_from_wire._status,
              key);
          // Drain the rest of the body so it's not in the buffer to confuse the
          // next transaction.
          auto &&[bytes_drained, drain_errata] =
              this->drain_body_internal(rsp_hdr_from_wire, json_txn, w.view());
          errata.note(std::move(drain_errata));

          return errata;
        }
        if (rsp_hdr_from_wire.verify_headers(key, *json_txn._rsp._fields_rules)) {
          errata.error(R"(Response headers did not match expected response headers.)");
        }
        auto &&[bytes_drained, drain_errata] =
            this->drain_body_internal(rsp_hdr_from_wire, json_txn, w.view());
        errata.note(std::move(drain_errata));

        if (!errata.is_ok()) {
          errata.error("Failed to replay transaction with key: {}", key);
        }
      } else {
        errata.error(R"(Invalid response. key={})", key);
      }
    } else {
      errata.error(R"(Invalid response read key={}.)", key);
    }
  }
  return errata;
}

Errata
Session::run_transactions(
    std::list<Txn> const &txn_list,
    swoc::TextView interface,
    swoc::IPEndpoint const *real_target,
    double rate_multiplier)
{
  Errata session_errata;

  auto const first_time = ClockType::now();
  for (auto const &txn : txn_list) {
    Errata txn_errata;
    if (this->is_closed()) {
      // verifier-server closes connections if the body is unspecified in size.
      // Otherwise proxies generally will timeout. To accomodate this, we
      // simply reconnect if the connection was closed.
      txn_errata.note(this->do_connect(interface, real_target));
      if (!txn_errata.is_ok()) {
        txn_errata.error(R"(Failed to reconnect HTTP/1 key={}.)", txn._req.get_key());
        session_errata.note(std::move(txn_errata));
        // If we don't have a valid connection, there's no point in continuing.
        break;
      }
    }
    if (txn._user_specified_delay_duration > 0us) {
      sleep_for(txn._user_specified_delay_duration);
    } else if (rate_multiplier != 0) {
      auto const start_offset = txn._start;
      auto const next_time = (rate_multiplier * start_offset) + first_time;
      auto current_time = ClockType::now();
      if (next_time > current_time) {
        sleep_until(next_time);
      }
    }
    auto const before = ClockType::now();
    txn_errata.note(this->run_transaction(txn));
    auto const after = ClockType::now();
    if (!txn_errata.is_ok()) {
      txn_errata.error(R"(Failed HTTP/1 transaction with key={}.)", txn._req.get_key());
    }

    auto const elapsed_ms = duration_cast<chrono::milliseconds>(after - before);
    if (elapsed_ms > Transaction_Delay_Cutoff) {
      txn_errata.error(R"(HTTP/1 transaction for key={} took {}.)", txn._req.get_key(), elapsed_ms);
    }
    session_errata.note(std::move(txn_errata));
  }
  return session_errata;
}

Errata
Session::set_fd(int fd)
{
  Errata errata;
  _fd = fd;
  return errata;
}

InterfaceNameToEndpoint::InterfaceNameToEndpoint(TextView expected_interface, int expected_family)
  : _expected_interface{expected_interface}
  , _expected_family{expected_family}
{
}

InterfaceNameToEndpoint::~InterfaceNameToEndpoint()
{
  if (_ifaddr_list_head != nullptr) {
    freeifaddrs(_ifaddr_list_head);
    _ifaddr_list_head = nullptr;
  }
}

swoc::Rv<struct ifaddrs *>
InterfaceNameToEndpoint::find_matching_interface()
{
  swoc::Rv<struct ifaddrs *> zret{nullptr};
  if (_ifaddr_list_head == nullptr) {
    if (getifaddrs(&_ifaddr_list_head) == -1) {
      zret.error("getifaddrs failed: {}", swoc::bwf::Errno{});
      return zret;
    }
  }
  for (auto *ifa = _ifaddr_list_head; ifa != nullptr; ifa = ifa->ifa_next) {
    std::string_view interface_name{ifa->ifa_name};
    if (interface_name != _expected_interface) {
      continue;
    }
    auto const family = ifa->ifa_addr->sa_family;
    if (family != _expected_family) {
      continue;
    }
    zret = ifa;
    return zret;
  }
  return nullptr;
}

swoc::Rv<swoc::IPEndpoint>
InterfaceNameToEndpoint::find_ip_endpoint()
{
  swoc::Rv<swoc::IPEndpoint> zret{};

  // Check whether we've already found this endpoint.
  auto interface_it = memoized_ip_endpoints.find(_expected_interface);
  if (interface_it != memoized_ip_endpoints.end()) {
    auto const &family_map = interface_it->second;
    auto family_it = family_map.find(_expected_family);
    if (family_it != family_map.end()) {
      auto const &ip_endpoint = family_it->second;
      zret.result() = ip_endpoint;
      zret.diag(
          "Using memoized interface from name {} with family {} and ip {}",
          _expected_interface,
          swoc::IPEndpoint::family_name(ip_endpoint.family()),
          ip_endpoint);
      return zret;
    }
  }

  if (getifaddrs(&_ifaddr_list_head) == -1) {
    zret.error("getifaddrs failed: {}", swoc::bwf::Errno{});
    return zret;
  }
  auto &&[matching_interface, find_errata] = find_matching_interface();
  zret.note(std::move(find_errata));
  if (!zret.is_ok()) {
    return zret;
  }
  if (matching_interface == nullptr) {
    zret.error(
        "Could not find an interface named {} with family {}.",
        _expected_interface,
        swoc::IPEndpoint::family_name(_expected_family));
    return zret;
  }
  auto &ip_endpoint = zret.result();
  ip_endpoint.assign(matching_interface->ifa_addr);

  if (!ip_endpoint.is_valid()) {
    zret.error("Could not form a valid IP from the specified interface {}", _expected_interface);
    return zret;
  }

  memoized_ip_endpoints[_expected_interface][_expected_family] = ip_endpoint;
  zret.diag(
      "Found interface from name {} with family {} and ip {}",
      _expected_interface,
      swoc::IPEndpoint::family_name(ip_endpoint.family()),
      ip_endpoint);
  return zret;
}

Errata
Session::do_connect(TextView interface, swoc::IPEndpoint const *real_target)
{
  Errata errata;
  int socket_fd = socket(real_target->family(), SOCK_STREAM, 0);
  if (0 <= socket_fd) {
    int ONE = 1;
    struct linger l;
    l.l_onoff = 0;
    l.l_linger = 0;
    setsockopt(socket_fd, SOL_SOCKET, SO_LINGER, (char *)&l, sizeof(l));
    if (!interface.empty()) {
      InterfaceNameToEndpoint interface_to_endpoint{interface, real_target->family()};
      auto &&[device_endpoint, device_errata] = interface_to_endpoint.find_ip_endpoint();
      errata.note(std::move(device_errata));
      if (!errata.is_ok()) {
        return errata;
      }
      if (::bind(socket_fd, &device_endpoint.sa, device_endpoint.size()) == -1) {
        errata.error("Failed to bind on interface {}: {}", interface, swoc::bwf::Errno{});
        return errata;
      }
    }
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &ONE, sizeof(int)) < 0) {
      errata.error(R"(Could not set reuseaddr on socket {} - {}.)", socket_fd, swoc::bwf::Errno{});
    } else {
      errata.note(this->set_fd(socket_fd));
      if (errata.is_ok()) {
        if (0 == ::connect(socket_fd, &real_target->sa, real_target->size())) {
          static const int ONE = 1;
          setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, &ONE, sizeof(ONE));
          if (0 == ::fcntl(socket_fd, F_SETFL, fcntl(socket_fd, F_GETFL, 0) | O_NONBLOCK)) {
            errata.note(this->connect());
          } else {
            errata.error(
                R"(Failed to make the client socket non-blocking {}: - {})",
                *real_target,
                swoc::bwf::Errno{});
          }
        } else {
          errata.error(R"(Failed to connect socket {}: - {})", *real_target, swoc::bwf::Errno{});
        }
      } else {
        errata.error(R"(Failed to open session - {})", swoc::bwf::Errno{});
      }
    }
  } else {
    errata.error(R"(Failed to open socket - {})", swoc::bwf::Errno{});
  }
  return errata;
}

Errata
Session::connect()
{
  Errata errata;
  return errata;
}

void
Session::close()
{
  if (!this->is_closed()) {
    ::close(_fd);
    _fd = -1;
  }
}

Errata
Session::init(int num_transactions)
{
  Errata errata;
  struct rlimit lim;
  if (getrlimit(RLIMIT_NOFILE, &lim) == 0) {
    auto const previous_limit = lim.rlim_cur;
    if (MAX_NOFILE > static_cast<int>(previous_limit)) {
      lim.rlim_cur = (lim.rlim_max = (rlim_t)MAX_NOFILE);
      if (setrlimit(RLIMIT_NOFILE, &lim) == 0 && getrlimit(RLIMIT_NOFILE, &lim) == 0) {
        errata.diag("Updated RLIMIT_NOFILE to {} from {}", MAX_NOFILE, previous_limit);

        // We could not set the rlimit. This will not be a problem if the user is
        // not testing under load. For instance, if this is run for a correctness
        // test with 10 transactions, not being able to raise the limit of the
        // number of files isn't a problem. The 300 is an arbitrary check on
        // whether the message should raise an error or just emit an info
        // message.
      } else if (num_transactions > 300) {
        errata.error(
            "Could not setrlimit to {} from {}, errno={}",
            MAX_NOFILE,
            previous_limit,
            errno);
      } else {
        errata
            .info("Could not setrlimit to {} from {}, errno={}", MAX_NOFILE, previous_limit, errno);
      }
    }
  }
  return errata;
}

ChunkCodex::Result
ChunkCodex::parse(swoc::TextView data, ChunkCallback const &cb)
{
  while (data) {
    switch (_state) {
    case State::INIT:
      _state = State::SIZE;
      break;
    case State::SIZE:
      while (data && isxdigit(*data)) {
        _size_text.write(*data++);
      }
      if (data) {
        _size = swoc::svtou(_size_text.view(), nullptr, 16);
        _size_text.clear();
        _state = State::CR;
      }
      break;
    case State::POST_BODY_CR:
      if (*data == '\r') {
        _state = State::POST_BODY_LF;
      }
      ++data;
      break;
    case State::CR:
      if (*data == '\r') {
        _state = State::LF;
      }
      ++data;
      break;
    case State::POST_BODY_LF:
      if (*data == '\n') {
        if (_size == 0) {
          // This is the end of a zero-sized chunk: the end of all chunk
          // content.
          _state = State::FINAL;
          ++data;
          _off = 0;
          return DONE;
        } else {
          _state = State::SIZE;
          ++data;
          _off = 0;
        }
      } else {
        _state = State::FINAL;
        return DONE;
      }
      break;
    case State::LF:
      if (*data == '\n') {
        if (_size) {
          _state = State::BODY;
          ++data;
          _off = 0;
        } else {
          _state = State::POST_BODY_CR;
        }
      }
      break;
    case State::BODY: {
      size_t n = std::min(data.size(), _size - _off);
      cb({data.data(), n}, _off, _size);
      data.remove_prefix(n);
      if ((_off += n) >= _size) {
        _state = State::POST_BODY_CR;
      }
    } break;
    case State::FINAL:
      return DONE;
    }
  }
  return CONTINUE;
}

std::tuple<ssize_t, std::error_code>
ChunkCodex::transmit(Session &session, swoc::TextView data, size_t chunk_size)
{
  static const std::error_code NO_ERROR;
  static constexpr swoc::TextView ZERO_CHUNK{"0\r\n\r\n"};

  swoc::LocalBufferWriter<10> w; // 8 bytes of size (32 bits) CR LF
  ssize_t n = 0;
  ssize_t total = 0;
  while (data) {
    if (data.size() < chunk_size) {
      chunk_size = data.size();
    }
    w.clear().print("{:x}{}", chunk_size, HTTP_EOL);
    n = session.write(w.view());
    if (n > 0) {
      n = session.write({data.data(), chunk_size});
      if (n > 0) {
        total += n;
        if (n == static_cast<ssize_t>(chunk_size)) {
          w.clear().print("{}",
                          HTTP_EOL); // Each chunk much terminate with CRLF
          session.write(w.view());
          data.remove_prefix(chunk_size);
        } else {
          return {total, std::error_code(errno, std::system_category())};
        }
      }
    } else {
      return {total, std::error_code(errno, std::system_category())};
    }
  }
  n = session.write(ZERO_CHUNK);
  if (n != static_cast<ssize_t>(ZERO_CHUNK.size())) {
    return {total, std::error_code(errno, std::system_category())};
  }
  return {total, NO_ERROR};
};
