/** @file
 * Common implementation for Proxy Verifier
 *
 * Copyright 2020, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "core/ProxyVerifier.h"
#include "core/yaml_util.h"

#include <algorithm>
#include <cassert>
#include <csignal>
#include <dirent.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "swoc/bwf_ex.h"
#include "swoc/bwf_ip.h"
#include "swoc/bwf_std.h"
#include "swoc/bwf_std.h"

using swoc::Errata;
using swoc::TextView;
using namespace swoc::literals;
using namespace std::literals;
using std::this_thread::sleep_until;
using std::this_thread::sleep_for;

namespace chrono = std::chrono;
using clock_type = std::chrono::system_clock;
using chrono::duration_cast;
using chrono::milliseconds;

constexpr auto Transaction_Delay_Cutoff = 10s;
constexpr auto Poll_Timeout = 5s;

bool Verbose = false;

using MSG_BUFF = swoc::LocalBufferWriter<1024>;

bool HttpHeader::_frozen = false;
swoc::MemArena HttpHeader::_arena{8000};
HttpHeader::NameSet HttpHeader::_names;
std::string HttpHeader::_key_format{"{field.uuid}"};
swoc::MemSpan<char> HttpHeader::_content;
swoc::TextView HttpHeader::FIELD_CONTENT_LENGTH;
swoc::TextView HttpHeader::FIELD_TRANSFER_ENCODING;
swoc::TextView HttpHeader::FIELD_HOST;
std::bitset<600> HttpHeader::STATUS_NO_CONTENT;

RuleCheck::RuleOptions RuleCheck::options;
RuleCheck::URLRuleOptions RuleCheck::url_rule_options;
RuleCheck::DuplicateFieldRuleOptions RuleCheck::duplicate_field_options;
std::unordered_map<std::string, TLSHandshakeBehavior> TLSSession::_handshake_behavior_per_sni;

static ssize_t send_nghttp2_data(
    nghttp2_session *session,
    uint8_t const *inputdata,
    size_t length,
    int flags,
    void *user_data);

static ssize_t receive_nghttp2_data(
    nghttp2_session *session,
    uint8_t *buf,
    size_t length,
    int flags,
    void *user_data,
    milliseconds timeout);

static ssize_t receive_nghttp2_responses(
    nghttp2_session *session,
    uint8_t *buf,
    size_t length,
    int flags,
    void *user_data);

static ssize_t receive_nghttp2_request(
    nghttp2_session *session,
    uint8_t *buf,
    size_t length,
    int flags,
    void *user_data,
    milliseconds timeout);

namespace
{
[[maybe_unused]] bool INITIALIZED = []() -> bool {
  HttpHeader::global_init();
  return true;
}();
}

swoc::Rv<int>
block_sigpipe()
{
  swoc::Rv<int> zret = 0;
  sigset_t set;
  if (sigemptyset(&set)) {
    zret = -1;
    zret.error(R"(Could not empty the signal set: {})", swoc::bwf::Errno{});
  } else if (sigaddset(&set, SIGPIPE)) {
    zret = -1;
    zret.error(R"(Could not add SIGPIPE to the signal set: {})", swoc::bwf::Errno{});
  } else if (pthread_sigmask(SIG_BLOCK, &set, nullptr)) {
    zret = -1;
    zret.error(R"(Could not block SIGPIPE: {})", swoc::bwf::Errno{});
  }
  return zret;
}

swoc::Errata
configure_logging(const std::string_view verbose_argument)
{
  swoc::Errata errata;
  auto severity_cutoff = swoc::Severity::INFO;
  if (strcasecmp(verbose_argument, "error") == 0) {
    severity_cutoff = swoc::Severity::ERROR;
  } else if (strcasecmp(verbose_argument, "warn") == 0) {
    severity_cutoff = swoc::Severity::WARN;
  } else if (strcasecmp(verbose_argument, "info") == 0) {
    severity_cutoff = swoc::Severity::INFO;
  } else if (strcasecmp(verbose_argument, "diag") == 0) {
    severity_cutoff = swoc::Severity::DIAG;
  } else {
    errata.error("Unrecognized verbosity parameter: {}", verbose_argument);
    return errata;
  }
  errata.diag("Configuring logging at level {}", severity_cutoff);

  static std::mutex logging_mutex;

  swoc::Errata::register_sink([severity_cutoff](Errata const &errata) {
    if (errata.severity() < severity_cutoff) {
      return;
    }
    std::string_view lead;
    for (auto const &annotation : errata) {
      if (annotation.severity() < severity_cutoff) {
        continue;
      }
      {
        std::lock_guard<std::mutex> lock(logging_mutex);
        std::cout << lead << " [" << static_cast<int>(annotation.severity())
                  << "]: " << annotation.text() << std::endl;
      }
      if (lead.size() == 0) {
        lead = "  "_sv;
      }
    }
  });
  return errata;
}

std::string
get_printable_alpn_string(std::string_view alpn_wire_string)
{
  char const *const last_char = &alpn_wire_string.back();
  std::string printable_alpn;
  printable_alpn.reserve(alpn_wire_string.size());
  unsigned short proto_size = 0;
  for (char const *p = &alpn_wire_string.front(); p <= last_char; ++p) {
    if (proto_size == 0) {
      proto_size = (unsigned short)*p;
    } else {
      printable_alpn.append(1, *p);
      --proto_size;
      if (proto_size == 0 && p != last_char) {
        printable_alpn.append(1, ',');
      }
    }
  }
  return printable_alpn;
}

swoc::Rv<YAML::Node const>
ReplayFileHandler::parse_for_protocol_node(
    YAML::Node const &protocol_node,
    std::string_view protocol_name)
{
  swoc::Rv<YAML::Node const> desired_node = YAML::Node{YAML::NodeType::Undefined};
  if (!protocol_node.IsSequence()) {
    desired_node.error("Protocol node at {} is not a sequence as required.", protocol_node.Mark());
    return desired_node;
  }
  if (protocol_node.size() == 0) {
    desired_node.error("Protocol node at {} is an empty sequence.", protocol_node.Mark());
    return desired_node;
  }
  for (auto const &protocol_element : protocol_node) {
    if (!protocol_element.IsMap()) {
      desired_node.error("Protocol element at {} is not a map.", protocol_element.Mark());
      return desired_node;
    }
    if (protocol_element[YAML_SSN_PROTOCOL_NAME].Scalar() != protocol_name) {
      continue;
    }
    return swoc::Rv<YAML::Node const>{protocol_element};
  }
  return desired_node;
}

swoc::Rv<std::string>
ReplayFileHandler::parse_sni(YAML::Node const &tls_node)
{
  swoc::Rv<std::string> sni;
  if (auto sni_node{tls_node[YAML_SSN_TLS_SNI_KEY]}; sni_node) {
    if (sni_node.IsScalar()) {
      sni.result() = sni_node.Scalar();
    } else {
      sni.error(
          R"(Session has a value for key "{}" that is not a scalar as required.)",
          YAML_SSN_TLS_SNI_KEY);
    }
  }
  return sni;
}

swoc::Rv<int>
ReplayFileHandler::parse_verify_mode(YAML::Node const &tls_node)
{
  swoc::Rv<int> verify_mode{-1};
  if (auto tls_verify_mode{tls_node[YAML_SSN_TLS_VERIFY_MODE_KEY]}; tls_verify_mode) {
    if (tls_verify_mode.IsScalar()) {
      verify_mode = std::stoi(tls_verify_mode.Scalar());
    } else {
      verify_mode.error(
          R"(Session has a value for key "{}" that is not a scalar as required.)",
          YAML_SSN_TLS_SNI_KEY);
    }
  }
  return verify_mode;
}

swoc::Rv<std::string>
ReplayFileHandler::parse_alpn_protocols_node(YAML::Node const &tls_node)
{
  swoc::Rv<std::string> alpn_protocol_string;
  if (auto alpn_protocols_node{tls_node[YAML_SSN_TLS_ALPN_PROTOCOLS_KEY]}; alpn_protocols_node) {
    if (!alpn_protocols_node.IsSequence()) {
      alpn_protocol_string.error(
          R"(Session has a value for key "{}" that is not a sequence as required.)",
          YAML_SSN_TLS_ALPN_PROTOCOLS_KEY);
      return alpn_protocol_string;
    }
    for (auto const &protocol : alpn_protocols_node) {
      std::string_view protocol_view{protocol.Scalar()};
      alpn_protocol_string.result().append(1, (char)protocol_view.size());
      alpn_protocol_string.result().append(protocol_view);
    }
  }
  return alpn_protocol_string;
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
  hdr->_is_http2 = false;
  auto received_data = swoc::TextView(buffer.data(), _body_offset);
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

void
TLSHandshakeBehavior::set_verify_mode(int verify_mode)
{
  _verify_mode = verify_mode;
}

int
TLSHandshakeBehavior::get_verify_mode() const
{
  return _verify_mode;
}

void
TLSHandshakeBehavior::set_alpn_protocols_string(std::string_view alpn_protocols)
{
  _alpn_wire_string = alpn_protocols;
}

std::string_view
TLSHandshakeBehavior::get_alpn_wire_string() const
{
  return _alpn_wire_string;
}

TLSSession::TLSSession(swoc::TextView const &client_sni, int client_verify_mode)
  : _client_sni{client_sni}
  , _client_verify_mode{client_verify_mode}
{
}

TLSSession::~TLSSession()
{
  if (_ssl != nullptr) {
    SSL_free(_ssl);
    _ssl = nullptr;
  }
}

swoc::Rv<ssize_t>
TLSSession::read(swoc::MemSpan<char> span)
{
  if (this->is_closed()) {
    return swoc::Rv<ssize_t>{0};
  }
  swoc::Rv<ssize_t> zret{SSL_read(this->_ssl, span.data(), span.size())};

  if (zret <= 0) {
    auto const ssl_error = SSL_get_error(get_ssl(), zret);
    auto &&[poll_return, poll_errata] = poll_for_data_on_ssl_socket(Poll_Timeout, ssl_error);
    zret.note(std::move(poll_errata));
    if (poll_return > 0) {
      // Simply repeat the read now that poll says something is ready.
      return read(span);
    } else if (!zret.is_ok()) {
      zret.error(R"(Failed SSL_read poll for TLS content: {}.)", swoc::bwf::Errno{});
      this->close();
    } else if (poll_return == 0) {
      zret.error("SSL_read timed out waiting to TLS content after {} milliseconds.", Poll_Timeout);
      this->close();
    } else if (poll_return < 0) {
      this->close();
    }
  }
  return zret;
}

swoc::Rv<ssize_t>
Session::write(swoc::TextView view)
{
  swoc::Rv<ssize_t> zret{0};
  swoc::TextView remaining = view;
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
Session::drain_body_internal(
    HttpHeader &rsp_hdr_from_wire,
    Txn const &json_txn,
    swoc::TextView initial)
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
Session::drain_body(HttpHeader const &hdr, size_t expected_content_size, swoc::TextView bytes_read)
{
  // The number of content body bytes drained. initial contains the body bytes
  // already drained, so we initialize it to that size.
  swoc::TextView initial{bytes_read.substr(_body_offset)};
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
      (hdr._is_request || (hdr._status && !HttpHeader::STATUS_NO_CONTENT[hdr._status]));
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

      if (!hdr._content_length_p) { // no content-length, must close to signal
                                    // end of body
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

swoc::Errata
Session::run_transaction(Txn const &json_txn)
{
  swoc::Errata errata;
  auto &&[bytes_written, write_errata] = this->write(json_txn._req);
  errata.note(std::move(write_errata));
  errata.diag("Sent the following HTTP/1 {} request:\n{}", json_txn._req._method, json_txn._req);

  if (errata.is_ok()) {
    auto const key{json_txn._req.get_key()};
    HttpHeader rsp_hdr_from_wire;
    rsp_hdr_from_wire._is_response = true;
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

swoc::Errata
Session::run_transactions(
    std::list<Txn> const &txn_list,
    swoc::IPEndpoint const *real_target,
    double rate_multiplier)
{
  swoc::Errata session_errata;

  auto const first_time = clock_type::now();
  for (auto const &txn : txn_list) {
    swoc::Errata txn_errata;
    if (this->is_closed()) {
      // verifier-server closes connections if the body is unspecified in size.
      // Otherwise proxies generally will timeout. To accomodate this, we
      // simply reconnect if the connection was closed.
      txn_errata.note(this->do_connect(real_target));
      if (!txn_errata.is_ok()) {
        txn_errata.error(R"(Failed to reconnect HTTP/1 key={}.)", txn._req.get_key());
        session_errata.note(std::move(txn_errata));
        // If we don't have a valid connection, there's no point in continuing.
        break;
      }
    }
    if (rate_multiplier != 0) {
      auto const start_offset = txn._start;
      auto const next_time = (rate_multiplier * start_offset) + first_time;
      auto current_time = clock_type::now();
      if (next_time > current_time) {
        sleep_until(next_time);
      }
    }
    auto const before = clock_type::now();
    txn_errata.note(this->run_transaction(txn));
    auto const after = clock_type::now();
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

swoc::Rv<ssize_t>
TLSSession::write(swoc::TextView view)
{
  swoc::TextView remaining = view;
  swoc::Rv<ssize_t> num_written = 0;
  static int write_count = 0;
  ++write_count;
  while (!remaining.empty()) {
    if (this->is_closed()) {
      num_written.diag("SSL_write failed: session is closed");
      return num_written;
    }
    auto const n = SSL_write(this->_ssl, remaining.data(), remaining.size());
    if (n > 0) {
      remaining = remaining.suffix(remaining.size() - n);
      num_written.result() += n;
      continue;
    } else if (n <= 0) {
      auto const ssl_error = SSL_get_error(this->_ssl, n);
      auto &&[poll_return, poll_errata] = poll_for_data_on_ssl_socket(Poll_Timeout, ssl_error);
      num_written.note(std::move(poll_errata));
      if (poll_return > 0) {
        // Poll succeeded. Repeat the attempt to write.
        continue;
      } else if (!num_written.is_ok()) {
        num_written.error(R"(Failed SSL_write: {}.)", swoc::bwf::Errno{});
        return num_written;
      } else if (poll_return == 0) {
        num_written.error("Timed out waiting to SSL_write after: {}.", Poll_Timeout);
        return num_written;
      } else if (poll_return < 0) {
        // Connection closed.
        num_written.diag("SSL_write failed during poll: session is closed");
        return num_written;
      }
    }
  }
  return num_written;
}

swoc::Rv<int>
TLSSession::poll_for_data_on_ssl_socket(chrono::milliseconds timeout, int ssl_error)
{
  swoc::Rv<int> zret{-1};
  if (is_closed()) {
    zret.diag("Poll called on a closed connection.");
    return zret;
  }
  if (ssl_error == SSL_ERROR_ZERO_RETURN || ssl_error == SSL_ERROR_SYSCALL) {
    // Either of these indicates that the peer has closed the connection for
    // writing and no more data can be read.
    zret.diag("Poll called on a TLS session closed by the peer.");
    this->close();
    return zret;
  }

  if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE) {
    zret.error(
        R"(SSL operation failed: {}, errno: {})",
        swoc::bwf::SSLError{ssl_error},
        swoc::bwf::Errno{});
    return zret;
  }
  short events = 0;
  if (ssl_error == SSL_ERROR_WANT_READ) {
    events = POLLIN;
  } else if (ssl_error == SSL_ERROR_WANT_WRITE) {
    events = POLLOUT;
  }
  return poll_for_data_on_socket(timeout, events);
}

swoc::Errata
Session::set_fd(int fd)
{
  swoc::Errata errata;
  _fd = fd;
  return errata;
}

// Complete the TLS handshake (server-side).
swoc::Errata
TLSSession::accept()
{
  swoc::Errata errata;
  _ssl = SSL_new(server_context);
  if (_ssl == nullptr) {
    errata.error(
        R"(Failed to create SSL server object fd={} server_context={} err={}.)",
        get_fd(),
        server_context,
        swoc::bwf::SSLError{});
    return errata;
  }
  if (SSL_set_fd(_ssl, get_fd()) == 0) {
    errata.error(R"(Failed SSL_set_fd: {}.)", swoc::bwf::SSLError{});
    return errata;
  }
  int retval = SSL_accept(_ssl);
  while (retval < 0) {
    auto const ssl_error = SSL_get_error(_ssl, retval);
    // Since there are multiple parts to the handshake, we may have to poll multiple
    // times to finish the accept.
    short events = 0;
    if (ssl_error == SSL_ERROR_WANT_WRITE || ssl_error == SSL_ERROR_WANT_ACCEPT) {
      events = POLLOUT;
    } else if (ssl_error == SSL_ERROR_WANT_READ) {
      events = POLLIN;
    } else {
      errata.error(
          R"(Failed SSL_accept {}, {}.)",
          swoc::bwf::SSLError{_ssl, retval},
          swoc::bwf::Errno{});
      break;
    }
    auto &&[poll_return, poll_errata] = poll_for_data_on_socket(Poll_Timeout, events);
    errata.note(std::move(poll_errata));
    if (!errata.is_ok()) {
      errata.error(R"(Failed SSL_accept during poll: {}.)", swoc::bwf::Errno{});
    } else if (poll_return == 0) {
      errata.error("Timed out waiting to SSL_accept after {}.", Poll_Timeout);
      return errata;
    } else if (poll_return < 0) {
      // Connection closed.
      errata.diag("Connection closed during poll for SSL_accept.");
      return errata;
    }
    // Poll succeeded.
    retval = SSL_accept(_ssl);
  }
  errata.diag("Finished accept using TLSSession");
  return errata;
}

int *H2Session::process_exit_code = nullptr;

swoc::Rv<int>
H2Session::poll_for_headers(chrono::milliseconds timeout)
{
  if (!_h2_is_negotiated) {
    return TLSSession::poll_for_headers(timeout);
  }
  if (this->get_a_stream_has_ended()) {
    return 1;
  }
  swoc::Rv<int> zret{-1};
  auto &&[poll_result, poll_errata] = Session::poll_for_data_on_socket(timeout);
  zret.note(std::move(poll_errata));
  if (!zret.is_ok()) {
    return zret;
  } else if (poll_result == 0) {
    return 0;
  } else if (poll_result < 0) {
    // Connection closed.
    close();
    return -1;
  }
  auto const received_bytes =
      receive_nghttp2_request(this->get_session(), nullptr, 0, 0, this, timeout);
  if (received_bytes == 0) {
    // The receive timed out.
    return 0;
  }
  if (is_closed()) {
    return -1;
  } else if (this->get_a_stream_has_ended()) {
    return 1;
  } else {
    // The caller will retry.
    return 0;
  }
}

bool
H2Session::get_is_server() const
{
  return _is_server;
}

// static
void
H2Session::set_non_zero_exit_status()
{
  *H2Session::process_exit_code = 1;
}

void
H2Session::record_stream_state(int32_t stream_id, std::shared_ptr<H2StreamState> stream_state)
{
  _stream_map[stream_id] = stream_state;
  _last_added_stream = stream_state;
}

bool
H2Session::get_a_stream_has_ended() const
{
  return !_ended_streams.empty();
}

void
H2Session::set_stream_has_ended(int32_t stream_id)
{
  _ended_streams.push_back(stream_id);
}

swoc::Rv<std::shared_ptr<HttpHeader>>
H2Session::read_and_parse_request(swoc::FixedBufferWriter &buffer)
{
  if (!_h2_is_negotiated) {
    return TLSSession::read_and_parse_request(buffer);
  }
  swoc::Rv<std::shared_ptr<HttpHeader>> zret{nullptr};

  // This function should only be called after poll_for_headers() says there is
  // a finished stream.
  assert(!_ended_streams.empty());
  auto const stream_id = _ended_streams.front();
  _ended_streams.pop_front();
  auto stream_map_iter = _stream_map.find(stream_id);
  if (stream_map_iter == _stream_map.end()) {
    zret.error("Requested request headers for stream id {}, but none are available.", stream_id);
    return zret;
  }
  auto &stream_state = stream_map_iter->second;
  zret = stream_state->_request_from_client;
  return zret;
}

swoc::Rv<size_t>
H2Session::drain_body(HttpHeader const &hdr, size_t expected_content_size, swoc::TextView initial)
{
  if (!_h2_is_negotiated) {
    return TLSSession::drain_body(hdr, expected_content_size, initial);
  }
  // For HTTP/2, we process entire streams once they are ended. Therefore there
  // is never body to drain.
  return {0};
}

// Complete the TLS handshake (server-side).
swoc::Errata
H2Session::accept()
{
  swoc::Errata errata = TLSSession::accept();
  if (!errata.is_ok()) {
    errata.error(R"(Failed to accept SSL server object)");
    return errata;
  }

  // Check what HTTP protocol was negotiated.
  unsigned char const *alpn = nullptr;
  unsigned int alpnlen = 0;
#ifndef OPENSSL_NO_NEXTPROTONEG
  SSL_get0_next_proto_negotiated(this->_ssl, &alpn, &alpnlen);
#endif /* !OPENSSL_NO_NEXTPROTONEG */
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
  if (alpn == nullptr) {
    SSL_get0_alpn_selected(this->_ssl, &alpn, &alpnlen);
  }
#endif /* OPENSSL_VERSION_NUMBER >= 0x10002000L */

  if (alpn != nullptr && alpnlen == 2 && memcmp("h2", alpn, 2) == 0) {
    errata.diag(R"(Negotiated ALPN: {}, HTTP/2 is negotiated.)", TextView{(char *)alpn, alpnlen});
    _h2_is_negotiated = true;
  } else {
    errata.diag(
        R"(Negotiated ALPN: {}, HTTP/2 is not negotiated. Assuming HTTP/1)",
        (alpn == nullptr) ? "none" : TextView{(char *)alpn, alpnlen});
    _h2_is_negotiated = false;
    // The rest of the code in this function is for HTTP/2 behavior.
    return errata;
  }

  this->server_session_init();
  errata.diag("Finished accept using H2Session");
  // Send initial H2 session frames
  send_connection_settings();
  send_nghttp2_data(_session, nullptr, 0, 0, this);
  return errata;
}

swoc::Errata
Session::do_connect(swoc::IPEndpoint const *real_target)
{
  swoc::Errata errata;
  int socket_fd = socket(real_target->family(), SOCK_STREAM, 0);
  if (0 <= socket_fd) {
    int ONE = 1;
    struct linger l;
    l.l_onoff = 0;
    l.l_linger = 0;
    setsockopt(socket_fd, SOL_SOCKET, SO_LINGER, (char *)&l, sizeof(l));
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

swoc::Errata
Session::connect()
{
  swoc::Errata errata;
  return errata;
}

swoc::Errata
TLSSession::connect()
{
  return this->connect(client_context);
}

// Complete the TLS handshake (client-side).
swoc::Errata
TLSSession::connect(SSL_CTX *client_context)
{
  swoc::Errata errata;
  _ssl = SSL_new(client_context);
  if (_ssl == nullptr) {
    errata.error(
        R"(Failed to create SSL client object fd={} client_context={} err={}.)",
        get_fd(),
        client_context,
        swoc::bwf::SSLError{});
    return errata;
  }
  SSL_set_fd(_ssl, get_fd());
  if (!_client_sni.empty()) {
    SSL_set_tlsext_host_name(_ssl, _client_sni.c_str());
  }
  if (_client_verify_mode != SSL_VERIFY_NONE) {
    errata.diag(
        R"(Setting client TLS verification mode against the proxy to: {}.)",
        _client_verify_mode);
    SSL_set_verify(_ssl, _client_verify_mode, nullptr /* No verify_callback is passed */);
  }
  int retval = SSL_connect(_ssl);
  while (retval < 0) {
    auto const ssl_error = SSL_get_error(_ssl, retval);
    // Since there are multiple parts to the handshake, we may have to poll multiple
    // times to finish the accept.
    short events = 0;
    if (ssl_error == SSL_ERROR_WANT_WRITE || ssl_error == SSL_ERROR_WANT_CONNECT) {
      events = POLLOUT;
    } else if (ssl_error == SSL_ERROR_WANT_READ) {
      events = POLLIN;
    } else {
      errata.error(
          R"(Failed SSL_connect {}, {}.)",
          swoc::bwf::SSLError{_ssl, retval},
          swoc::bwf::Errno{});
      break;
    }
    auto &&[poll_return, poll_errata] = poll_for_data_on_socket(Poll_Timeout, events);
    errata.note(std::move(poll_errata));
    if (!errata.is_ok()) {
      errata.error("Failed SSL_connect during poll.");
      return errata;
    } else if (poll_return < 0) {
      // Connection closed.
      errata.error("Connection closed while performing SSL_connect.");
      close();
      return errata;
    } else if (poll_return == 0) {
      errata.error("Poll timed out for SSL_connect after {}.", Poll_Timeout);
      return errata;
    }
    // Poll succeeded.
    retval = SSL_connect(_ssl);
  }

  auto const verify_result = SSL_get_verify_result(_ssl);
  errata.diag(
      R"(Proxy TLS verification result: {} ({}).)",
      verify_result,
      (verify_result == X509_V_OK ? "X509_V_OK" : "not X509_V_OK"));
  return errata;
}

// Complete the TLS handshake (client-side).
swoc::Errata
H2Session::connect()
{
  // Complete the TLS handshake
  swoc::Errata errata = super_type::connect(h2_client_context);
  if (!errata.is_ok()) {
    return errata;
  }
  unsigned char const *alpn = nullptr;
  unsigned int alpnlen = 0;

  // Make sure we negotiated a H2 session
#ifndef OPENSSL_NO_NEXTPROTONEG
  SSL_get0_next_proto_negotiated(this->_ssl, &alpn, &alpnlen);
#endif /* !OPENSSL_NO_NEXTPROTONEG */
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
  if (alpn == nullptr) {
    SSL_get0_alpn_selected(this->_ssl, &alpn, &alpnlen);
  }
#endif /* OPENSSL_VERSION_NUMBER >= 0x10002000L */

  if (alpn != nullptr && alpnlen == 2 && memcmp("h2", alpn, 2) == 0) {
    errata.diag(R"(h2 is negotiated.)");
    _h2_is_negotiated = true;
  } else {
    errata.diag(R"(h2 is not negotiated. Assuming HTTP/1)");
    _h2_is_negotiated = false;
    return errata;
  }

  this->client_session_init();

  // Send initial H2 session frames
  send_connection_settings();
  send_nghttp2_data(_session, nullptr, 0, 0, this);
  return errata;
}

swoc::Errata
H2Session::run_transactions(
    std::list<Txn> const &txn_list,
    swoc::IPEndpoint const *real_target,
    double rate_multiplier)
{
  swoc::Errata errata;

  auto const first_time = clock_type::now();
  for (auto const &txn : txn_list) {
    swoc::Errata txn_errata;
    auto const key{txn._req.get_key()};
    if (this->is_closed()) {
      txn_errata.note(this->do_connect(real_target));
      if (!txn_errata.is_ok()) {
        txn_errata.error(R"(Failed to reconnect HTTP/2 key={}.)", key);
        // If we don't have a valid connection, there's no point in continuing.
        break;
      }
    }
    if (rate_multiplier != 0) {
      auto const start_offset = txn._start;
      auto const next_time = (rate_multiplier * start_offset) + first_time;
      auto current_time = clock_type::now();
      auto delay_time = duration_cast<milliseconds>(next_time - current_time);
      while (delay_time > 0ms) {
        // Make use of our delay time to read any incoming responses.
        receive_nghttp2_data(this->get_session(), nullptr, 0, 0, this, delay_time);
        current_time = clock_type::now();
        delay_time = duration_cast<milliseconds>(next_time - current_time);
        sleep_for(delay_time);
      }
    }
    txn_errata.note(this->run_transaction(txn));
    if (!txn_errata.is_ok()) {
      txn_errata.error(R"(Failed HTTP/2 transaction with key={}.)", key);
    }
    errata.note(std::move(txn_errata));
  }
  receive_nghttp2_responses(this->get_session(), nullptr, 0, 0, this);
  return errata;
}

swoc::Errata
H2Session::run_transaction(Txn const &txn)
{
  swoc::Errata errata;
  auto &&[bytes_written, write_errata] = this->write(txn._req);
  errata.note(std::move(write_errata));
  _last_added_stream->_specified_response = &txn._rsp;
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

void
TLSSession::close()
{
  if (!this->is_closed()) {
    if (_ssl != nullptr) {
      SSL_free(_ssl);
      _ssl = nullptr;
    }
    super_type::close();
  }
}

swoc::file::path TLSSession::certificate_file;
swoc::file::path TLSSession::privatekey_file;
swoc::file::path TLSSession::ca_certificate_file;
swoc::file::path TLSSession::ca_certificate_dir;
SSL_CTX *TLSSession::server_context = nullptr;
SSL_CTX *TLSSession::client_context = nullptr;

const int MAX_NOFILE = 300000;

swoc::Errata
Session::init(int num_transactions)
{
  swoc::Errata errata;
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

// static
swoc::Errata
TLSSession::init()
{
  SSL_load_error_strings();
  SSL_library_init();
  Errata errata = TLSSession::client_init(client_context);
  errata.note(TLSSession::server_init(server_context));
  errata.diag("Finished TLSSession::init");
  return errata;
}

// static
void
TLSSession::terminate()
{
  TLSSession::terminate(client_context);
  TLSSession::terminate(server_context);
}

static int
client_hello_callback(SSL *ssl, int * /* al */, void * /* arg */)
{
  int ret = SSL_CLIENT_HELLO_SUCCESS;
  swoc::Errata errata;

  /*
   * Retrieve the SNI from the client hello, if provided.
   *
   * I'm surprised by how complicated this is. SSL_get_servername, which would
   * ideally make this easy, does not work in the context of the client hello
   * callback, yet documentation encourages using the client hello callback
   * rather than the server name callback. I borrowed the below code from
   * OpenSSL here:
   *
   * https://codesearch.isocpp.org/actcd19/main/o/openssl/openssl_1.1.1a-1/test/handshake_helper.c
   *
   * Licensed under the permissive OpenSSL license.
   */

  unsigned char const *p = nullptr;
  size_t len = 0, remaining = 0;

  /*
   * The server_name extension was given too much extensibility when it
   * was written, so parsing the normal case is a bit complex.
   */
  if (!SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_server_name, &p, &remaining) || remaining <= 2) {
    return ret;
  }
  /* Extract the length of the supplied list of names. */
  len = (*(p++) << 8);
  len += *(p++);
  if (len + 2 != remaining) {
    return ret;
  }
  remaining = len;
  /*
   * The list in practice only has a single element, so we only consider
   * the first one.
   */
  if (remaining == 0 || *p++ != TLSEXT_NAMETYPE_host_name) {
    return 0;
  }
  remaining--;
  /* Now we can finally pull out the byte array with the actual hostname. */
  if (remaining <= 2) {
    return ret;
  }
  len = (*(p++) << 8);
  len += *(p++);
  if (len + 2 > remaining) {
    return 0;
  }
  remaining = len;
  char const *client_sni = (const char *)p;

  /* End: code borrowed from OpenSSL. */

  if (client_sni == nullptr) {
    return ret;
  }
  errata.diag(R"(Accepted a TLS connection with an SNI of: {}.)", client_sni);

  auto const verify_mode = TLSSession::get_verify_mode_for_sni(client_sni);
  if (verify_mode == SSL_VERIFY_NONE) {
    return ret;
  }
  errata.diag(R"(Sending a certificate request to client with SNI: {}.)", client_sni);

  SSL_set_verify(ssl, verify_mode, nullptr /* no callback specified */);

  auto const verify_result = SSL_get_verify_result(ssl);
  errata.diag(
      R"(Client TLS verification result for client with SNI {}: {}.)",
      client_sni,
      (verify_result == X509_V_OK ? "passed" : "failed"));
  return ret;
}
// static
swoc::Errata
TLSSession::configure_host_cert(
    std::string_view _cert_path,
    std::string_view public_file,
    std::string_view private_file)
{
  swoc::Errata errata;
  swoc::file::path cert_path{_cert_path};
  std::error_code ec;
  cert_path = swoc::file::absolute(cert_path, ec);
  if (ec.value() != 0) {
    errata.error(
        R"(Could not get absolute path for host certificate path "{}": {}.)",
        cert_path,
        ec);
    return errata;
  }

  auto stat{swoc::file::status(cert_path, ec)};
  if (ec.value() != 0) {
    errata.error(R"(Invalid host certificate path "{}": {}.)", cert_path, ec);
    return errata;
  }

  if (is_dir(stat)) {
    TLSSession::certificate_file = swoc::file::path{(cert_path / public_file).string()};
    TLSSession::privatekey_file = swoc::file::path{(cert_path / private_file).string()};
  } else {
    TLSSession::certificate_file = swoc::file::path{cert_path.string()};
  }
  return errata;
}

// static
swoc::Errata
TLSSession::configure_client_cert(std::string_view cert_path)
{
  return TLSSession::configure_host_cert(cert_path, "client.pem", "client.key");
}

// static
swoc::Errata
TLSSession::configure_server_cert(std::string_view cert_path)
{
  return TLSSession::configure_host_cert(cert_path, "server.pem", "server.key");
}

// static
swoc::Errata
TLSSession::configure_ca_cert(std::string_view _cert_path)
{
  swoc::Errata errata;
  swoc::file::path cert_path{_cert_path};
  std::error_code ec;
  cert_path = swoc::file::absolute(cert_path, ec);
  if (ec.value() != 0) {
    errata.error(R"(Could not get absolute path for CA certificate path "{}": {}.)", cert_path, ec);
    return errata;
  }

  auto stat{swoc::file::status(cert_path, ec)};
  if (ec.value() != 0) {
    errata.error(R"(Could not stat certificate path "{}": {}.)", cert_path, ec);
    return errata;
  }

  if (is_dir(stat)) {
    TLSSession::ca_certificate_dir = swoc::file::path{cert_path};
  } else {
    TLSSession::ca_certificate_file = swoc::file::path{cert_path};
  }
  return errata;
}

// static
swoc::Errata
TLSSession::configure_certificates(SSL_CTX *&context)
{
  swoc::Errata errata;
  if (!certificate_file.empty()) {
    // A host certificate was provided.
    if (!SSL_CTX_use_certificate_file(context, certificate_file.c_str(), SSL_FILETYPE_PEM)) {
      errata.error(
          R"(Failed to load server cert from "{}": {}.)",
          certificate_file,
          swoc::bwf::SSLError{});
    } else {
      // Loading the public key succeeded. The private key may have been
      // provided as a separate file or it may be included in the previous
      // file.
      if (!privatekey_file.empty()) {
        // The private key is in a separate file.
        if (!SSL_CTX_use_PrivateKey_file(context, privatekey_file.c_str(), SSL_FILETYPE_PEM)) {
          errata.error(
              R"(Failed to load server private key from "{}": {}.)",
              privatekey_file,
              swoc::bwf::SSLError{});
        }
      } else {
        // The private key is (well, at least should) be included in the same
        // cert file.
        if (!SSL_CTX_use_PrivateKey_file(context, certificate_file.c_str(), SSL_FILETYPE_PEM)) {
          errata.error(
              R"(Failed to load server private key from certificate "{}": {}.)",
              certificate_file,
              swoc::bwf::SSLError{});
        }
      }
    }
  }

  if (!ca_certificate_file.empty() || !ca_certificate_dir.empty()) {
    // A CA for peer verification was provided.

    // SSL_CTX_load_verify_locations expects nullptr, not empty string, for
    // the unprovided path parameters.
    char const *cert_file = ca_certificate_file.empty() ? nullptr : ca_certificate_file.c_str();
    char const *cert_dir = ca_certificate_dir.empty() ? nullptr : ca_certificate_dir.c_str();
    if (!SSL_CTX_load_verify_locations(context, cert_file, cert_dir)) {
      errata.error(
          R"(Failed to load ca certificates from "{}" and "{}": {}.)",
          ca_certificate_file,
          ca_certificate_dir,
          swoc::bwf::SSLError{});
    }
  }
  return errata;
}

// static
swoc::Errata
TLSSession::client_init(SSL_CTX *&client_context)
{
  swoc::Errata errata;
  client_context = SSL_CTX_new(TLS_client_method());
  if (!client_context) {
    errata.error(R"(Failed to create client_context: {}.)", swoc::bwf::SSLError{});
    return errata;
  }
  errata.note(configure_certificates(client_context));
  return errata;
}

swoc::Errata
TLSSession::server_init(SSL_CTX *&server_context)
{
  swoc::Errata errata;
  server_context = SSL_CTX_new(TLS_server_method());
  if (!server_context) {
    errata.error(R"(Failed to create server_context: {}.)", swoc::bwf::SSLError{});
    return errata;
  }
  errata.note(configure_certificates(server_context));

  /* Register for the client hello callback so we can inspect the SNI
   * for dynamic server behavior (such as requesting a client cert). */
  SSL_CTX_set_client_hello_cb(server_context, client_hello_callback, nullptr);

  return errata;
}

// static
void
TLSSession::terminate(SSL_CTX *&context)
{
  SSL_CTX_free(context);
  context = nullptr;
}

// static
void
TLSSession::register_tls_handshake_behavior(
    std::string_view sni,
    TLSHandshakeBehavior &&handshake_behavior)
{
  _handshake_behavior_per_sni.emplace(sni, std::move(handshake_behavior));
}

// static
int
TLSSession::get_verify_mode_for_sni(std::string_view sni)
{
  auto const it = _handshake_behavior_per_sni.find(std::string(sni));
  if (it == _handshake_behavior_per_sni.end()) {
    return SSL_VERIFY_NONE;
  }
  return it->second.get_verify_mode();
}

// static
std::string_view
TLSSession::get_alpn_protocol_string_for_sni(std::string_view sni)
{
  auto const it = _handshake_behavior_per_sni.find(std::string(sni));
  if (it == _handshake_behavior_per_sni.end()) {
    return "";
  }
  return it->second.get_alpn_wire_string();
}

static int
on_begin_headers_callback(
    nghttp2_session * /* session */,
    nghttp2_frame const *frame,
    void *user_data)
{
  swoc::Errata errata;
  H2Session *session_data = reinterpret_cast<H2Session *>(user_data);
  int const headers_category = frame->headers.cat;
  auto const stream_id = frame->hd.stream_id;

  switch (headers_category) {
  case NGHTTP2_HCAT_REQUEST: {
    auto stream_state = std::make_shared<H2StreamState>();
    stream_state->set_stream_id(stream_id);
    session_data->record_stream_state(stream_id, stream_state);
    auto &request_headers = stream_state->_request_from_client;
    request_headers->_contains_pseudo_headers_in_fields_array = true;
    request_headers->_stream_id = stream_id;
    break;
  }
  case NGHTTP2_HCAT_RESPONSE: {
    auto stream_map_iter = session_data->_stream_map.find(stream_id);
    if (stream_map_iter == session_data->_stream_map.end()) {
      errata.error(
          "Got HTTP/2 headers for an unregistered stream id of {}. Headers category: {}",
          stream_id,
          headers_category);
      return 0;
    }
    auto &stream_state = stream_map_iter->second;
    auto &response_headers = stream_state->_response_from_server;
    response_headers->_stream_id = stream_id;
    response_headers->_contains_pseudo_headers_in_fields_array = true;
    break;
  }
  case NGHTTP2_HCAT_PUSH_RESPONSE:
  case NGHTTP2_HCAT_HEADERS:
    errata.error("Got HTTP/2 headers for an unimplemented category: {}", headers_category);
  }
  return 0;
}

static int
on_header_callback(
    nghttp2_session * /* session */,
    nghttp2_frame const *frame,
    nghttp2_rcbuf *name,
    nghttp2_rcbuf *value,
    uint8_t /* flags */,
    void *user_data)
{
  // Be aware that the END_STREAM and END_HEADERS flags are not provided here
  // by nghttp2.  They instead have to be processed in on_frame_recv_cb.
  swoc::Errata errata;
  int const headers_category = frame->headers.cat;
  auto const stream_id = frame->hd.stream_id;
  H2Session *session_data = reinterpret_cast<H2Session *>(user_data);
  auto stream_map_iter = session_data->_stream_map.find(stream_id);
  if (stream_map_iter == session_data->_stream_map.end()) {
    errata.error(
        "Got HTTP/2 headers for an unregistered stream id of {}. Headers category: {}",
        stream_id,
        headers_category);
    return 0;
  }
  auto &stream_state = stream_map_iter->second;

  swoc::TextView name_view = stream_state->register_rcbuf(name);
  swoc::TextView value_view = stream_state->register_rcbuf(value);

  switch (headers_category) {
  case NGHTTP2_HCAT_REQUEST: {
    auto &request_headers = stream_state->_request_from_client;
    if (name_view == ":method") {
      request_headers->_method = value_view;
    } else if (name_view == ":scheme") {
      request_headers->_scheme = value_view;
    } else if (name_view == ":authority") {
      request_headers->_authority = value_view;
    } else if (name_view == ":path") {
      request_headers->_path = value_view;
    }
    request_headers->_fields_rules->add_field(name_view, value_view);
    break;
  }

  case NGHTTP2_HCAT_RESPONSE: {
    auto &response_headers = stream_state->_response_from_server;
    if (name_view == ":status") {
      response_headers->_status = swoc::svtou(value_view);
      response_headers->_status_string = std::string(value_view);
    }
    response_headers->_fields_rules->add_field(name_view, value_view);
    // See if we are expecting a 100 response.
    if (stream_state->_wait_for_continue) {
      if (name_view == ":status" && value_view == "100") {
        // We got our 100 Continue. No need to wait for it anymore.
        stream_state->_wait_for_continue = false;
      }
    }
    break;
  }
  case NGHTTP2_HCAT_PUSH_RESPONSE:
  case NGHTTP2_HCAT_HEADERS:
    errata.error("Got HTTP/2 an header for an unimplemented category: {}", headers_category);
    return 0;
  }
  return 0;
}

/* nghttp2_send_callback. Here we transmit the |data|, |length| bytes,
 *    to the network. Because we are using libevent bufferevent, we just
 *       write those bytes into bufferevent buffer. */
static ssize_t
send_nghttp2_data(
    nghttp2_session *session,
    uint8_t const * /* inputdata */,
    size_t /* length */,
    int /* flags */,
    void *user_data)
{
  Errata errata;
  H2Session *session_data = reinterpret_cast<H2Session *>(user_data);
  int total_amount_sent = 0;
  while (true) {
    uint8_t const *data = nullptr;
    ssize_t datalen = nghttp2_session_mem_send(session, &data);
    if (datalen == 0) {
      // No more data to send.
      break;
    } else if (datalen < 0) {
      errata.error("Failure calling nghttp2_session_mem_send: {}", datalen);
      break;
    }
    int amount_sent = 0;
    while (amount_sent < datalen) {
      auto const n = session_data->write(TextView{(char *)data, (size_t)datalen});
      if (n <= 0) {
        break;
      }
      amount_sent += n;
    }
    total_amount_sent += amount_sent;
  }

  return (ssize_t)total_amount_sent;
}

/**
 * Receive data on the session for timeout milliseconds.
 *
 * @return The number of bytes processes per nghttp2_session_mem_recv (may be
 * 0), or -1 on error.
 */
static ssize_t
receive_nghttp2_data(
    nghttp2_session *session,
    uint8_t * /* buf */,
    size_t /* length */,
    int /* flags */,
    void *user_data,
    milliseconds timeout)
{
  H2Session *session_data = reinterpret_cast<H2Session *>(user_data);
  swoc::Errata errata;
  unsigned char buffer[10 * 1024];

  if (session_data->is_closed()) {
    errata.error("Socket closed while waiting for an HTTP/2 resonse.");
    return -1;
  }
  int n = SSL_read(session_data->get_ssl(), buffer, sizeof(buffer));
  if (n <= 0) {
    auto const ssl_error = SSL_get_error(session_data->get_ssl(), n);
    auto &&[poll_return, poll_errata] =
        session_data->poll_for_data_on_ssl_socket(timeout, ssl_error);
    errata.note(std::move(poll_errata));
    if (!errata.is_ok()) {
      errata.error(R"(Failed SSL_read for HTTP/2 responses during poll: {}.)", swoc::bwf::Errno{});
      return -1;
    } else if (poll_return < 0) {
      session_data->close();
      errata.error("Socket closed while polling for an HTTP/2 resonse.");
      return -1;
    } else if (poll_return == 0) {
      // Timeout in this context is OK.
      return 0;
    }
    // Poll succeeded. Repeat the attempt to read.
    n = SSL_read(session_data->get_ssl(), buffer, sizeof(buffer));
  }
  if (n <= 0) {
    auto const ssl_error = SSL_get_error(session_data->get_ssl(), n);
    if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
      // SSL just wants more data. Not a problem.
      return 0;
    } else {
      // Assume there was an issue.
      errata.error("SSL_read error in receive_nghttp2_data: {}", swoc::bwf::SSLError{ssl_error});
      return -1;
    }
  }

  // n > 0: Some bytes have been read. Pass that into the nghttp2 system.
  int rv = nghttp2_session_mem_recv(session_data->get_session(), buffer, (size_t)n);
  if (rv < 0) {
    errata.error(
        "nghttp2_session_mem_recv failed for HTTP/2 responses: {}",
        nghttp2_strerror((int)rv));
    return -1;
  } else if (rv == 0) {
    return 0;
  }
  // opportunity to send any frames like the window_update frame
  send_nghttp2_data(session, nullptr, 0, 0, user_data);
  return (ssize_t)rv;
}

static ssize_t
receive_nghttp2_responses(
    nghttp2_session *session,
    uint8_t * /* buf */,
    size_t /* length */,
    int /* flags */,
    void *user_data)
{
  H2Session *session_data = reinterpret_cast<H2Session *>(user_data);
  int total_recv = 0;

  while (!session_data->_stream_map.empty()) {
    auto const received_bytes =
        receive_nghttp2_data(session, nullptr, 0, 0, user_data, Poll_Timeout);
    if (received_bytes < 0) {
      break;
    }
    total_recv += total_recv;
  }
  return (ssize_t)total_recv;
}

static ssize_t
receive_nghttp2_request(
    nghttp2_session *session,
    uint8_t * /* buf */,
    size_t /* length */,
    int /* flags */,
    void *user_data,
    milliseconds timeout)
{
  H2Session *session_data = reinterpret_cast<H2Session *>(user_data);
  swoc::Errata errata;
  unsigned char buffer[10 * 1024];
  int total_recv = 0;

  auto const start_time = clock_type::now();
  while (session_data->get_is_server() && !session_data->get_a_stream_has_ended()) {
    if (start_time - clock_type::now() > timeout) {
      return 0;
    }
    int n = SSL_read(session_data->get_ssl(), buffer, sizeof(buffer));
    while (n <= 0) {
      auto const ssl_error = SSL_get_error(session_data->get_ssl(), n);
      auto &&[poll_return, poll_errata] =
          session_data->poll_for_data_on_ssl_socket(timeout, ssl_error);
      errata.note(std::move(poll_errata));
      if (!errata.is_ok()) {
        errata.error(
            R"(Failed SSL_read for HTTP/2 request headers during poll: {}.)",
            swoc::bwf::Errno{});
        return (ssize_t)total_recv;
      } else if (poll_return < 0) {
        session_data->close();
        return (ssize_t)total_recv;
      } else if (poll_return == 0) {
        errata.error("Timed out waiting to SSL_read for HTTP/2 request headers after {}.", timeout);
        return (ssize_t)total_recv;
      }
      // Poll succeeded. Repeat the attempt to read.
      n = SSL_read(session_data->get_ssl(), buffer, sizeof(buffer));
    }
    int rv = nghttp2_session_mem_recv(session, buffer, (size_t)n);
    if (rv < 0) {
      errata.error(
          "nghttp2_session_mem_recv failed for response headers: {}",
          nghttp2_strerror((int)rv));
      return -1;
    } else if (rv == 0) {
      return total_recv;
    }
    total_recv += rv;
    // opportunity to send any frames like the window_update frame
    send_nghttp2_data(session, nullptr, 0, 0, user_data);
  }
  return (ssize_t)total_recv;
}

static int
on_frame_send_cb(
    nghttp2_session * /* session */,
    nghttp2_frame const * /* frame */,
    void * /* user_data */)
{
  return 0;
}

static int
on_frame_recv_cb(nghttp2_session * /* session */, nghttp2_frame const *frame, void *user_data)
{
  // Note that this is called after the more specific on_begin_headers_callback,
  // on_header_callback, etc. callbacks are called.
  swoc::Errata errata;

  switch (frame->hd.type) {
  case NGHTTP2_DATA:
    break;
  case NGHTTP2_HEADERS:
    break;
  case NGHTTP2_PRIORITY: // Not doing anything here
    break;
  case NGHTTP2_RST_STREAM: // Close down the stream, now
    break;
  case NGHTTP2_SETTINGS: // Don't do anything here
    break;
  case NGHTTP2_WINDOW_UPDATE: // Don't do anything here
    // May need to make sure we don't overrun windows for large uploads
    // Or hopefully the underlying system does that...
    break;
  case NGHTTP2_PUSH_PROMISE: // Don't do anything here
    break;
  case NGHTTP2_GOAWAY: // Take down the session now
    break;
  }
  auto const flags = frame->hd.flags;
  // `flags` have to be processed here. They are not communicated via
  // on_header_callback.
  if (flags & NGHTTP2_FLAG_END_HEADERS || flags & NGHTTP2_FLAG_END_STREAM) {
    auto *session_data = reinterpret_cast<H2Session *>(user_data);
    auto const stream_id = frame->hd.stream_id;
    auto stream_map_iter = session_data->_stream_map.find(stream_id);
    if (stream_map_iter == session_data->_stream_map.end()) {
      // Nothing to do if this is not in our stream map.
      return 0;
    }
    if (flags & NGHTTP2_FLAG_END_HEADERS) {
      H2StreamState &stream_state = *stream_map_iter->second;
      int const headers_category = frame->headers.cat;
      if (headers_category == NGHTTP2_HCAT_REQUEST) {
        auto &request_from_client = *stream_state._request_from_client;
        request_from_client.derive_key();
        stream_state._key = request_from_client.get_key();
        auto &composed_url = stream_state._composed_url;
        composed_url = request_from_client._scheme;
        if (!composed_url.empty()) {
          composed_url.append("://");
        }
        composed_url.append(request_from_client._authority);
        composed_url.append(request_from_client._path);
        request_from_client.parse_url(composed_url);
        errata.diag(
            "Received an HTTP/2 request for stream id {}:\n{}",
            stream_id,
            request_from_client);
      } else if (headers_category == NGHTTP2_HCAT_RESPONSE) {
        auto &response_from_wire = *stream_state._response_from_server;
        errata.diag(
            "Received an HTTP/2 response for stream id {}:\n{}",
            stream_id,
            response_from_wire);
        response_from_wire.derive_key();
        if (stream_state._key.empty()) {
          // A response for which we didn't process the request, presumably. A
          // server push? Maybe? In theory we can support that but currently we
          // do not. Emit a warning for now.
          stream_state._key = response_from_wire.get_key();
          errata.error(
              "Incoming HTTP/2 response has no key set from the request. Using key from "
              "response: {}.",
              stream_state._key);
        } else {
          // Make sure the key is set and give preference to the associated
          // request over the content of the response. There shouldn't be a
          // difference, but if there is, the user has the YAML file with the
          // request's key in front of them, and identifying that transaction
          // is more helpful than so some abberant response's key from the
          // wire. If they are looking into issues, debug logging will show
          // the fields of both the request and response.
          response_from_wire.set_key(stream_state._key);
        }
        auto const &key = stream_state._key;
        auto const &specified_response = stream_state._specified_response;
        if (response_from_wire.verify_headers(key, *specified_response->_fields_rules)) {
          errata.error(R"(HTTP/2 response headers did not match expected response headers.)");
          session_data->set_non_zero_exit_status();
        }
        if (specified_response->_status != 0 &&
            response_from_wire._status != specified_response->_status &&
            (response_from_wire._status != 200 || specified_response->_status != 304) &&
            (response_from_wire._status != 304 || specified_response->_status != 200))
        {
          errata.error(
              R"(HTTP/2 Status Violation: expected {} got {}, key={}.)",
              specified_response->_status,
              response_from_wire._status,
              key);
        }
      }
    }
    if (flags & NGHTTP2_FLAG_END_STREAM) {
      // We already verified above that this is in our _stream_map.
      session_data->set_stream_has_ended(stream_id);
    }
  }
  return 0;
}

static int
on_stream_close_cb(
    nghttp2_session * /* session */,
    int32_t stream_id,
    uint32_t /* error_code */,
    void *user_data)
{
  swoc::Errata errata;
  errata.diag("Stream is closed with id: {}", stream_id);
  H2Session *session_data = reinterpret_cast<H2Session *>(user_data);
  auto iter = session_data->_stream_map.find(stream_id);
  if (iter != session_data->_stream_map.end()) {
    H2StreamState &stream_state = *iter->second;
    auto const &message_start = stream_state._stream_start;
    auto const message_end = clock_type::now();
    auto const elapsed_ms = duration_cast<chrono::milliseconds>(message_end - message_start);
    if (elapsed_ms > Transaction_Delay_Cutoff) {
      errata.error(
          R"(HTTP/2 transaction in stream id {} having key={} took {}.)",
          stream_id,
          stream_state._key,
          elapsed_ms);
    }
    stream_state.set_stream_has_closed();
    session_data->_stream_map.erase(iter);
  }
  return 0;
}

static int
on_data_chunk_recv_cb(
    nghttp2_session * /* session */,
    uint8_t /* flags */,
    int32_t stream_id,
    uint8_t const *data,
    size_t len,
    void *user_data)
{
  swoc::Errata errata;
  auto *session_data = reinterpret_cast<H2Session *>(user_data);
  auto iter = session_data->_stream_map.find(stream_id);
  if (iter == session_data->_stream_map.end()) {
    errata.error("Could not find a stream with stream id: {}", stream_id);
    return 0;
  }
  H2StreamState &stream_state = *iter->second;
  stream_state._received_body_length += len;
  errata.diag(
      "Drained HTTP/2 body for transaction with key: {}, stream id: {} "
      "of {} bytes with content: {}",
      stream_state._key,
      stream_id,
      len,
      TextView(reinterpret_cast<char const *>(data), len));
  return 0;
}

H2StreamState::H2StreamState()
  : _stream_start{clock_type::now()}
  , _request_from_client{std::make_shared<HttpHeader>()}
  , _response_from_server{std::make_shared<HttpHeader>()}
{
  _request_from_client->_is_http2 = true;
  _request_from_client->_is_request = true;
  _response_from_server->_is_http2 = true;
  _response_from_server->_is_response = true;
}

H2StreamState::~H2StreamState()
{
  for (auto rcbuf : _rcbufs_to_free) {
    nghttp2_rcbuf_decref(rcbuf);
  }
  if (_request_nv_headers) {
    free(_request_nv_headers);
    _request_nv_headers = nullptr;
  }
  if (_response_nv_headers) {
    free(_response_nv_headers);
    _response_nv_headers = nullptr;
  }
}

void
H2StreamState::set_stream_has_closed()
{
  _stream_has_closed = true;
}

bool
H2StreamState::get_stream_has_closed() const
{
  return _stream_has_closed;
}

void
H2StreamState::set_stream_id(int32_t id)
{
  _stream_id = id;
  if (_request_from_client) {
    _request_from_client->_stream_id = id;
  }
  if (_response_from_server) {
    _response_from_server->_stream_id = id;
  }
}

int32_t
H2StreamState::get_stream_id() const
{
  return _stream_id;
}

void
H2StreamState::store_nv_response_headers_to_free(nghttp2_nv *hdrs)
{
  _response_nv_headers = hdrs;
}

void
H2StreamState::store_nv_request_headers_to_free(nghttp2_nv *hdrs)
{
  _request_nv_headers = hdrs;
}

swoc::TextView
H2StreamState::register_rcbuf(nghttp2_rcbuf *rcbuf)
{
  nghttp2_rcbuf_incref(rcbuf);
  _rcbufs_to_free.push_back(rcbuf);
  auto buf = nghttp2_rcbuf_get_buf(rcbuf);
  return TextView(reinterpret_cast<char *>(buf.base), buf.len);
}

H2Session::H2Session() : _session{nullptr}, _callbacks{nullptr}, _options{nullptr} { }

H2Session::H2Session(swoc::TextView const &client_sni, int client_verify_mode)
  : TLSSession(client_sni, client_verify_mode)
  , _session{nullptr}
  , _callbacks{nullptr}
  , _options{nullptr}
{
}

H2Session::~H2Session()
{
  // This is safe to call upon a nullptr. Thus this is appropriate to be called
  // even if client_session_init or server_session_init has not been called.
  nghttp2_session_callbacks_del(_callbacks);
  nghttp2_session_del(_session);
  nghttp2_option_del(_options);
}

swoc::Rv<ssize_t>
H2Session::read(swoc::MemSpan<char> span)
{
  if (!_h2_is_negotiated) {
    return TLSSession::read(span);
  }
  return swoc::Rv<ssize_t>{1};
}

swoc::Rv<ssize_t>
H2Session::write(swoc::TextView data)
{
  return TLSSession::write(data);
}

ssize_t
data_read_callback(
    nghttp2_session *session,
    int32_t stream_id,
    uint8_t *buf,
    size_t length,
    uint32_t *data_flags,
    nghttp2_data_source * /* source */,
    void *user_data)
{
  swoc::Errata errata;
  size_t num_to_copy = 0;
  H2StreamState *stream_state =
      reinterpret_cast<H2StreamState *>(nghttp2_session_get_stream_user_data(session, stream_id));
  if (stream_state == nullptr) {
    auto *session_data = reinterpret_cast<H2Session *>(user_data);
    auto iter = session_data->_stream_map.find(stream_id);
    if (iter == session_data->_stream_map.end()) {
      errata.error("Could not find a stream with stream id: {}", stream_id);
      return 0;
    }
    stream_state = iter->second.get();
  }
  if (!stream_state->_wait_for_continue) {
    num_to_copy =
        std::min(length, stream_state->_send_body_length - stream_state->_send_body_offset);
    if (num_to_copy > 0) {
      memcpy(buf, stream_state->_body_to_send + stream_state->_send_body_offset, num_to_copy);
      stream_state->_send_body_offset += num_to_copy;
    } else {
      num_to_copy = 0;
    }
    if (stream_state->_send_body_offset >= stream_state->_send_body_length) {
      *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }
  }
  errata.diag("Writing a {} byte body for stream id: {}", num_to_copy, stream_id);
  return num_to_copy;
}

swoc::Rv<ssize_t>
H2Session::write(HttpHeader const &hdr)
{
  if (!_h2_is_negotiated) {
    return Session::write(hdr);
  }
  swoc::Rv<ssize_t> zret{0};
  int32_t stream_id = 0;
  int32_t submit_result = 0;
  H2StreamState *stream_state = nullptr;
  std::shared_ptr<H2StreamState> new_stream_state{nullptr};
  if (hdr._is_response) {
    stream_id = hdr._stream_id;
    auto stream_map_iter = _stream_map.find(stream_id);
    if (stream_map_iter == _stream_map.end()) {
      zret.error("Could not find registered stream for stream id: {}", stream_id);
      return zret;
    }
    stream_state = stream_map_iter->second.get();
  } else {
    new_stream_state = std::make_shared<H2StreamState>();
    stream_state = new_stream_state.get();
  }

  // grab header, send to session
  // pack_headers will convert all the fields in hdr into nghttp2_nv structs
  int hdr_count = 0;
  nghttp2_nv *hdrs = nullptr;
  pack_headers(hdr, hdrs, hdr_count);
  if (hdr._is_response) {
    stream_state->store_nv_response_headers_to_free(hdrs);
  } else {
    stream_state->store_nv_request_headers_to_free(hdrs);
  }

  stream_state->_key = hdr.get_key();
  if (hdr._content_size > 0 && (hdr._is_request || !HttpHeader::STATUS_NO_CONTENT[hdr._status])) {
    TextView content;
    if (hdr._content_data) {
      content = TextView{hdr._content_data, hdr._content_size};
    } else {
      // If hdr._content_data is null, then there was no explicit description
      // of the body data via the data node. Instead we'll use our generated
      // HttpHeader::_content.
      content = TextView{HttpHeader::_content.data(), hdr._content_size};
    }
    nghttp2_data_provider data_prd;
    data_prd.source.fd = 0;
    data_prd.source.ptr = nullptr;
    data_prd.read_callback = data_read_callback;
    stream_state->_body_to_send = content.data();
    stream_state->_send_body_length = content.size();
    stream_state->_wait_for_continue = hdr._send_continue;
    if (hdr._is_response) {
      submit_result = nghttp2_submit_response(
          this->_session,
          stream_state->get_stream_id(),
          hdrs,
          hdr_count,
          &data_prd);
    } else {
      submit_result =
          nghttp2_submit_request(this->_session, nullptr, hdrs, hdr_count, &data_prd, stream_state);
    }
  } else { // Empty body.
    if (hdr._is_response) {
      submit_result = nghttp2_submit_response(
          this->_session,
          stream_state->get_stream_id(),
          hdrs,
          hdr_count,
          nullptr);
    } else {
      submit_result =
          nghttp2_submit_request(this->_session, nullptr, hdrs, hdr_count, nullptr, stream_state);
    }
  }

  if (hdr._is_response) {
    stream_id = stream_state->get_stream_id();
    if (submit_result < 0) {
      zret.error(
          "Submitting an HTTP/2 with stream id {} response failed: {}",
          stream_id,
          submit_result);
    }
  } else { // request
    if (submit_result < 0) {
      zret.error("Submitting an HTTP/2 request failed: {}", submit_result);
    } else {
      stream_id = submit_result;
      stream_state->set_stream_id(stream_id);
      record_stream_state(stream_id, new_stream_state);
    }
    zret.diag("Sent the following HTTP/2 headers for stream id {}:\n{}", stream_id, hdr);
  }

  // Kick off the send logic to put the data on the wire
  zret.result() = send_nghttp2_data(_session, nullptr, 0, 0, this);

  return zret;
}

swoc::Errata
H2Session::pack_headers(HttpHeader const &hdr, nghttp2_nv *&nv_hdr, int &hdr_count)
{
  swoc::Errata errata;
  if (!_h2_is_negotiated) {
    errata.error("Should not be packing headers if h2 is not negotiated.");
    return errata;
  }
  hdr_count = hdr._fields_rules->_fields.size();

  if (!hdr._contains_pseudo_headers_in_fields_array) {
    if (hdr._is_response) {
      hdr_count += 1;
    } else if (hdr._is_request) {
      hdr_count += 4;
    } else {
      hdr_count = 0;
      errata.error(R"(Unable to write header: could not determine request/response state.)");
      return errata;
    }
  }

  nv_hdr = reinterpret_cast<nghttp2_nv *>(malloc(sizeof(nghttp2_nv) * hdr_count));
  int offset = 0;

  // nghttp2 requires pseudo header fields to be at the start of the
  // nv array. Thus we add them here before calling add_fields_to_ngnva
  // which then skips the pseueo headers if they are in there.
  if (hdr._is_response) {
    nv_hdr[offset++] = tv_to_nv(":status", hdr._status_string);
  } else if (hdr._is_request) {
    // TODO: add error checking and refactor and tolerance for non-required
    // pseudo-headers
    nv_hdr[offset++] = tv_to_nv(":method", hdr._method);
    nv_hdr[offset++] = tv_to_nv(":scheme", hdr._scheme);
    nv_hdr[offset++] = tv_to_nv(":path", hdr._path);
    nv_hdr[offset++] = tv_to_nv(":authority", hdr._authority);
  }

  hdr._fields_rules->add_fields_to_ngnva(nv_hdr + offset);

  return errata;
}

nghttp2_nv
H2Session::tv_to_nv(char const *name, swoc::TextView v)
{
  nghttp2_nv res;

  // Note: nghttp2 requires the field names to be lowercase if
  // NGHTTP2_NV_FLAG_NO_COPY_NAME is set. Fortunately we make our stored field
  // names lower case when we parse them from the yaml replay file.
  res.name = const_cast<uint8_t *>((uint8_t *)name);
  res.value = const_cast<uint8_t *>((uint8_t *)v.data());
  res.namelen = strlen(name);
  res.valuelen = v.length();
  res.flags = NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE;

  return res;
}

SSL_CTX *H2Session::h2_client_context = nullptr;

swoc::Errata
H2Session::send_connection_settings()
{
  swoc::Errata errata;
  nghttp2_settings_entry iv[1] = {{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
  int rv = 0;

  /* client 24 bytes magic string will be sent by nghttp2 library */
  rv = nghttp2_submit_settings(this->_session, NGHTTP2_FLAG_NONE, iv, 1);
  if (rv != 0) {
    errata.error(R"(Could not submit SETTINGS)");
  }
  return errata;
}

const unsigned char npn_str[] = {2, 'h', '2', 7, 'h', 't', 't', 'p', '1', '.', '1'};
constexpr int npn_len = sizeof(npn_str);

int
alpn_select_next_proto_cb(
    SSL *ssl,
    unsigned char const **out,
    unsigned char *outlen,
    unsigned char const *in,
    unsigned int inlen,
    void * /* arg */)
{
  /* It's easier to get the SNI here than in the client_hello_callback because
   * we can use SSL_get_servername here. Per the OpenSSL documentation of
   * SSL_get_servername:
   *
   *    Note that the ClientHello callback occurs before a servername extension
   *    from the client is processed. The servername, certificate and ALPN
   *    callbacks occur after a servername extension from the client is
   *    processed.
   */
  char const *sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
  unsigned char const *alpn = npn_str;
  int alpn_len = npn_len;

  if (sni != nullptr) {
    std::string_view alpn_protocol_string = TLSSession::get_alpn_protocol_string_for_sni(sni);
    if (!alpn_protocol_string.empty()) {
      alpn = reinterpret_cast<unsigned char const *>(alpn_protocol_string.data());
      alpn_len = alpn_protocol_string.size();
    }
  }

  swoc::Errata errata;
  if (SSL_select_next_proto(const_cast<unsigned char **>(out), outlen, alpn, alpn_len, in, inlen) ==
      OPENSSL_NPN_NEGOTIATED)
  {
    errata.diag("Negotiated alpn: {}", TextView{(char *)*out, (size_t)*outlen});
    return SSL_TLSEXT_ERR_OK;
  } else {
    errata.error(
        R"(Failed to find a an ALPN match: server ALPN list: "{}", client ALPN list: "{}")",
        TextView((char *)alpn, (size_t)alpn_len),
        TextView{(char *)in, (size_t)inlen});
  }
  *out = nullptr;
  *outlen = 0;
  return SSL_TLSEXT_ERR_NOACK;
}

#ifndef OPENSSL_NO_NEXTPROTONEG
int
select_next_proto_cb(
    SSL * /* ssl */,
    unsigned char **out,
    unsigned char *outlen,
    unsigned char const *in,
    unsigned int inlen,
    void * /* arg */)
{
  if (SSL_select_next_proto(out, outlen, npn_str, npn_len, in, inlen) == OPENSSL_NPN_NEGOTIATED) {
    return SSL_TLSEXT_ERR_OK;
  }
  *out = nullptr;
  *outlen = 0;
  return SSL_TLSEXT_ERR_NOACK;
}

static int
advertise_next_protocol_cb(
    SSL * /* ssl */,
    unsigned char const **out,
    unsigned int *outlen,
    void * /* arg */)
{
  *out = npn_str;
  *outlen = npn_len;
  return SSL_TLSEXT_ERR_OK;
}
#endif /* !OPENSSL_NO_NEXTPROTONEG */

// static
swoc::Errata
H2Session::init(int *process_exit_code)
{
  H2Session::process_exit_code = process_exit_code;
  Errata errata = H2Session::client_init(h2_client_context);
  errata.note(H2Session::server_init(server_context));
  errata.diag("Finished H2Session::init");
  return errata;
}

// static
void
H2Session::terminate()
{
  // H2Session uses the same context as TLSSession::server_context, which is
  // cleaned up via TLSSession::init().
  return H2Session::terminate(h2_client_context);
}

// static
swoc::Errata
H2Session::client_init(SSL_CTX *&client_context)
{
  swoc::Errata errata = super_type::client_init(client_context);

  if (!errata.is_ok()) {
    return errata;
  }

#ifndef OPENSSL_NO_NEXTPROTONEG
  // Initialize the protocol selection to include H2
  SSL_CTX_set_next_proto_select_cb(client_context, select_next_proto_cb, nullptr);
#endif /* !OPENSSL_NO_NEXTPROTONEG */

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
  // Set the protocols the client will advertise
  SSL_CTX_set_alpn_protos(client_context, npn_str, npn_len);
#else
  static_assert(false, "Error must be at least openssl 1.0.2");
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L
  return errata;
}

// static
swoc::Errata
H2Session::server_init(SSL_CTX *&server_context)
{
  swoc::Errata errata;
  // H2Session uses TLSSession::server_context which is already initialized via
  // TLSSession::init. Thus there is no need to call
  // TLSSession::server_session_init() here.

#ifndef OPENSSL_NO_NEXTPROTONEG
  // Initialize the protocol selection to include H2
  SSL_CTX_set_next_protos_advertised_cb(server_context, advertise_next_protocol_cb, nullptr);
#endif /* !OPENSSL_NO_NEXTPROTONEG */

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
  // Set the protocols the server will negotiate.
  SSL_CTX_set_alpn_select_cb(server_context, alpn_select_next_proto_cb, nullptr);
#else
  static_assert(false, "Error must be at least openssl 1.0.2");
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L
  return errata;
}

// static
void
H2Session::terminate(SSL_CTX *&client_context)
{
  super_type::terminate(client_context);
}

swoc::Errata
H2Session::client_session_init()
{
  swoc::Errata errata;

  // Set up the H2 callback methods
  int ret = nghttp2_session_callbacks_new(&this->_callbacks);

  if (ret != 0) {
    errata.error("nghttp2_session_callbacks_new {}", ret);
  }

  if (0 != nghttp2_option_new(&_options)) {
    errata.error("nghttp2_option_new could not allocate memory.");
  }
  nghttp2_option_set_no_closed_streams(_options, 1);
  nghttp2_option_set_max_deflate_dynamic_table_size(_options, 0);

  nghttp2_session_callbacks_set_on_begin_headers_callback(
      this->_callbacks,
      on_begin_headers_callback);
  nghttp2_session_callbacks_set_on_header_callback2(this->_callbacks, on_header_callback);

  // Note that instead of using the nghttp2_session_callbacks_set_send_callback
  // and nghttp2_session_callbacks_set_recv_callback, we manually drive things
  // along via our use of nghttp2_session_mem_recv and
  // nghttp2_session_mem_send.

  nghttp2_session_callbacks_set_on_frame_send_callback(this->_callbacks, on_frame_send_cb);
  nghttp2_session_callbacks_set_on_frame_recv_callback(this->_callbacks, on_frame_recv_cb);
  nghttp2_session_callbacks_set_on_stream_close_callback(this->_callbacks, on_stream_close_cb);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
      this->_callbacks,
      on_data_chunk_recv_cb);

  nghttp2_session_client_new(&this->_session, this->_callbacks, this);

  return errata;
}

swoc::Errata
H2Session::server_session_init()
{
  swoc::Errata errata;
  if (!_h2_is_negotiated) {
    return errata;
  }

  _is_server = true;

  // Set up the H2 callback methods
  auto ret = nghttp2_session_callbacks_new(&this->_callbacks);
  if (0 != ret) {
    errata.error("nghttp2_session_callbacks_new {}", ret);
    return errata;
  }

  if (0 != nghttp2_option_new(&_options)) {
    errata.error("nghttp2_option_new could not allocate memory.");
    return errata;
  }
  nghttp2_option_set_no_closed_streams(_options, 1);
  nghttp2_option_set_max_deflate_dynamic_table_size(_options, 0);

  nghttp2_session_callbacks_set_on_header_callback2(this->_callbacks, on_header_callback);
  nghttp2_session_callbacks_set_on_begin_headers_callback(
      this->_callbacks,
      on_begin_headers_callback);

  // Note that instead of using the nghttp2_session_callbacks_set_send_callback
  // and nghttp2_session_callbacks_set_recv_callback, we manually drive things
  // along via our use of nghttp2_session_mem_recv and
  // nghttp2_session_mem_send.

  nghttp2_session_callbacks_set_on_frame_send_callback(this->_callbacks, on_frame_send_cb);
  nghttp2_session_callbacks_set_on_frame_recv_callback(this->_callbacks, on_frame_recv_cb);
  nghttp2_session_callbacks_set_on_stream_close_callback(this->_callbacks, on_stream_close_cb);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
      this->_callbacks,
      on_data_chunk_recv_cb);

  ret = nghttp2_session_server_new(&this->_session, this->_callbacks, this);
  if (0 != ret) {
    errata.error("nghttp2_session_server_new could not initialize a new session.");
    return errata;
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

void
HttpHeader::global_init()
{
  FIELD_CONTENT_LENGTH = localize_lower("Content-Length"_tv);
  FIELD_TRANSFER_ENCODING = localize_lower("Transfer-Encoding"_tv);
  FIELD_HOST = localize_lower("Host"_tv);

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
RuleCheck::options_init()
{
  options = RuleOptions();

  // Overloaded resolution works with function pointers, but not with
  // std::functions. We have to help out the compiler, therefore, via casting
  // to the correct function type.
  using single_field_function_type = std::shared_ptr<RuleCheck> (*)(swoc::TextView, swoc::TextView);
  options[swoc::TextView(YAML_RULE_EQUALS)] =
      static_cast<single_field_function_type>(make_equality);
  options[swoc::TextView(YAML_RULE_PRESENCE)] =
      static_cast<single_field_function_type>(make_presence);
  options[swoc::TextView(YAML_RULE_ABSENCE)] =
      static_cast<single_field_function_type>(make_absence);
  options[swoc::TextView(YAML_RULE_CONTAINS)] =
      static_cast<single_field_function_type>(make_contains);
  options[swoc::TextView(YAML_RULE_PREFIX)] = static_cast<single_field_function_type>(make_prefix);
  options[swoc::TextView(YAML_RULE_SUFFIX)] = static_cast<single_field_function_type>(make_suffix);

  url_rule_options = URLRuleOptions();
  using url_function_type = std::shared_ptr<RuleCheck> (*)(YamlUrlPart, swoc::TextView);
  url_rule_options[swoc::TextView(YAML_RULE_EQUALS)] =
      static_cast<url_function_type>(make_equality);
  url_rule_options[swoc::TextView(YAML_RULE_PRESENCE)] =
      static_cast<url_function_type>(make_presence);
  url_rule_options[swoc::TextView(YAML_RULE_ABSENCE)] =
      static_cast<url_function_type>(make_absence);
  url_rule_options[swoc::TextView(YAML_RULE_CONTAINS)] =
      static_cast<url_function_type>(make_contains);
  url_rule_options[swoc::TextView(YAML_RULE_PREFIX)] = static_cast<url_function_type>(make_prefix);
  url_rule_options[swoc::TextView(YAML_RULE_SUFFIX)] = static_cast<url_function_type>(make_suffix);

  duplicate_field_options = DuplicateFieldRuleOptions();
  using duplicate_field_function_type =
      std::shared_ptr<RuleCheck> (*)(swoc::TextView, std::vector<swoc::TextView> &&);
  duplicate_field_options[swoc::TextView(YAML_RULE_EQUALS)] =
      static_cast<duplicate_field_function_type>(make_equality);
  duplicate_field_options[swoc::TextView(YAML_RULE_PRESENCE)] =
      static_cast<duplicate_field_function_type>(make_presence);
  duplicate_field_options[swoc::TextView(YAML_RULE_ABSENCE)] =
      static_cast<duplicate_field_function_type>(make_absence);
  duplicate_field_options[swoc::TextView(YAML_RULE_CONTAINS)] =
      static_cast<duplicate_field_function_type>(make_contains);
  duplicate_field_options[swoc::TextView(YAML_RULE_PREFIX)] =
      static_cast<duplicate_field_function_type>(make_prefix);
  duplicate_field_options[swoc::TextView(YAML_RULE_SUFFIX)] =
      static_cast<duplicate_field_function_type>(make_suffix);
}

std::shared_ptr<RuleCheck>
RuleCheck::make_rule_check(
    swoc::TextView localized_name,
    swoc::TextView localized_value,
    swoc::TextView rule_type)
{
  swoc::Errata errata;

  auto fn_iter = options.find(rule_type);
  if (fn_iter == options.end()) {
    errata.info(R"(Invalid Test: Key: "{}")", rule_type);
    return nullptr;
  }
  return fn_iter->second(localized_name, localized_value);
}

std::shared_ptr<RuleCheck>
RuleCheck::make_rule_check(
    YamlUrlPart url_part,
    swoc::TextView localized_value,
    swoc::TextView rule_type)
{
  swoc::Errata errata;

  auto fn_iter = url_rule_options.find(rule_type);
  if (fn_iter == url_rule_options.end()) {
    errata.info(R"(Invalid Test: Key: "{}")", rule_type);
    return nullptr;
  }
  return fn_iter->second(url_part, localized_value);
}

std::shared_ptr<RuleCheck>
RuleCheck::make_rule_check(
    swoc::TextView localized_name,
    std::vector<swoc::TextView> &&localized_values,
    swoc::TextView rule_type)
{
  swoc::Errata errata;

  auto fn_iter = duplicate_field_options.find(rule_type);
  if (fn_iter == duplicate_field_options.end()) {
    errata.info(R"(Invalid Test: Key: "{}")", rule_type);
    return nullptr;
  }
  return fn_iter->second(localized_name, std::move(localized_values));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_equality(swoc::TextView name, swoc::TextView value)
{
  return std::shared_ptr<RuleCheck>(new EqualityCheck(name, value));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_equality(YamlUrlPart url_part, swoc::TextView value)
{
  return std::shared_ptr<RuleCheck>(new EqualityCheck(url_part, value));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_equality(swoc::TextView name, std::vector<swoc::TextView> &&values)
{
  return std::shared_ptr<RuleCheck>(new EqualityCheck(name, std::move(values)));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_presence(swoc::TextView name, swoc::TextView /* value */)
{
  return std::shared_ptr<RuleCheck>(new PresenceCheck(name, !EXPECTS_DUPLICATE_FIELDS));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_presence(YamlUrlPart url_part, swoc::TextView /* value */)
{
  return std::shared_ptr<RuleCheck>(new PresenceCheck(url_part));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_presence(swoc::TextView name, std::vector<swoc::TextView> && /* values */)
{
  return std::shared_ptr<RuleCheck>(new PresenceCheck(name, EXPECTS_DUPLICATE_FIELDS));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_absence(swoc::TextView name, swoc::TextView /* value */)
{
  return std::shared_ptr<RuleCheck>(new AbsenceCheck(name, !EXPECTS_DUPLICATE_FIELDS));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_absence(YamlUrlPart url_part, swoc::TextView /* value */)
{
  return std::shared_ptr<RuleCheck>(new AbsenceCheck(url_part));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_absence(swoc::TextView name, std::vector<swoc::TextView> && /* values */)
{
  return std::shared_ptr<RuleCheck>(new AbsenceCheck(name, EXPECTS_DUPLICATE_FIELDS));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_contains(swoc::TextView name, swoc::TextView value)
{
  return std::shared_ptr<RuleCheck>(new ContainsCheck(name, value));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_contains(YamlUrlPart url_part, swoc::TextView value)
{
  return std::shared_ptr<RuleCheck>(new ContainsCheck(url_part, value));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_contains(swoc::TextView name, std::vector<swoc::TextView> &&values)
{
  return std::shared_ptr<RuleCheck>(new ContainsCheck(name, std::move(values)));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_prefix(swoc::TextView name, swoc::TextView value)
{
  return std::shared_ptr<RuleCheck>(new PrefixCheck(name, value));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_prefix(YamlUrlPart url_part, swoc::TextView value)
{
  return std::shared_ptr<RuleCheck>(new PrefixCheck(url_part, value));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_prefix(swoc::TextView name, std::vector<swoc::TextView> &&values)
{
  return std::shared_ptr<RuleCheck>(new PrefixCheck(name, std::move(values)));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_suffix(swoc::TextView name, swoc::TextView value)
{
  return std::shared_ptr<RuleCheck>(new SuffixCheck(name, value));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_suffix(YamlUrlPart url_part, swoc::TextView value)
{
  return std::shared_ptr<RuleCheck>(new SuffixCheck(url_part, value));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_suffix(swoc::TextView name, std::vector<swoc::TextView> &&values)
{
  return std::shared_ptr<RuleCheck>(new SuffixCheck(name, std::move(values)));
}

EqualityCheck::EqualityCheck(swoc::TextView name, swoc::TextView value)
{
  _name = name;
  _value = value;
  _is_field = true;
}

EqualityCheck::EqualityCheck(YamlUrlPart url_part, swoc::TextView value)
{
  _name = URL_PART_NAMES[url_part];
  _value = value;
  _is_field = false;
}

EqualityCheck::EqualityCheck(swoc::TextView name, std::vector<swoc::TextView> &&values)
{
  _name = name;
  _values = std::move(values);
  _expects_duplicate_fields = true;
  _is_field = true;
}

PresenceCheck::PresenceCheck(swoc::TextView name, bool expects_duplicate_fields)
{
  _name = name;
  _expects_duplicate_fields = expects_duplicate_fields;
  _is_field = true;
}

PresenceCheck::PresenceCheck(YamlUrlPart url_part)
{
  _name = URL_PART_NAMES[url_part];
  _is_field = false;
}

AbsenceCheck::AbsenceCheck(swoc::TextView name, bool expects_duplicate_fields)
{
  _name = name;
  _expects_duplicate_fields = expects_duplicate_fields;
  _is_field = true;
}

AbsenceCheck::AbsenceCheck(YamlUrlPart url_part)
{
  _name = URL_PART_NAMES[url_part];
  _is_field = false;
}

ContainsCheck::ContainsCheck(swoc::TextView name, swoc::TextView value)
{
  _name = name;
  _value = value;
  _is_field = true;
}

ContainsCheck::ContainsCheck(YamlUrlPart url_part, swoc::TextView value)
{
  _name = URL_PART_NAMES[url_part];
  _value = value;
  _is_field = false;
}

ContainsCheck::ContainsCheck(swoc::TextView name, std::vector<swoc::TextView> &&values)
{
  _name = name;
  _values = std::move(values);
  _expects_duplicate_fields = true;
  _is_field = true;
}

PrefixCheck::PrefixCheck(swoc::TextView name, swoc::TextView value)
{
  _name = name;
  _value = value;
  _is_field = true;
}

PrefixCheck::PrefixCheck(YamlUrlPart url_part, swoc::TextView value)
{
  _name = URL_PART_NAMES[url_part];
  _value = value;
  _is_field = false;
}

PrefixCheck::PrefixCheck(swoc::TextView name, std::vector<swoc::TextView> &&values)
{
  _name = name;
  _values = std::move(values);
  _expects_duplicate_fields = true;
  _is_field = true;
}

SuffixCheck::SuffixCheck(swoc::TextView name, swoc::TextView value)
{
  _name = name;
  _value = value;
  _is_field = true;
}

SuffixCheck::SuffixCheck(YamlUrlPart url_part, swoc::TextView value)
{
  _name = URL_PART_NAMES[url_part];
  _value = value;
  _is_field = false;
}

SuffixCheck::SuffixCheck(swoc::TextView name, std::vector<swoc::TextView> &&values)
{
  _name = name;
  _values = std::move(values);
  _expects_duplicate_fields = true;
  _is_field = true;
}

bool
EqualityCheck::test(swoc::TextView key, swoc::TextView name, swoc::TextView value) const
{
  swoc::Errata errata;
  if (name.empty()) {
    errata.info(
        R"(Equals Violation: Absent. Key: "{}", {}: "{}", Correct Value: "{}")",
        key,
        target_type(),
        _name,
        _value);
  } else if (strcmp(value, _value)) {
    errata.info(
        R"(Equals Violation: Different. Key: "{}", {}: "{}", Correct Value: "{}", Actual Value: "{}")",
        key,
        target_type(),
        _name,
        _value,
        value);
  } else {
    errata.info(
        R"(Equals Success: Key: "{}", {}: "{}", Value: "{}")",
        key,
        target_type(),
        _name,
        _value);
    return true;
  }
  return false;
}

bool
EqualityCheck::test(
    swoc::TextView key,
    swoc::TextView name,
    std::vector<swoc::TextView> const &values) const
{
  swoc::Errata errata;
  if (name.empty()) {
    MSG_BUFF message;
    message.print(R"(Equals Violation: Absent. Key: "{}", {}: "{}", )", key, target_type(), _name);
    message.print(R"(Correct Values:)");
    for (auto const &value : _values) {
      message.print(R"( "{}")", value);
    }
  } else if (_values != values) {
    MSG_BUFF message;
    message
        .print(R"(Equals Violation: Different. Key: "{}", {}: "{}", )", key, target_type(), _name);

    message.print(R"(Correct Values:)");
    for (auto const &value : _values) {
      message.print(R"( "{}")", value);
    }
    message.print(R"(, Received Values:)");
    for (auto const &value : values) {
      message.print(R"( "{}")", value);
    }
    errata.info(message.view());
  } else {
    MSG_BUFF message;
    message.print(R"(Equals Success: Key: "{}", {}: "{}", Values:)", key, target_type(), _name);
    for (auto const &value : values) {
      message.print(R"( "{}")", value);
    }
    errata.info(message.view());
    return true;
  }
  return false;
}

bool
PresenceCheck::test(swoc::TextView key, swoc::TextView name, swoc::TextView value) const
{
  swoc::Errata errata;
  if (name.empty()) {
    errata.info(R"(Presence Violation: Absent. Key: "{}", {}: "{}")", key, target_type(), _name);
    return false;
  }
  errata.info(
      R"(Presence Success: Key: "{}", {}: "{}", Value: "{}")",
      key,
      target_type(),
      _name,
      value);
  return true;
}

bool
PresenceCheck::test(
    swoc::TextView key,
    swoc::TextView name,
    std::vector<swoc::TextView> const &values) const
{
  swoc::Errata errata;
  if (name.empty()) {
    errata.info(R"(Presence Violation: Absent. Key: "{}", {}: "{}")", key, target_type(), _name);
    return false;
  }
  MSG_BUFF message;
  message.print(R"(Presence Success: Key: "{}", {}: "{}", Values:)", key, target_type(), _name);
  for (auto const &value : values) {
    message.print(R"( "{}")", value);
  }
  errata.info(message.view());
  return true;
}

bool
AbsenceCheck::test(swoc::TextView key, swoc::TextView name, swoc::TextView value) const
{
  swoc::Errata errata;
  if (!name.empty()) {
    errata.info(
        R"(Absence Violation: Present. Key: "{}", {}: "{}", Value: "{}")",
        key,
        target_type(),
        _name,
        value);
    return false;
  }
  errata.info(R"(Absence Success: Key: "{}", {}: "{}")", key, target_type(), _name);
  return true;
}

bool
AbsenceCheck::test(
    swoc::TextView key,
    swoc::TextView name,
    std::vector<swoc::TextView> const &values) const
{
  swoc::Errata errata;
  if (!name.empty()) {
    MSG_BUFF message;
    message.print(
        R"(Absence Violation: Present. Key: "{}", {}: "{}", Values:)",
        key,
        target_type(),
        _name);
    for (auto const &value : values) {
      message.print(R"( "{}")", value);
    }
    errata.info(message.view());
    return false;
  }
  errata.info(R"(Absence Success: Key: "{}", {}: "{}")", key, target_type(), _name);
  return true;
}

bool
SubstrCheck::test(swoc::TextView key, swoc::TextView name, swoc::TextView value) const
{
  swoc::Errata errata;
  if (name.empty()) {
    errata.info(
        R"({} Violation: Absent. Key: "{}", {}: "{}", Required Value: "{}")",
        get_test_name(),
        key,
        target_type(),
        _name,
        _value);
  } else if (test_tv(value, _value)) {
    errata.info(
        R"({} Violation: Not Found. Key: "{}", {}: "{}", Required Value: "{}", Actual Value: "{}")",
        get_test_name(),
        key,
        target_type(),
        _name,
        _value,
        value);
  } else {
    errata.info(
        R"({} Success: Key: "{}", {}: "{}", Required Value: "{}", Value: "{}")",
        get_test_name(),
        key,
        target_type(),
        _name,
        _value,
        value);
    return true;
  }
  return false;
}

bool
SubstrCheck::test(
    swoc::TextView key,
    swoc::TextView name,
    std::vector<swoc::TextView> const &values) const
{
  swoc::Errata errata;
  if (name.empty() || values.size() != _values.size()) {
    MSG_BUFF message;
    message.print(
        R"({} Violation: Absent/Mismatched. Key: "{}", {}: "{}", )",
        get_test_name(),
        key,
        target_type(),
        _name);
    message.print(R"(Required Values:)");
    for (auto const &value : _values) {
      message.print(R"( "{}")", value);
    }
    message.print(R"(, Received Values:)");
    for (auto const &value : values) {
      message.print(R"( "{}")", value);
    }
    errata.info(message.view());
    return false;
  }
  auto value_it = values.begin();
  auto test_it = _values.begin();
  while (value_it != values.end()) {
    if (test_tv(*value_it, *test_it)) {
      MSG_BUFF message;
      message.print(
          R"({} Violation: Not Found. Key: "{}", {}: "{}", )",
          get_test_name(),
          key,
          target_type(),
          _name);

      message.print(R"(Required Values:)");
      for (auto const &value : _values) {
        message.print(R"( "{}")", value);
      }
      message.print(R"(, Received Values:)");
      for (auto const &value : values) {
        message.print(R"( "{}")", value);
      }
      errata.info(message.view());
      break;
    }
    ++value_it;
    ++test_it;
  }
  MSG_BUFF message;
  message.print(R"({} Success: Key: "{}", {}: "{}", )", get_test_name(), key, target_type(), _name);

  message.print(R"(Required Values:)");
  for (auto const &value : _values) {
    message.print(R"( "{}")", value);
  }
  message.print(R"(, Received Values:)");
  for (auto const &value : values) {
    message.print(R"( "{}")", value);
  }
  errata.info(message.view());
  return true;
}

// Return true for failure, false for success
bool
ContainsCheck::test_tv(swoc::TextView value, swoc::TextView test) const
{
  return (value.find(test) == std::string::npos);
}

bool
PrefixCheck::test_tv(swoc::TextView value, swoc::TextView test) const
{
  return (!value.starts_with(test));
}

bool
SuffixCheck::test_tv(swoc::TextView value, swoc::TextView test) const
{
  return (!value.ends_with(test));
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
    }
  }
  return {};
}

swoc::Errata
HttpHeader::serialize(swoc::BufferWriter &w) const
{
  swoc::Errata errata;

  if (_is_response) {
    w.print("HTTP/{} {} {}{}", _http_version, _status, _reason, HTTP_EOL);
  } else if (_is_request) {
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

swoc::Errata
HttpFields::parse_url_rules(YAML::Node const &url_rules_node, bool assume_equality_rule)
{
  swoc::Errata errata;

  for (auto const &node : url_rules_node) {
    if (!node.IsSequence()) {
      errata.error("URL rule at {} is not a sequence as required.", node.Mark());
      continue;
    }
    const auto node_size = node.size();
    if (node_size != 2 && node_size != 3) {
      errata.error(
          "URL rule node at {} is not a sequence of length 2 "
          "or 3 as required.",
          node.Mark());
      continue;
    }

    TextView part_name{HttpHeader::localize_lower(node[YAML_RULE_KEY_INDEX].Scalar())};
    YamlUrlPart part_id = HttpHeader::parse_url_part(part_name);
    if (part_id == YamlUrlPart::Error) {
      errata.error("URL rule node at {} has an invalid URL part.", node.Mark());
      continue;
    }
    const YAML::Node ValueNode{node[YAML_RULE_VALUE_INDEX]};
    if (ValueNode.IsScalar()) {
      // There's only a single value associated with this URL part.
      TextView value{HttpHeader::localize(node[YAML_RULE_VALUE_INDEX].Scalar())};
      if (node_size == 2 && assume_equality_rule) {
        _url_rules[static_cast<size_t>(part_id)].push_back(
            RuleCheck::make_equality(part_id, value));
      } else if (node_size == 3) {
        // Contains a verification rule.
        TextView rule_type{node[YAML_RULE_TYPE_INDEX].Scalar()};
        std::shared_ptr<RuleCheck> tester = RuleCheck::make_rule_check(part_id, value, rule_type);
        if (!tester) {
          errata.error(
              "URL rule node at {} does not have a valid directive ({})",
              node.Mark(),
              rule_type);
          continue;
        } else {
          _url_rules[static_cast<size_t>(part_id)].push_back(tester);
        }
      }
      // No error reported if incorrect length
    } else if (ValueNode.IsMap()) {
      // Verification is specified as a map, such as:
      // - [ path, { value: config/settings.yaml, as: equal } ]
      TextView value;
      if (auto const url_value_node{ValueNode[YAML_RULE_VALUE_MAP_KEY]}; url_value_node) {
        value = HttpHeader::localize(url_value_node.Scalar());
      }
      if (!ValueNode[YAML_RULE_TYPE_MAP_KEY]) {
        // No verification directive was specified.
        if (assume_equality_rule) {
          _url_rules[static_cast<size_t>(part_id)].push_back(
              RuleCheck::make_equality(part_id, value));
        }
        continue;
      }
      TextView rule_type{ValueNode[YAML_RULE_TYPE_MAP_KEY].Scalar()};
      std::shared_ptr<RuleCheck> tester = RuleCheck::make_rule_check(part_id, value, rule_type);
      if (!tester) {
        errata.error(
            "URL rule node at {} does not have a valid directive ({})",
            node.Mark(),
            rule_type);
        continue;
      } else {
        _url_rules[static_cast<size_t>(part_id)].push_back(tester);
      }
    } else if (ValueNode.IsSequence()) {
      errata.error("URL rule node at {} has multiple values, which is not allowed.", node.Mark());
      continue;
    }
  }
  return errata;
}

swoc::Errata
HttpFields::parse_global_rules(YAML::Node const &node)
{
  swoc::Errata errata;

  if (auto rules_node{node[YAML_FIELDS_KEY]}; rules_node) {
    if (rules_node.IsSequence()) {
      if (rules_node.size() > 0) {
        auto result{this->parse_fields_and_rules(rules_node, !ASSUME_EQUALITY_RULE)};
        if (!result.is_ok()) {
          errata.error("Failed to parse fields and rules at {}", node.Mark());
          errata.note(std::move(result));
        }
      } else {
        errata.info(R"(Fields and rules node at {} is an empty list.)", rules_node.Mark());
      }
    } else {
      errata.info(R"(Fields and rules node at {} is not a sequence.)", rules_node.Mark());
    }
  } else {
    errata.info(R"(Node at {} is missing a fields node.)", node.Mark());
  }
  return errata;
}

swoc::Errata
HttpFields::parse_fields_and_rules(YAML::Node const &fields_rules_node, bool assume_equality_rule)
{
  swoc::Errata errata;

  for (auto const &node : fields_rules_node) {
    if (!node.IsSequence()) {
      errata.error("Field or rule at {} is not a sequence as required.", node.Mark());
      continue;
    }
    auto const node_size = node.size();
    if (node_size != 2 && node_size != 3) {
      errata.error(
          "Field or rule node at {} is not a sequence of length 2 "
          "or 3 as required.",
          node.Mark());
      continue;
    }

    TextView name{HttpHeader::localize_lower(node[YAML_RULE_KEY_INDEX].Scalar())};
    const YAML::Node ValueNode{node[YAML_RULE_VALUE_INDEX]};
    if (ValueNode.IsScalar()) {
      // There's only a single value associated with this field name.
      TextView value{HttpHeader::localize(node[YAML_RULE_VALUE_INDEX].Scalar())};
      add_field(name, value);
      if (node_size == 2 && assume_equality_rule) {
        _rules.emplace(name, RuleCheck::make_equality(name, value));
      } else if (node_size == 3) {
        // Contains a verification rule.
        // -[ Host, example.com, equal ]
        TextView rule_type{node[YAML_RULE_TYPE_INDEX].Scalar()};
        std::shared_ptr<RuleCheck> tester = RuleCheck::make_rule_check(name, value, rule_type);
        if (!tester) {
          errata.error(
              "Field rule at {} does not have a valid directive ({})",
              node.Mark(),
              rule_type);
          continue;
        } else {
          _rules.emplace(name, tester);
        }
      }
    } else if (ValueNode.IsSequence()) {
      // There's a list of values associated with this field. This
      // indicates duplicate fields for the same field name.
      std::vector<TextView> values;
      values.reserve(ValueNode.size());
      for (auto const &value : ValueNode) {
        TextView localized_value{HttpHeader::localize(value.Scalar())};
        values.emplace_back(localized_value);
        add_field(name, localized_value);
      }
      if (node_size == 2 && assume_equality_rule) {
        _rules.emplace(name, RuleCheck::make_equality(name, std::move(values)));
      } else if (node_size == 3) {
        // Contains a verification rule.
        // -[ set-cookie, [ first-cookie, second-cookie ], present ]
        TextView rule_type{node[YAML_RULE_TYPE_INDEX].Scalar()};
        std::shared_ptr<RuleCheck> tester =
            RuleCheck::make_rule_check(name, std::move(values), rule_type);
        if (!tester) {
          errata.error(
              "Field rule at {} does not have a valid directive ({})",
              node.Mark(),
              rule_type);
          continue;
        } else {
          _rules.emplace(name, tester);
        }
      }
    } else if (ValueNode.IsMap()) {
      // Verification is specified as a map, such as:
      // -[ Host, { value: example.com, as: equal } ]
      TextView value;
      if (auto const field_value_node{ValueNode[YAML_RULE_VALUE_MAP_KEY]}; field_value_node) {
        if (field_value_node.IsScalar()) {
          value = HttpHeader::localize(field_value_node.Scalar());
          add_field(name, value);
        } else if (field_value_node.IsSequence()) {
          // Verification is for duplicate fields:
          // -[ set-cookie, { value: [ cookiea, cookieb], as: equal } ]
          std::vector<TextView> values;
          values.reserve(ValueNode.size());
          for (auto const &value : field_value_node) {
            TextView localized_value{HttpHeader::localize(value.Scalar())};
            values.emplace_back(localized_value);
            add_field(name, localized_value);
          }
          if (auto const rule_type_node{ValueNode[YAML_RULE_TYPE_MAP_KEY]}; rule_type_node) {
            TextView rule_type{rule_type_node.Scalar()};
            std::shared_ptr<RuleCheck> tester =
                RuleCheck::make_rule_check(name, std::move(values), rule_type);
            if (!tester) {
              errata.error(
                  "Field rule at {} does not have a valid directive ({})",
                  node.Mark(),
                  rule_type);
              continue;
            } else {
              _rules.emplace(name, tester);
            }
          } else {
            // No verification directive was specified.
            if (assume_equality_rule) {
              _rules.emplace(name, RuleCheck::make_equality(name, std::move(values)));
            }
          }
          continue;
        }
      }
      if (auto const rule_type_node{ValueNode[YAML_RULE_TYPE_MAP_KEY]}; rule_type_node) {
        TextView rule_type{rule_type_node.Scalar()};
        std::shared_ptr<RuleCheck> tester = RuleCheck::make_rule_check(name, value, rule_type);
        if (!tester) {
          errata.error(
              "Field rule at {} does not have a valid directive ({})",
              node.Mark(),
              rule_type);
          continue;
        } else {
          _rules.emplace(name, tester);
        }
      } else {
        // No verification directive was specified.
        if (assume_equality_rule) {
          _rules.emplace(name, RuleCheck::make_equality(name, value));
        }
        continue;
      }
    }
  }
  return errata;
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
    uri_scheme = this->localize(url.substr(0, scheme_end));
  }
  uri_host = this->localize(url.substr(host_start, host_end - host_start));
  if (port_start != std::string::npos) {
    uri_port = this->localize(url.substr(port_start, port_end - port_start));
  } else {
    port_end = host_end;
  }
  uri_authority = this->localize(url.substr(host_start, port_end - host_start));
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
    uri_path = this->localize(url.substr(path_start, path_end - path_start));
  }
  if (query_start != std::string::npos) {
    uri_query = this->localize(url.substr(query_start, query_end - query_start));
  }
  if (fragment_start != std::string::npos) {
    uri_fragment = this->localize(url.substr(fragment_start, fragment_end - fragment_start));
  }

  _fields_rules->_url_parts[static_cast<size_t>(YamlUrlPart::Scheme)] = uri_scheme;
  _fields_rules->_url_parts[static_cast<size_t>(YamlUrlPart::Host)] = uri_host;
  _fields_rules->_url_parts[static_cast<size_t>(YamlUrlPart::Port)] = uri_port;
  _fields_rules->_url_parts[static_cast<size_t>(YamlUrlPart::Authority)] = uri_authority;
  _fields_rules->_url_parts[static_cast<size_t>(YamlUrlPart::Path)] = uri_path;
  _fields_rules->_url_parts[static_cast<size_t>(YamlUrlPart::Query)] = uri_query;
  _fields_rules->_url_parts[static_cast<size_t>(YamlUrlPart::Fragment)] = uri_fragment;

  // Non-URI parsing
  // Split out the path and scheme for http/2 required headers
  // See rfc3986 section-3.2.
  std::size_t end_scheme = url.find("://");
  std::size_t start_auth = 0;
  if (end_scheme == std::string::npos) {
    start_auth = 0;
  } else {
    start_auth = end_scheme + 3; // "://" is 3 characters.
    _scheme = this->localize(url.substr(0, end_scheme));
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
  _authority = this->localize(url.substr(start_auth, end_host - start_auth));
  // _path is the value used for HTTP/2 ':path' and thus includes everything past
  // the authority.
  if (end_host != url.length()) {
    _path = this->localize(url.substr(end_host));
  }
  return errata;
}

YamlUrlPart
HttpHeader::parse_url_part(swoc::TextView name)
{
  return URL_PART_NAMES[name];
}

swoc::Errata
HttpHeader::process_pseudo_headers(YAML::Node const &node)
{
  swoc::Errata errata;
  auto number_of_pseudo_headers = 0;
  auto pseudo_it = _fields_rules->_fields.find(YAML_HTTP2_PSEUDO_METHOD_KEY);
  if (pseudo_it != _fields_rules->_fields.end()) {
    if (!_method.empty()) {
      errata.error(
          "The {} node is not compatible with the {} pseudo header: {}",
          YAML_HTTP_METHOD_KEY,
          YAML_HTTP2_PSEUDO_METHOD_KEY,
          node.Mark());
    }
    _method = pseudo_it->second;
    ++number_of_pseudo_headers;
    _is_request = true;
  }
  pseudo_it = _fields_rules->_fields.find(YAML_HTTP2_PSEUDO_SCHEME_KEY);
  if (pseudo_it != _fields_rules->_fields.end()) {
    if (!_scheme.empty()) {
      errata.error(
          "The {} node is not compatible with the {} pseudo header: {}",
          YAML_HTTP_SCHEME_KEY,
          YAML_HTTP2_PSEUDO_SCHEME_KEY,
          node.Mark());
    }
    _scheme = pseudo_it->second;
    ++number_of_pseudo_headers;
    _is_request = true;
  }
  pseudo_it = _fields_rules->_fields.find(YAML_HTTP2_PSEUDO_AUTHORITY_KEY);
  if (pseudo_it != _fields_rules->_fields.end()) {
    auto const host_it = _fields_rules->_fields.find(FIELD_HOST);
    if (host_it != _fields_rules->_fields.end()) {
      // We intentionally allow this, even though contrary to spec, to allow the use
      // of Proxy Verifier to test proxy's handling of this.
      errata.info(
          "Contrary to spec, a transaction is specified with both {} and {} header fields: {}",
          YAML_HTTP2_PSEUDO_AUTHORITY_KEY,
          FIELD_HOST,
          node.Mark());
    } else if (!_authority.empty()) {
      errata.error(
          "The {} node is not compatible with the {} pseudo header: {}",
          YAML_HTTP_URL_KEY,
          YAML_HTTP2_PSEUDO_AUTHORITY_KEY,
          node.Mark());
    }
    _authority = pseudo_it->second;
    ++number_of_pseudo_headers;
    _is_request = true;
  }
  pseudo_it = _fields_rules->_fields.find(YAML_HTTP2_PSEUDO_PATH_KEY);
  if (pseudo_it != _fields_rules->_fields.end()) {
    if (!_path.empty()) {
      errata.error(
          "The {} node is not compatible with the {} pseudo header: {}",
          YAML_HTTP_URL_KEY,
          YAML_HTTP2_PSEUDO_PATH_KEY,
          node.Mark());
    }
    _path = pseudo_it->second;
    ++number_of_pseudo_headers;
    _is_request = true;
  }
  pseudo_it = _fields_rules->_fields.find(YAML_HTTP2_PSEUDO_STATUS_KEY);
  if (pseudo_it != _fields_rules->_fields.end()) {
    if (_status != 0) {
      errata.error(
          "The {} node is not compatible with the {} pseudo header: {}",
          YAML_HTTP_STATUS_KEY,
          YAML_HTTP2_PSEUDO_STATUS_KEY,
          node.Mark());
    }
    auto const &status_field_value = pseudo_it->second;
    TextView parsed;
    auto n = swoc::svtou(status_field_value, &parsed);
    if (parsed.size() == status_field_value.size() && 0 < n && n <= 599) {
      _status = n;
      _status_string = std::to_string(_status);
    } else {
      errata.error(
          R"("{}" pseudo header value "{}" at {} must be an integer in the range [1..599].)",
          YAML_HTTP2_PSEUDO_STATUS_KEY,
          status_field_value,
          node.Mark());
    }
    ++number_of_pseudo_headers;
    _is_response = true;
  }
  if (number_of_pseudo_headers > 0) {
    // Do some sanity checking on the user's pseudo headers, if provided.
    if (_is_response && number_of_pseudo_headers != 1) {
      errata.error("Found a mixture of request and response pseudo header fields: {}", node.Mark());
    }
    if (_is_request && number_of_pseudo_headers != 4) {
      errata.error(
          "Did not find all four required pseudo header fields "
          "(:method, :scheme, :authority, :path): {}",
          node.Mark());
    }
    // Pseudo header fields currently implies HTTP/2.
    _http_version = "2";
    _contains_pseudo_headers_in_fields_array = true;
  }
  return errata;
}

swoc::Errata
HttpHeader::load(YAML::Node const &node)
{
  swoc::Errata errata;

  if (node[YAML_HTTP_VERSION_KEY]) {
    _http_version = this->localize_lower(node[YAML_HTTP_VERSION_KEY].Scalar());
  } else {
    _http_version = "1.1";
  }
  if (node[YAML_HTTP2_KEY]) {
    auto http2_node{node[YAML_HTTP2_KEY]};
    if (http2_node.IsMap()) {
      if (http2_node[YAML_HTTP_STREAM_ID_KEY]) {
        auto http_stream_id_node{http2_node[YAML_HTTP_STREAM_ID_KEY]};
        if (http_stream_id_node.IsScalar()) {
          TextView text{http_stream_id_node.Scalar()};
          TextView parsed;
          auto n = swoc::svtou(text, &parsed);
          if (parsed.size() == text.size() && 0 < n) {
            _stream_id = n;
          } else {
            errata.error(
                R"("{}" value "{}" at {} must be a positive integer.)",
                YAML_HTTP_STREAM_ID_KEY,
                text,
                http_stream_id_node.Mark());
          }
        } else {
          errata.error(
              R"("{}" at {} must be a positive integer.)",
              YAML_HTTP_STREAM_ID_KEY,
              http_stream_id_node.Mark());
        }
      }
    } else {
      errata.error(
          R"("{}" value at {} must be a map of HTTP/2 values.)",
          YAML_HTTP2_KEY,
          http2_node.Mark());
    }
  }

  if (node[YAML_HTTP_STATUS_KEY]) {
    _is_response = true;
    auto status_node{node[YAML_HTTP_STATUS_KEY]};
    if (status_node.IsScalar()) {
      TextView text{status_node.Scalar()};
      TextView parsed;
      auto n = swoc::svtou(text, &parsed);
      if (parsed.size() == text.size() && 0 < n && n <= 599) {
        _status = n;
        _status_string = std::to_string(_status);
      } else {
        errata.error(
            R"("{}" value "{}" at {} must be an integer in the range [1..599].)",
            YAML_HTTP_STATUS_KEY,
            text,
            status_node.Mark());
      }
    } else {
      errata.error(
          R"("{}" value at {} must be an integer in the range [1..599].)",
          YAML_HTTP_STATUS_KEY,
          status_node.Mark());
    }
  }

  if (node[YAML_HTTP_REASON_KEY]) {
    auto reason_node{node[YAML_HTTP_REASON_KEY]};
    if (reason_node.IsScalar()) {
      _reason = this->localize(reason_node.Scalar());
    } else {
      errata.error(
          R"("{}" value at {} must be a string.)",
          YAML_HTTP_REASON_KEY,
          reason_node.Mark());
    }
  }

  if (node[YAML_HTTP_METHOD_KEY]) {
    auto method_node{node[YAML_HTTP_METHOD_KEY]};
    if (method_node.IsScalar()) {
      _method = this->localize(method_node.Scalar());
      _is_request = true;
    } else {
      errata.error(
          R"("{}" value at {} must be a string.)",
          YAML_HTTP_REASON_KEY,
          method_node.Mark());
    }
  }

  if (node[YAML_HTTP_URL_KEY]) {
    auto url_node{node[YAML_HTTP_URL_KEY]};
    if (url_node.IsScalar()) {
      _url = this->localize(url_node.Scalar());
      this->parse_url(_url);
    } else if (url_node.IsSequence()) {
      _fields_rules->parse_url_rules(url_node, _verify_strictly);
    } else {
      errata.error(
          R"("{}" value at {} must be a string or sequence.)",
          YAML_HTTP_URL_KEY,
          url_node.Mark());
    }
  }

  if (node[YAML_HTTP_SCHEME_KEY]) {
    auto scheme_node{node[YAML_HTTP_SCHEME_KEY]};
    if (scheme_node.IsScalar()) {
      _scheme = this->localize(scheme_node.Scalar());
    } else {
      errata.error(
          R"("{}" value at {} must be a string.)",
          YAML_HTTP_SCHEME_KEY,
          scheme_node.Mark());
    }
  }

  if (node[YAML_HDR_KEY]) {
    auto hdr_node{node[YAML_HDR_KEY]};
    if (hdr_node[YAML_FIELDS_KEY]) {
      auto field_list_node{hdr_node[YAML_FIELDS_KEY]};
      swoc::Errata result =
          _fields_rules->parse_fields_and_rules(field_list_node, _verify_strictly);
      if (result.is_ok()) {
        errata.note(this->update_content_length(_method));
        errata.note(this->update_transfer_encoding());
      } else {
        errata.error("Failed to parse response at {}", node.Mark());
        errata.note(std::move(result));
      }
    }
  }

  errata.note(this->process_pseudo_headers(node));

  if (!_method.empty() && _authority.empty()) {
    // The URL didn't have the authority. Get it from the Host header if it
    // exists.
    auto const it = _fields_rules->_fields.find(FIELD_HOST);
    if (it != _fields_rules->_fields.end()) {
      _authority = it->second;
    }
  }

  // Do this after parsing fields so it can override transfer encoding.
  if (auto content_node{node[YAML_CONTENT_KEY]}; content_node) {
    if (content_node.IsMap()) {
      if (auto xf_node{content_node[YAML_CONTENT_TRANSFER_KEY]}; xf_node) {
        TextView xf{xf_node.Scalar()};
        if (0 == strcasecmp("chunked"_tv, xf)) {
          _chunked_p = true;
        } else if (0 == strcasecmp("plain"_tv, xf)) {
          _chunked_p = false;
        } else {
          errata.error(
              R"(Invalid value "{}" for "{}" key at {} in "{}" node at {})",
              xf,
              YAML_CONTENT_TRANSFER_KEY,
              xf_node.Mark(),
              YAML_CONTENT_KEY,
              content_node.Mark());
        }
      }
      if (auto data_node{content_node[YAML_CONTENT_DATA_KEY]}; data_node) {
        Encoding enc{Encoding::TEXT};
        if (auto enc_node{content_node[YAML_CONTENT_ENCODING_KEY]}; enc_node) {
          TextView text{enc_node.Scalar()};
          if (0 == strcasecmp("uri"_tv, text)) {
            enc = Encoding::URI;
          } else if (0 == strcasecmp("plain"_tv, text)) {
            enc = Encoding::TEXT;
          } else {
            errata.error(R"(Unknown encoding "{}" at {}.)", text, enc_node.Mark());
          }
        }
        TextView content{this->localize(data_node.Scalar(), enc)};
        _content_data = content.data();
        const size_t content_size = content.size();
        _recorded_content_size = content_size;
        if (_content_length_p) {
          if (_content_size != content_size) {
            errata.diag(
                R"(Conflicting sizes for "Content-Length", sending header value {} instead of data value {}.)",
                _content_size,
                content_size);
          }
        }
      } else if (auto size_node{content_node[YAML_CONTENT_SIZE_KEY]}; size_node) {
        const size_t content_size = swoc::svtou(size_node.Scalar());
        _recorded_content_size = content_size;
        // Cross check against previously read content-length header, if any.
        if (_content_length_p) {
          if (_content_size != content_size) {
            errata.diag(
                R"(Conflicting sizes for "Content-Length", sending header value {} instead of rule value {}.)",
                _content_size,
                content_size);
          }
        } else if (_chunked_p) {
          _content_size = content_size;
        } else if (_is_http2) {
          // HTTP/2 transactions may, and likely won't, have a Content-Length
          // header field. And chunked encoding is not allowed in HTTP/2.
          _content_size = content_size;
        }
      } else {
        errata.error(
            R"("{}" node at {} does not have a "{}" or "{}" key as required.)",
            YAML_CONTENT_KEY,
            node.Mark(),
            YAML_CONTENT_SIZE_KEY,
            YAML_CONTENT_DATA_KEY);
      }
    } else {
      errata.error(R"("{}" node at {} is not a map.)", YAML_CONTENT_KEY, content_node.Mark());
    }
  }

  // After everything has been read, there should be enough information now to
  // derive a key.
  derive_key();

  return errata;
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
        if (!rule_check->test(transaction_key, URL_PART_NAMES[static_cast<YamlUrlPart>(i)], value))
        {
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

swoc::TextView
HttpHeader::localize(char const *text)
{
  return self_type::localize_helper(TextView{text, strlen(text) + 1}, !SHOULD_LOWER);
}

swoc::TextView
HttpHeader::localize_lower(char const *text)
{
  return self_type::localize_lower(TextView{text, strlen(text) + 1});
}

swoc::TextView
HttpHeader::localize(TextView text)
{
  return HttpHeader::localize_helper(text, !SHOULD_LOWER);
}

swoc::TextView
HttpHeader::localize_lower(TextView text)
{
  // _names.find() does a case insensitive lookup, so cache lookup via _names
  // only should be used for case-insensitive localization. It's value applies
  // to well-known, common strings such as HTTP headers.
  auto spot = _names.find(text);
  if (spot != _names.end()) {
    return *spot;
  }
  return HttpHeader::localize_helper(text, SHOULD_LOWER);
}

swoc::TextView
HttpHeader::localize_helper(TextView text, bool should_lower)
{
  if (!_frozen) {
    auto span{_arena.alloc(text.size()).rebind<char>()};
    if (should_lower) {
      std::transform(text.begin(), text.end(), span.begin(), &tolower);
    } else {
      std::copy(text.begin(), text.end(), span.begin());
    }
    TextView local{span.data(), text.size()};
    if (should_lower) {
      _names.insert(local);
    }
    return local;
  }
  return text;
}

swoc::TextView
HttpHeader::localize(TextView text, Encoding enc)
{
  if (Encoding::URI == enc) {
    auto span{_arena.require(text.size()).remnant().rebind<char>()};
    auto spot = text.begin(), limit = text.end();
    char *dst = span.begin();
    while (spot < limit) {
      if (*spot == '%' &&
          (spot + 1 < limit && isxdigit(spot[1]) && (spot + 2 < limit && isxdigit(spot[2]))))
      {
        *dst++ = swoc::svto_radix<16>(TextView{spot + 1, spot + 3});
        spot += 3;
      } else {
        *dst++ = *spot++;
      }
    }
    TextView text{span.data(), dst};
    _arena.alloc(text.size());
    return text;
  }
  return self_type::localize(text);
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
      _is_request = true;

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
      _is_response = true;

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
    bwformat(w, spec, _hdr._url);
  } else {
    bwformat(w, spec, TRANSACTION_KEY_NOT_SET);
  }
  return w;
}

namespace swoc
{
inline namespace SWOC_VERSION_NS
{
BufferWriter &
bwformat(BufferWriter &w, bwf::Spec const & /* spec */, HttpHeader const &h)
{
  if (h._is_http2) {
    if (h._status) {
      w.print(R"(- ":status": "{}"{})", h._status_string, '\n');
    } else {
      w.print(R"(- ":method": "{}"{})", h._method, '\n');
      w.print(R"(- ":scheme": "{}"{})", h._scheme, '\n');
      w.print(R"(- ":authority": "{}"{})", h._authority, '\n');
      w.print(R"(- ":path": "{}"{})", h._path, '\n');
    }
  } else {
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

BufferWriter &
bwformat(BufferWriter &w, bwf::Spec const & /* spec */, std::chrono::milliseconds const &s)
{
  w.print("{} milliseconds", s.count());
  return w;
}

BufferWriter &
bwformat(BufferWriter &w, bwf::Spec const &spec, bwf::SSLError const &error)
{
  // Hand rolled, might not be totally compliant everywhere, but probably close
  // enough. The long string will be locally accurate. Clang requires the double
  // braces.
  static const std::array<std::string_view, 11> SHORT_NAME = {{
      "SSL_ERROR_NONE: ",
      "SSL_ERROR_SSL: ",
      "SSL_ERROR_WANT_READ: ",
      "SSL_ERROR_WANT_WRITE: ",
      "SSL_ERROR_WANT_X509_LOOKUP: ",
      "SSL_ERROR_SYSCALL: ",
      "SSL_ERROR_ZERO_RETURN: ",
      "SSL_ERROR_WANT_CONNECT: ",
      "SSL_ERROR_WANT_ACCEPT: ",
      "SSL_ERROR_WANT_ASYNC: ",
      "SSL_ERROR_WANT_ASYNC_JOB: ",
  }};

  auto short_name = [](int n) {
    return 0 <= n && n < int(SHORT_NAME.size()) ? SHORT_NAME[n] : "Unknown: "sv;
  };
  static const bwf::Format number_fmt{"[{}]"sv}; // numeric value format.
  if (spec.has_numeric_type()) {                 // if numeric type, print just the numeric
                                                 // part.
    w.print(number_fmt, error._e);
  } else {
    w.write(short_name(error._e));
    auto const &error_reason = ERR_reason_error_string(error._e);
    if (error_reason != nullptr) {
      w.write(ERR_reason_error_string(error._e));
    }
    if (spec._type != 's' && spec._type != 'S') {
      w.write(' ');
      w.print(number_fmt, error._e);
    }
  }
  return w;
}
} // namespace SWOC_VERSION_NS
} // namespace swoc

/** RAII for managing the handler's file. */
struct HandlerOpener
{
public:
  swoc::Errata errata;

public:
  HandlerOpener(ReplayFileHandler &handler, swoc::file::path const &path) : _handler(handler)
  {
    errata.note(_handler.file_open(path));
  }
  ~HandlerOpener()
  {
    errata.note(_handler.file_close());
  }

private:
  ReplayFileHandler &_handler;
};

swoc::Errata
Load_Replay_File(swoc::file::path const &path, ReplayFileHandler &handler)
{
  HandlerOpener opener(handler, path);
  auto errata = opener.errata;
  if (!errata.is_ok()) {
    return errata;
  }
  std::error_code ec;
  std::string content{swoc::file::load(path, ec)};
  if (ec.value()) {
    errata.error(R"(Error loading "{}": {})", path, ec);
    return errata;
  }
  YAML::Node root;
  auto global_fields_rules = std::make_shared<HttpFields>();
  try {
    root = YAML::Load(content);
    yaml_merge(root);
  } catch (std::exception const &ex) {
    errata.error(R"(Exception: {} in "{}".)", ex.what(), path);
  }
  if (!errata.is_ok()) {
    return errata;
  }
  if (root[YAML_META_KEY]) {
    auto meta_node{root[YAML_META_KEY]};
    if (meta_node[YAML_GLOBALS_KEY]) {
      auto globals_node{meta_node[YAML_GLOBALS_KEY]};
      // Path not passed to later calls than Load_Replay_File.
      errata.note(global_fields_rules->parse_global_rules(globals_node));
    }
  } else {
    errata.info(R"(No meta node ("{}") at "{}":{}.)", YAML_META_KEY, path, root.Mark().line);
  }
  handler.global_config = VerificationConfig{global_fields_rules};
  if (!root[YAML_SSN_KEY]) {
    errata.error(R"(No sessions list ("{}") at "{}":{}.)", YAML_META_KEY, path, root.Mark().line);
    return errata;
  }
  auto ssn_list_node{root[YAML_SSN_KEY]};
  if (!ssn_list_node.IsSequence()) {
    errata.error(
        R"("{}" value at "{}":{} is not a sequence.)",
        YAML_SSN_KEY,
        path,
        ssn_list_node.Mark());
    return errata;
  }
  if (ssn_list_node.size() == 0) {
    errata.diag(R"(Session list at "{}":{} is an empty list.)", path, ssn_list_node.Mark().line);
    return errata;
  }
  for (auto const &ssn_node : ssn_list_node) {
    // HeaderRules ssn_rules = global_rules;
    auto session_errata{handler.ssn_open(ssn_node)};
    if (!session_errata.is_ok()) {
      errata.note(std::move(session_errata));
      errata.error(R"(Failure opening session at "{}":{}.)", path, ssn_node.Mark().line);
      continue;
    }
    if (!ssn_node[YAML_TXN_KEY]) {
      errata.error(
          R"(Session at "{}":{} has no "{}" key.)",
          path,
          ssn_node.Mark().line,
          YAML_TXN_KEY);
      continue;
    }
    auto txn_list_node{ssn_node[YAML_TXN_KEY]};
    if (!txn_list_node.IsSequence()) {
      session_errata.error(
          R"(Transaction list at {} in session at {} in "{}" is not a list.)",
          txn_list_node.Mark(),
          ssn_node.Mark(),
          path);
    }
    if (txn_list_node.size() == 0) {
      session_errata.info(
          R"(Transaction list at {} in session at {} in "{}" is an empty list.)",
          txn_list_node.Mark(),
          ssn_node.Mark(),
          path);
    }
    for (auto const &txn_node : txn_list_node) {
      // HeaderRules txn_rules = ssn_rules;
      auto txn_errata = handler.txn_open(txn_node);
      if (!txn_errata.is_ok()) {
        session_errata.error(R"(Could not open transaction at {} in "{}".)", txn_node.Mark(), path);
      }
      HttpFields all_fields;
      if (auto all_node{txn_node[YAML_ALL_MESSAGES_KEY]}; all_node) {
        if (auto headers_node{all_node[YAML_HDR_KEY]}; headers_node) {
          txn_errata.note(all_fields.parse_global_rules(headers_node));
        }
      }
      if (auto creq_node{txn_node[YAML_CLIENT_REQ_KEY]}; creq_node) {
        txn_errata.note(handler.client_request(creq_node));
      }
      if (auto preq_node{txn_node[YAML_PROXY_REQ_KEY]}; preq_node) { // global_rules appears to be
                                                                     // being copied
        txn_errata.note(handler.proxy_request(preq_node));
      }
      if (auto ursp_node{txn_node[YAML_SERVER_RSP_KEY]}; ursp_node) {
        txn_errata.note(handler.server_response(ursp_node));
      }
      if (auto prsp_node{txn_node[YAML_PROXY_RSP_KEY]}; prsp_node) {
        txn_errata.note(handler.proxy_response(prsp_node));
      }
      if (!all_fields._fields.empty()) {
        txn_errata.note(handler.apply_to_all_messages(all_fields));
      }
      txn_errata.note(handler.txn_close());
      if (!txn_errata.is_ok()) {
        txn_errata.error(R"(Failure with transaction at {} in "{}".)", txn_node.Mark(), path);
      }
      session_errata.note(std::move(txn_errata));
    }
    session_errata.note(handler.ssn_close());
    errata.note(std::move(session_errata));
  }
  return errata;
}

swoc::Errata
Load_Replay_Directory(
    swoc::file::path const &path,
    swoc::Errata (*loader)(swoc::file::path const &),
    int n_threads)
{
  swoc::Errata errata;
  std::mutex local_mutex;
  std::error_code ec;

  dirent **elements = nullptr;

  auto stat{swoc::file::status(path, ec)};
  if (ec) {
    return Errata().error(R"(Invalid test directory "{}": [{}])", path, ec);
  } else if (swoc::file::is_regular_file(stat)) {
    return loader(path);
  } else if (!swoc::file::is_dir(stat)) {
    return Errata().error(R"("{}" is not a file or a directory.)", path);
  }

  if (0 == chdir(path.c_str())) {
    int n_sessions = scandir(
        ".",
        &elements,
        [](dirent const *entry) -> int {
          auto extension = swoc::TextView{entry->d_name, strlen(entry->d_name)}.suffix_at('.');
          return 0 == strcasecmp(extension, "json") || 0 == strcasecmp(extension, "yaml");
        },
        &alphasort);
    if (n_sessions > 0) {
      std::atomic<int> idx{0};
      swoc::MemSpan<dirent *> entries{elements, static_cast<size_t>(n_sessions)};

      // Lambda suitable to spawn in a thread to load files.
      auto load_wrapper = [&]() -> void {
        size_t k = 0;
        while ((k = idx++) < entries.count()) {
          auto result = (*loader)(swoc::file::path{entries[k]->d_name});
          std::lock_guard<std::mutex> lock(local_mutex);
          errata.note(result);
        }
      };

      errata.info("Loading {} replay files.", n_sessions);
      std::vector<std::thread> threads;
      threads.reserve(n_threads);
      for (int tidx = 0; tidx < n_threads; ++tidx) {
        threads.emplace_back(load_wrapper);
      }
      for (std::thread &thread : threads) {
        thread.join();
      }
      for (int i = 0; i < n_sessions; i++) {
        free(elements[i]);
      }
      free(elements);

    } else {
      errata.error(R"(No replay files found in "{}".)", path);
    }
  } else {
    errata.error(R"(Failed to access directory "{}": {}.)", path, swoc::bwf::Errno{});
  }
  return errata;
}

swoc::Errata
parse_ips(std::string arg, std::deque<swoc::IPEndpoint> &target)
{
  swoc::Errata errata;
  size_t offset = 0;
  size_t new_offset = 0;
  while (offset != std::string::npos) {
    new_offset = arg.find(',', offset);
    std::string name = arg.substr(offset, new_offset - offset);
    offset = new_offset != std::string::npos ? new_offset + 1 : new_offset;
    swoc::IPEndpoint addr;
    if (!addr.parse(name)) {
      errata.error(R"("{}" is not a valid IP address.)", name);
      return errata;
    }
    target.push_back(addr);
  }
  return errata;
}

swoc::Errata
resolve_ips(std::string arg, std::deque<swoc::IPEndpoint> &target)
{
  swoc::Errata errata;
  size_t offset = 0;
  size_t new_offset = 0;
  while (offset != std::string::npos) {
    new_offset = arg.find(',', offset);
    std::string name = arg.substr(offset, new_offset - offset);
    offset = new_offset != std::string::npos ? new_offset + 1 : new_offset;
    auto &&[tmp_target, result] = Resolve_FQDN(name);
    if (!result.is_ok()) {
      errata.error(R"("{}" is not a valid IP address.)", name);
      return errata;
    }
    target.push_back(tmp_target);
  }
  return errata;
}

swoc::Rv<swoc::IPEndpoint>
Resolve_FQDN(swoc::TextView fqdn)
{
  swoc::Rv<swoc::IPEndpoint> zret;
  swoc::TextView host_str, port_str;
  in_port_t port = 0;
  static constexpr in_port_t MAX_PORT{std::numeric_limits<in_port_t>::max()};

  if (swoc::IPEndpoint::tokenize(fqdn, &host_str, &port_str)) {
    swoc::IPAddr addr;
    if (port_str) {
      swoc::TextView text(port_str);
      auto n = swoc::svto_radix<10>(text);
      if (text.empty() && 0 < n && n <= MAX_PORT) {
        port = htons(n);
        if (addr.load(host_str)) {
          zret.result().assign(addr, port);
        } else {
          addrinfo *addrs = nullptr;
          addrinfo hints;
          char buff[host_str.size() + 1];
          memcpy(buff, host_str.data(), host_str.size());
          buff[host_str.size()] = '\0';
          hints.ai_family = AF_UNSPEC;
          hints.ai_socktype = SOCK_STREAM;
          hints.ai_protocol = IPPROTO_TCP;
          hints.ai_flags = 0;
          auto result = getaddrinfo(buff, nullptr, &hints, &addrs);
          if (0 == result) {
            zret.result().assign(addrs->ai_addr);
            zret.result().port() = port;
            freeaddrinfo(addrs);
          } else {
            zret.error(R"(Failed to resolve "{}": {}.)", host_str, swoc::bwf::Errno(result));
          }
        }
      } else {
        zret.error(R"(Port value {} out of range [ 1 .. {} ].)", port_str, MAX_PORT);
      }
    } else {
      zret.error(R"(Address "{}" does not have the require port specifier.)", fqdn);
    }

  } else {
    zret.error(R"(Malformed address "{}".)", fqdn);
  }
  return zret;
}

void
ThreadPool::wait_for_work(ThreadInfo *thread_info)
{
  // ready to roll, add to the pool.
  {
    std::unique_lock<std::mutex> lock(_threadPoolMutex);
    _threadPool.push_back(thread_info);
    _threadPoolCvar.notify_all();
  }

  // wait for a notification there's a session to process.
  {
    std::unique_lock<std::mutex> lock(thread_info->_mutex);
    while (!thread_info->data_ready()) {
      thread_info->_cvar.wait_for(lock, 100ms);
    }
  }
}

ThreadInfo *
ThreadPool::get_worker()
{
  ThreadInfo *thread_info = nullptr;
  {
    std::unique_lock<std::mutex> lock(this->_threadPoolMutex);
    while (_threadPool.size() == 0) {
      if (_allThreads.size() > max_threads) {
        // Just sleep until a thread comes back
        _threadPoolCvar.wait(lock);
      } else { // Make a new thread
        // This is circuitous, but we do this so that the thread can put a
        // pointer to it's @c std::thread in it's info. Note the circular
        // dependency: there's no object until after the constructor is called
        // but the constructor needs to be called to get the object. Sigh.
        std::thread *t = &_allThreads.emplace_back();
        *t = this->make_thread(t);
        _threadPoolCvar.wait(lock); // expect the new thread to enter
                                    // itself in the pool and signal.
      }
    }
    thread_info = _threadPool.front();
    _threadPool.pop_front();
  }
  return thread_info;
}

void
ThreadPool::join_threads()
{
  for (auto &thread : _allThreads) {
    thread.join();
  }
}

void
ThreadPool::set_max_threads(size_t new_max)
{
  max_threads = new_max;
}
