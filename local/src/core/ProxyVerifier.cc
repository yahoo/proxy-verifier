/** @file
 * Common implementation for Proxy Verifier
 *
 * Copyright 2020, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "core/ProxyVerifier.h"
#include "core/yaml_util.h"

#include <algorithm>
#include <dirent.h>
#include <netdb.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include <signal.h>

#include <fcntl.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#include "swoc/bwf_ex.h"
#include "swoc/bwf_std.h"
#include "swoc/bwf_ip.h"

using swoc::Errata;
using swoc::TextView;
using namespace swoc::literals;
using namespace std::literals;
namespace chrono = std::chrono;
using clock_type = chrono::system_clock;

constexpr auto Transaction_Delay_Cutoff = 500ms;

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
RuleCheck::DuplicateFieldRuleOptions RuleCheck::duplicate_field_options;

static ssize_t send_callback(nghttp2_session *session, const uint8_t *inputdata,
                             size_t length, int flags, void *user_data);
static ssize_t recv_callback(nghttp2_session *session, uint8_t *buf,
                             size_t length, int flags, void *user_data);

namespace {
[[maybe_unused]] bool INITIALIZED = []() -> bool {
  HttpHeader::global_init();
  return true;
}();
}

swoc::Rv<int> block_sigpipe() {
  swoc::Rv<int> zret = 0;
  sigset_t set;
  if (sigemptyset(&set)) {
    zret = -1;
    zret.errata().error(R"(Could not empty the signal set: {})",
                        swoc::bwf::Errno{});
  } else if (sigaddset(&set, SIGPIPE)) {
    zret = -1;
    zret.errata().error(R"(Could not add SIGPIPE to the signal set: {})",
                        swoc::bwf::Errno{});
  } else if (pthread_sigmask(SIG_BLOCK, &set, nullptr)) {
    zret = -1;
    zret.errata().error(R"(Could not block SIGPIPE: {})", swoc::bwf::Errno{});
  }
  return std::move(zret);
}

swoc::Errata configure_logging(const std::string_view verbose_argument) {
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
    return std::move(errata);
  }
  errata.diag("Configuring logging at level {}", severity_cutoff);

  swoc::Errata::register_sink([severity_cutoff](Errata const &errata) {
    if (errata.severity() < severity_cutoff) {
      return;
    }
    std::string_view lead;
    for (const auto &annotation : errata) {
      if (annotation.severity() < severity_cutoff) {
        continue;
      }
      std::cout << lead << " [" << static_cast<int>(annotation.severity())
                << "]: " << annotation.text() << std::endl;
      if (lead.size() == 0) {
        lead = "  "_sv;
      }
    }
  });
  return std::move(errata);
}

Session::Session() {}

Session::~Session() { this->close(); }

swoc::Rv<ssize_t> Session::read(swoc::MemSpan<char> span) {
  swoc::Rv<ssize_t> zret{::read(_fd, span.data(), span.size())};
  if (zret <= 0) {
    this->close();
  }
  return std::move(zret);
}

swoc::Rv<ssize_t> TLSSession::read(swoc::MemSpan<char> span) {
  errno = 0;
  swoc::Rv<ssize_t> zret{SSL_read(this->_ssl, span.data(), span.size())};
  const auto ssl_error = (zret <= 0) ? SSL_get_error(_ssl, zret) : 0;

  if ((zret < 0 && ssl_error != SSL_ERROR_WANT_READ)) {
    zret.errata().error(
        R"(read of {} bytes failed. Bytes read: {}, ssl_err: {}, errno: {})",
        span.size(), zret.result(), swoc::bwf::SSLError{ssl_error},
        swoc::bwf::Errno{});
    this->close();
  } else if (zret == 0) {
    this->close();
  }
  return std::move(zret);
}

swoc::Rv<ssize_t> Session::write(swoc::TextView view) {
  return ::write(_fd, view.data(), view.size());
}

swoc::Rv<ssize_t> Session::write(HttpHeader const &hdr) {
  // 1. header.serialize, write it out
  // 2. transmit the body
  swoc::LocalBufferWriter<MAX_HDR_SIZE> w;
  swoc::Rv<ssize_t> zret{-1};

  zret.errata() = hdr.serialize(w);

  if (zret.is_ok()) {
    zret.result() = write(w.view());

    if (zret == w.size()) {
      zret.result() += write_body(hdr);
    } else {
      zret.errata().error(
          R"(Header write failed with {} of {} bytes written: {}.)",
          zret.result(), w.size(), swoc::bwf::Errno{});
    }
  }
  return std::move(zret);
}

swoc::Rv<ssize_t> Session::read_header(swoc::FixedBufferWriter &w) {
  swoc::Rv<ssize_t> zret{-1};

  zret.errata().diag("Reading header.");
  while (w.remaining() > 0) {
    auto n = read(w.aux_span());
    if (!is_closed()) {
      // Where to start searching for the EOH string.
      size_t start =
          std::max<size_t>(w.size(), HTTP_EOH.size()) - HTTP_EOH.size();
      w.commit(n);
      size_t offset = w.view().substr(start).find(HTTP_EOH);
      if (TextView::npos != offset) {
        zret = start + offset + HTTP_EOH.size();
        break;
      }
    } else {
      if (w.size()) {
        zret.errata().error(
            R"(Connection closed unexpectedly after {} bytes while waiting for header: {}.)",
            w.size(), swoc::bwf::Errno{});
      } else {
        zret = 0; // clean close between transactions.
      }
      break;
    }
  }
  if (zret.is_ok() && zret == -1) {
    zret.errata().error(R"(Header exceeded maximum size {}.)", w.capacity());
  }
  return std::move(zret);
}

swoc::Rv<size_t> Session::drain_body(HttpHeader const &hdr,
                                     swoc::TextView initial) {
  static constexpr size_t UNBOUNDED = std::numeric_limits<size_t>::max();
  swoc::Rv<size_t> body_size = 0; // bytes drained for the content body.
  std::string buff;
  size_t content_length = hdr._content_length_p ? hdr._content_size : UNBOUNDED;
  if (content_length < initial.size()) {
    body_size.errata().error(
        R"(Response overrun: received {} bytes of content, expected {}.)",
        initial.size(), content_length);
    return std::move(body_size);
  }

  // If there's a status, and it indicates no body, we're done.
  if (hdr._status && HttpHeader::STATUS_NO_CONTENT[hdr._status] &&
      !hdr._content_length_p && !hdr._chunked_p) {
    return std::move(body_size);
  }

  buff.reserve(std::min<size_t>(content_length, MAX_DRAIN_BUFFER_SIZE));

  if (is_closed()) {
    body_size.errata().error(
        R"(drain_body: stream closed) could not read {} bytes)",
        body_size.result());
    return std::move(body_size);
  }

  if (hdr._chunked_p) {
    ChunkCodex::ChunkCallback cb{
        [&](TextView block, size_t offset, size_t size) -> bool {
          body_size.result() += block.size();
          return true;
        }};
    ChunkCodex codex;

    auto result = codex.parse(initial, cb);
    while (result == ChunkCodex::CONTINUE && body_size < content_length) {
      auto n{read({buff.data(), std::min<size_t>(content_length - body_size,
                                                 MAX_DRAIN_BUFFER_SIZE)})};
      if (is_closed()) {
        if (content_length == UNBOUNDED) {
          // Is this an error? It's chunked, so an actual close seems unexpected
          // - should have parsed the empty chunk.
          body_size.errata().info(
              "Connection closed on unbounded chunked-encoded body.");
          result = ChunkCodex::DONE;
        } else {
          body_size.errata().error(
              R"(Response underrun: received {} bytes of content, expected {}, when file closed because {}.)",
              body_size.result(), content_length, swoc::bwf::Errno{});
        }
        break;
      } else {
        result = codex.parse(TextView(buff.data(), n), cb);
      }
    }
    if (result != ChunkCodex::DONE ||
        (content_length != UNBOUNDED && body_size != content_length)) {
      body_size.errata().error(
          R"(Invalid chunked response: expected {} bytes, drained {} bytes. Chunk is done: {}.)",
          content_length, body_size.result(), result != ChunkCodex::DONE);
      return std::move(body_size);
    }
    body_size.errata().diag("Drained {} chunked bytes.", body_size.result());
  } else {
    body_size = initial.size();
    while (body_size < content_length) {
      ssize_t n = read({buff.data(), std::min(content_length - body_size,
                                              MAX_DRAIN_BUFFER_SIZE)});
      // Do not update body_size with n yet because read may return a negative
      // value on error conditions. If there is an error on read, then we close
      // the connection. Thus we check is_closed() here.
      if (is_closed()) {
        if (content_length == UNBOUNDED) {
          body_size.errata().diag("Connection closed on unbounded body");
        } else {
          body_size.errata().error(
              R"(Response underrun: received {} bytes  of content, expected {}, when file closed because {}.)",
              body_size.result(), content_length, swoc::bwf::Errno{});
        }
        break;
      }
      body_size.result() += n;
    }
    if (body_size > content_length) {
      body_size.errata().error(
          R"(Invalid response: expected {} fixed bytes, drained {} byts.)",
          content_length, body_size.result());
      return std::move(body_size);
    }
    body_size.errata().diag("Drained {} bytes.", body_size.result());
  }
  return std::move(body_size);
}

swoc::Rv<ssize_t> Session::write_body(HttpHeader const &hdr) {
  swoc::Rv<ssize_t> bytes_written{0};
  std::error_code ec;

  bytes_written.errata().diag("Transmit {} byte body {}{}.", hdr._content_size,
                              swoc::bwf::If(hdr._content_length_p, "[CL]"),
                              swoc::bwf::If(hdr._chunked_p, "[chunked]"));

  if (hdr._content_size > 0 ||
      (hdr._status && !HttpHeader::STATUS_NO_CONTENT[hdr._status])) {
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
      bytes_written = write(content);
      ec = std::error_code(errno, std::system_category());

      if (!hdr._content_length_p) { // no content-length, must close to signal
                                    // end of body
        bytes_written.errata().diag(
            "No content length, status {}. Closing the connection.",
            hdr._status);
        close();
      }
    }

    if (bytes_written != hdr._content_size) {
      bytes_written.errata().error(
          R"(Body write{} failed with {} of {} bytes written: {}.)",
          swoc::bwf::If(hdr._chunked_p, " [chunked]"), bytes_written.result(),
          hdr._content_size, ec);
    }
  } else if (hdr._content_size == 0 && hdr._status &&
             !HttpHeader::STATUS_NO_CONTENT[hdr._status] && !hdr._chunked_p &&
             !hdr._content_length_p) {
    // There's no body but the status expects one, so signal no body with EOS.
    bytes_written.errata().diag("No CL or TE, status {}: closing.",
                                hdr._status);
    close();
  }

  return std::move(bytes_written);
}

swoc::Errata Session::run_transaction(const Txn &txn) {
  swoc::Errata errata;
  errata.diag("Running transaction.");

  errata.note(this->write(txn._req).errata());

  if (errata.is_ok()) {
    const auto key{txn._req.make_key()};
    HttpHeader rsp_hdr;
    swoc::LocalBufferWriter<MAX_HDR_SIZE> w;
    errata.diag("Reading response header.");

    auto read_result{this->read_header(w)};

    if (read_result.is_ok()) {
      ssize_t body_offset{read_result};
      auto result{rsp_hdr.parse_response(TextView(w.data(), body_offset))};

      if (result.is_ok()) {
        if (rsp_hdr._status == 100) {
          errata.diag("100-Continue response. Read another header.");
          rsp_hdr = HttpHeader{};
          w.clear();
          auto read_result{this->read_header(w)};

          if (read_result.is_ok()) {
            body_offset = read_result;
            auto result{
                rsp_hdr.parse_response(TextView(w.data(), body_offset))};

            if (!result.is_ok()) {
              errata.error(R"(Failed to parse post 100 header.)");
              return errata;
            }
          } else {
            errata.error(R"(Failed to read post 100 header.)");
            return errata;
          }
        }
        errata.diag(R"(Status: "{}")", rsp_hdr._status);
        errata.diag("{}", rsp_hdr);
        if (txn._rsp._status != 0 && rsp_hdr._status != txn._rsp._status &&
            (rsp_hdr._status != 200 || txn._rsp._status != 304) &&
            (rsp_hdr._status != 304 || txn._rsp._status != 200)) {
          errata.error(R"(Invalid status expected {} got {}. key={}.)",
                       txn._rsp._status, rsp_hdr._status, key);
          return errata;
        }
        if (rsp_hdr.verify_headers(key, *txn._rsp._fields_rules)) {
          errata.error(
              R"(Response headers did not match expected response headers.)");
        }
        errata.diag("Reading response body offset={}.",
                    w.view().substr(body_offset));
        rsp_hdr.update_content_length(txn._req._method);
        rsp_hdr.update_transfer_encoding();
        /* Looks like missing plugins is causing issues with length mismatches
         */
        /*
        if (txn._rsp._content_length_p != rsp_hdr._content_length_p) {
          errata.error(R"(Content length specificaton mismatch: got {} ({})
        expected {}({}) . url={})", rsp_hdr._content_length_p ? "length" :
        "chunked", rsp_hdr._content_size, txn._rsp._content_length_p ? "length"
        : "chunked" , txn._rsp._content_size, txn._req._url); return errata;
        }
        if (txn._rsp._content_length_p && txn._rsp._content_size !=
        rsp_hdr._content_size) { errata.error(R"(Content length mismatch: got
        {}, expected {}. url={})", rsp_hdr._content_size,
        txn._rsp._content_size, txn._req._url); return errata;
        }
        */
        errata.note(
            this->drain_body(rsp_hdr, w.view().substr(body_offset)).errata());

        if (!errata.is_ok()) {
        }
      } else {
        errata.error(R"(Invalid response. key={})", key);
        errata.note(result);
      }
    } else {
      errata.error(R"(Invalid response read key={}.)", key);
      errata.note(read_result);
      std::cerr << errata;
    }
  }
  return errata;
}

swoc::Errata Session::run_transactions(const std::list<Txn> &txn_list,
                                       const swoc::IPEndpoint *real_target) {
  swoc::Errata session_errata;

  for (auto const &txn : txn_list) {
    swoc::Errata txn_errata;
    if (this->is_closed()) {
      txn_errata.note(this->do_connect(real_target));
      if (!txn_errata.is_ok()) {
        txn_errata.error(R"(Failed to reconnect HTTP/1 key={}.)", txn._req.make_key());
      }
    }
    const auto before = clock_type::now();
    txn_errata.note(this->run_transaction(txn));
    const auto after = clock_type::now();
    if (!txn_errata.is_ok()) {
      txn_errata.error(R"(Failed HTTP/1 transaction with key={}.)", txn._req.make_key());
    }

    const auto elapsed_ms = chrono::duration_cast<chrono::milliseconds>(after - before);
    if (elapsed_ms > Transaction_Delay_Cutoff) {
      txn_errata.error(R"(Transaction for key={} took {} milliseconds.)",
          txn._req.make_key(), elapsed_ms.count());
    }
    session_errata.note(txn_errata);
  }
  return std::move(session_errata);
}

swoc::Rv<ssize_t> TLSSession::write(swoc::TextView view) {
  int total_size = view.size();
  swoc::Rv<ssize_t> num_written = 0;
  while (num_written < total_size) {
    errno = 0;
    const auto n = SSL_write(this->_ssl, view.data() + num_written,
                             view.size() - num_written);
    if (n <= 0) {
      num_written.errata().error(R"(write failed: {}, errno: {})",
                                 swoc::bwf::SSLError{}, swoc::bwf::Errno{});
      return std::move(num_written);
    } else {
      num_written.result() += n;
    }
  }
  return std::move(num_written);
}

swoc::Errata Session::set_fd(int fd) {
  swoc::Errata errata;
  this->close();
  _fd = fd;
  return std::move(errata);
}

// Complete the TLS handshake
swoc::Errata TLSSession::accept() {
  swoc::Errata errata;
  _ssl = SSL_new(server_ctx);
  if (_ssl == nullptr) {
    errata.error(
        R"(Failed to create SSL server object fd={} server_ctx={} err={}.)",
        get_fd(), server_ctx, swoc::bwf::SSLError{});
  } else {
    SSL_set_fd(_ssl, get_fd());
    int retval = SSL_accept(_ssl);
    if (retval <= 0) {
      errata.error(
          R"(Failed SSL_accept {}, {}.)", swoc::bwf::SSLError{},
          swoc::bwf::Errno{});
    }
  }
  return std::move(errata);
}

swoc::Errata Session::do_connect(const swoc::IPEndpoint *real_target) {
  swoc::Errata errata;
  int socket_fd = socket(real_target->family(), SOCK_STREAM, 0);
  if (0 <= socket_fd) {
    int ONE = 1;
    struct linger l;
    l.l_onoff = 0;
    l.l_linger = 0;
    setsockopt(socket_fd, SOL_SOCKET, SO_LINGER, (char *)&l, sizeof(l));
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &ONE, sizeof(int)) <
        0) {
      errata.error(R"(Could not set reuseaddr on socket {} - {}.)", socket_fd,
                   swoc::bwf::Errno{});
    } else {
      errata = this->set_fd(socket_fd);
      if (errata.is_ok()) {
        if (0 == ::connect(socket_fd, &real_target->sa, real_target->size())) {
          static const int ONE = 1;
          setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, &ONE, sizeof(ONE));
          errata = this->connect();
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

swoc::Errata Session::connect() {
  swoc::Errata errata;
  return std::move(errata);
}

swoc::Errata TLSSession::connect() { return this->connect(client_ctx); }

// Complete the TLS handshake
swoc::Errata TLSSession::connect(SSL_CTX *clt_ctx) {
  swoc::Errata errata;
  _ssl = SSL_new(clt_ctx);
  if (_ssl == nullptr) {
    errata.error(
        R"(Failed to create SSL client object fd={} client_ctx={} err={}.)",
        get_fd(), client_ctx, swoc::bwf::SSLError{});
  } else {
    SSL_set_fd(_ssl, get_fd());
    if (!_client_sni.empty()) {
      SSL_set_tlsext_host_name(_ssl, _client_sni.data());
    }
    int retval = SSL_connect(_ssl);
    if (retval <= 0) {
      errata.error(
          R"(Failed SSL_connect {}, {}.)", swoc::bwf::SSLError{},
          swoc::bwf::Errno{});
    }
  }
  return std::move(errata);
}

swoc::Errata H2Session::connect() {
  // Complete the TLS handshake
  swoc::Errata errata = super_type::connect(h2_client_ctx);
  if (errata.is_ok()) {
    const unsigned char *alpn = nullptr;
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

    if (alpn == nullptr || alpnlen != 2 || memcmp("h2", alpn, 2) != 0) {
      errata.error(R"(h2 is not negotiated)");
      return errata;
    }

    this->session_init();

    // Send initial H2 session frames
    send_client_connection_header();
    send_callback(_session, nullptr, 0, 0, this);
  }
  return errata;
}

swoc::Errata H2Session::run_transactions(const std::list<Txn> &txn_list,
                                         const swoc::IPEndpoint *real_target) {
  swoc::Errata errata;

  for (auto const &txn : txn_list) {
    const auto key{txn._req.make_key()};
    if (this->is_closed()) {
      errata.note(this->do_connect(real_target));
      if (!errata.is_ok()) {
        errata.error(R"(Failed to reconnect HTTP/2 key={}.)", key);
      }
    }
    errata.note(this->run_transaction(txn));
    if (!errata.is_ok()) {
      errata.error(R"(Failed HTTP/2 transaction with key={}.)", key);
    }
  }
  recv_callback(this->get_session(), nullptr, 0, 0, this);
  return std::move(errata);
}

swoc::Errata H2Session::run_transaction(const Txn &txn) {
  swoc::Errata errata;
  errata.diag("Running H2 transaction.");

  // Write the header
  errata.note(this->write(txn._req).errata());

  errata.diag("wrote header");

  return std::move(errata);
}

void Session::close() {
  if (!this->is_closed()) {
    ::close(_fd);
    _fd = -1;
  }
}

void TLSSession::close() {
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
SSL_CTX *TLSSession::server_ctx = nullptr;
SSL_CTX *TLSSession::client_ctx = nullptr;

const int MAX_NOFILE = 300000;

swoc::Errata Session::init() {
  swoc::Errata errata;
  struct rlimit lim;
  if (getrlimit(RLIMIT_NOFILE, &lim) == 0) {
    if (MAX_NOFILE > (int)lim.rlim_cur) {
      lim.rlim_cur = (lim.rlim_max = (rlim_t)MAX_NOFILE);
      if (setrlimit(RLIMIT_NOFILE, &lim) == 0 &&
          getrlimit(RLIMIT_NOFILE, &lim) == 0) {
        errata.diag("Updated RLIMIT_NOFILE to {}", MAX_NOFILE);
      } else {
        errata.error("Failed setrlimit errno={}", errno);
      }
    }
  }
  return std::move(errata);
}

swoc::Errata TLSSession::init(SSL_CTX *&svr_ctx, SSL_CTX *&clt_ctx) {
  swoc::Errata errata;
  SSL_load_error_strings();
  SSL_library_init();

  svr_ctx = SSL_CTX_new(TLS_server_method());
  if (!TLSSession::certificate_file.empty()) {
    if (!SSL_CTX_use_certificate_file(
            svr_ctx, TLSSession::certificate_file.c_str(), SSL_FILETYPE_PEM)) {
      errata.error(R"(Failed to load cert from "{}": {}.)",
                   TLSSession::certificate_file, swoc::bwf::SSLError{});
    } else {
      if (!TLSSession::privatekey_file.empty()) {
        if (!SSL_CTX_use_PrivateKey_file(svr_ctx,
                                         TLSSession::privatekey_file.c_str(),
                                         SSL_FILETYPE_PEM)) {
          errata.error(R"(Failed to load private key from "{}": {}.)",
                       TLSSession::privatekey_file, swoc::bwf::SSLError{});
        }
      } else {
        if (!SSL_CTX_use_PrivateKey_file(svr_ctx,
                                         TLSSession::certificate_file.c_str(),
                                         SSL_FILETYPE_PEM)) {
          errata.error(R"(Failed to load private key from "{}": {}.)",
                       TLSSession::certificate_file, swoc::bwf::SSLError{});
        }
      }
    }
  }
  clt_ctx = SSL_CTX_new(TLS_client_method());
  if (!clt_ctx) {
    errata.error(R"(Failed to create client_ctx: {}.)", swoc::bwf::SSLError{});
  }
  return std::move(errata);
}

static int on_begin_headers_callback(nghttp2_session *session,
                                     const nghttp2_frame *frame,
                                     void *user_data) {
  swoc::Errata errata;
  errata.diag("on_begin_headers_callback");
  return 0;
}

static int on_header_callback(nghttp2_session *session,
                              const nghttp2_frame *frame, const uint8_t *name,
                              size_t namelen, const uint8_t *value,
                              size_t valuelen, uint8_t flags, void *user_data) {
  swoc::Errata errata;
  if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
    H2Session *session_data = reinterpret_cast<H2Session *>(user_data);
    // See if we are expecting a 100 response
    //
    auto iter = session_data->_stream_map.find(frame->hd.stream_id);
    if (iter != session_data->_stream_map.end()) {
      if (iter->second->_wait_for_continue) {
        if (strncmp(reinterpret_cast<const char *>(name), ":status", namelen) ==
                0 &&
            strncmp(reinterpret_cast<const char *>(value), "100", valuelen) ==
                0) {
          iter->second->_wait_for_continue = false;
        }
      }
    }
  }
  errata.diag("{}: {}", reinterpret_cast<const char *>(name),
              reinterpret_cast<const char *>(value));
  return 0;
}

/* nghttp2_send_callback. Here we transmit the |data|, |length| bytes,
 *    to the network. Because we are using libevent bufferevent, we just
 *       write those bytes into bufferevent buffer. */
static ssize_t send_callback(nghttp2_session *session, const uint8_t *inputdata,
                             size_t length, int flags, void *user_data) {
  H2Session *session_data = reinterpret_cast<H2Session *>(user_data);

  swoc::Errata errata;
  errata.diag("Need to write {} bytes", length);
  int total_amount_sent = 0;
  for (;;) {
    const uint8_t *data = nullptr;
    ssize_t datalen = nghttp2_session_mem_send(session, &data);
    size_t total_data_len = datalen;
    if (datalen <= 0) {
      break;
    }
    int amount_sent = 0;
    while (amount_sent < datalen) {
      int n = SSL_write(session_data->get_ssl(), data, datalen);
      amount_sent += n;

      errata.diag("Tried to write {} bytes and wrote {} bytes", datalen, n);
      if (n <= 0)
        break;
    }
    total_amount_sent += amount_sent;
  }

  return (ssize_t)total_amount_sent;
}

static ssize_t recv_callback(nghttp2_session *session, uint8_t *buf,
                             size_t length, int flags, void *user_data) {
  H2Session *session_data = reinterpret_cast<H2Session *>(user_data);
  swoc::Errata errata;
  errata.diag("Try to read up to {} bytes", length);
  unsigned char buffer[10 * 1024];
  int total_recv = 0;

  while (!session_data->_stream_map.empty()) {
    int n = SSL_read(session_data->get_ssl(), buffer, sizeof(buffer));
    errata.diag("Read {} bytes", n);
    int rv = nghttp2_session_mem_recv(session_data->get_session(), buffer,
                                      (size_t)n);
    errata.diag("Processed {} bytes", rv);
    if (rv < 0) {
      fprintf(stderr, "error: (nghttp2_session_mem_recv) %s\n",
              nghttp2_strerror((int)rv));
      return -1;
    } else if (rv == 0) {
      return total_recv;
    }
    total_recv += rv;
    // opportunity to send any frames like the window_update frame
    send_callback(session, nullptr, 0, 0, user_data);
  }
  return (ssize_t)total_recv;
}

static int on_frame_send_cb(nghttp2_session *session,
                            const nghttp2_frame *frame, void *user_data) {
  swoc::Errata errata;
  errata.diag("on_frame_send_cb");
  return 0;
}

static int on_frame_recv_cb(nghttp2_session *session,
                            const nghttp2_frame *frame, void *user_data) {
  swoc::Errata errata;
  errata.diag("on_frame_recv_cb type={}", frame->hd.type);

  switch (frame->hd.type) {
  case NGHTTP2_DATA:
    // Processed the data and send the window update
    break;
  case NGHTTP2_HEADERS: // Dealt with this in the on_headers callbacks
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

  return 0;
}

static int on_stream_close_cb(nghttp2_session *session, int32_t stream_id,
                              uint32_t error_code, void *user_data) {
  swoc::Errata errata;
  errata.diag("on_stream_close_cb {}", stream_id);
  H2Session *session_data = reinterpret_cast<H2Session *>(user_data);
  auto iter = session_data->_stream_map.find(stream_id);
  if (iter != session_data->_stream_map.end()) {
    session_data->_stream_map.erase(iter);
  }
  return 0;
}

static int on_data_chunk_recv_cb(nghttp2_session *session, uint8_t flags,
                                 int32_t stream_id, const uint8_t *data,
                                 size_t len, void *user_data) {
  swoc::Errata errata;
  errata.diag("on_data_chunk_recv_cb {} bytes", len);
  return 0;
}

H2Session::H2Session() { callbacks = nullptr; }

swoc::Rv<ssize_t> H2Session::read(swoc::MemSpan<char> span) {
  swoc::Rv<ssize_t> zret{1};
  return zret;
}

swoc::Rv<ssize_t> H2Session::write(swoc::TextView data) {
  swoc::Rv<ssize_t> zret{1};
  return zret;
}

ssize_t data_read_callback(nghttp2_session *session, int32_t stream_id,
                           uint8_t *buf, size_t length, uint32_t *data_flags,
                           nghttp2_data_source *source, void *user_data) {
  size_t num_to_copy = 0;
  H2StreamState *state = reinterpret_cast<H2StreamState *>(
      nghttp2_session_get_stream_user_data(session, stream_id));
  if (!state->_wait_for_continue) {
    num_to_copy =
        std::min(length, state->_send_body_length - state->_send_body_offset);
    if (num_to_copy > 0) {
      memcpy(buf, state->_send_body + state->_send_body_offset, num_to_copy);
      state->_send_body_offset += num_to_copy;
    } else {
      num_to_copy = 0;
    }
    if (state->_send_body_offset >= state->_send_body_length) {
      *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }
  }
  return num_to_copy;
}

swoc::Rv<ssize_t> H2Session::write(HttpHeader const &hdr) {
  swoc::Rv<ssize_t> zret{1};
  // grab header, send to session
  // pack_headers will convert all the fields in hdr into nghttp2_nv structs
  int hdr_count = 0;
  nghttp2_nv *hdrs = nullptr;
  pack_headers(hdr, hdrs, hdr_count);

  int32_t stream_id = 0;
  H2StreamState *stream_state = new H2StreamState();
  // Content, need to set up the post body too
  if (hdr._content_size > 0 ||
      (hdr._status && !HttpHeader::STATUS_NO_CONTENT[hdr._status])) {
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
    stream_state->_send_body = content.data();
    stream_state->_send_body_length = content.size();
    stream_state->_req = &hdr;
    stream_state->_wait_for_continue = hdr._send_continue;
    stream_id = nghttp2_submit_request(this->_session, nullptr, hdrs, hdr_count,
                                       &data_prd, stream_state);
  } else {
    stream_id = nghttp2_submit_request(this->_session, nullptr, hdrs, hdr_count,
                                       nullptr, stream_state);
    stream_state->_stream_id = stream_id;
  }
  zret.errata().diag(R"(Sent stream "{}" with {} headers)", stream_id,
                     hdr_count);

  // Kick off the send logic to put the data on the wire
  send_callback(_session, nullptr, 0, 0, this);
  free(hdrs);

  _stream_map.insert(std::make_pair(stream_id, stream_state));

  return 1;
}

swoc::Errata H2Session::pack_headers(HttpHeader const &hdr, nghttp2_nv *&nv_hdr,
                                     int &hdr_count) {
  swoc::Errata errata;
  hdr_count = hdr._fields_rules->_fields.size();

  if (hdr._status) {
    hdr_count += 1;
  } else if (hdr._method) {
    hdr_count += 4;
  } else {
    hdr_count = 0;
    errata.error(R"(Unable to write header - no status nor method.)");
    return errata;
  }

  nv_hdr =
      reinterpret_cast<nghttp2_nv *>(malloc(sizeof(nghttp2_nv) * hdr_count));
  int offset = 0;

  if (hdr._status) {
    // status is unsigned, not a TextView, but only 1 off case so just write the
    // code here
    nghttp2_nv status_nv = {const_cast<uint8_t *>((uint8_t *)":status"),
                            (uint8_t *)&hdr._status, sizeof(":status") - 1,
                            sizeof((uint8_t *)&hdr._status) - 1,
                            NGHTTP2_NV_FLAG_NONE};
    nv_hdr[offset++] = status_nv;
  } else if (hdr._method) {
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

nghttp2_nv H2Session::tv_to_nv(const char *name, swoc::TextView v) {
  nghttp2_nv res;

  res.name = const_cast<uint8_t *>((uint8_t *)name);
  res.value = const_cast<uint8_t *>((uint8_t *)v.data());
  res.namelen = strlen(name);
  res.valuelen = v.length();
  res.flags = NGHTTP2_NV_FLAG_NONE;

  return res;
}

SSL_CTX *H2Session::h2_server_ctx = nullptr;
SSL_CTX *H2Session::h2_client_ctx = nullptr;

swoc::Errata H2Session::send_client_connection_header() {
  swoc::Errata errata;
  nghttp2_settings_entry iv[1] = {
      {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
  int rv = 0;

  /* client 24 bytes magic string will be sent by nghttp2 library */
  rv = nghttp2_submit_settings(this->_session, NGHTTP2_FLAG_NONE, iv, 1);
  if (rv != 0) {
    errata.error(R"(Could not submit SETTINGS)");
  }
  return errata;
}

const unsigned char npn_str[] = {2,   'h', '2', 7,   'h', 't',
                                 't', 'p', '1', '.', '1'};
int npn_len = 11;

int alpn_select_next_proto_cb(SSL *ssl, const unsigned char **out,
                              unsigned char *outlen, const unsigned char *in,
                              unsigned int inlen, void *arg) {
  if (SSL_select_next_proto(const_cast<unsigned char **>(out), outlen, npn_str,
                            npn_len, in, inlen) == OPENSSL_NPN_NEGOTIATED) {
    return SSL_TLSEXT_ERR_OK;
  }
  *out = nullptr;
  *outlen = 0;
  return SSL_TLSEXT_ERR_NOACK;
}

int select_next_proto_cb(SSL *ssl, unsigned char **out, unsigned char *outlen,
                         const unsigned char *in, unsigned int inlen,
                         void *arg) {
  if (SSL_select_next_proto(out, outlen, npn_str, npn_len, in, inlen) ==
      OPENSSL_NPN_NEGOTIATED) {
    return SSL_TLSEXT_ERR_OK;
  }
  *out = nullptr;
  *outlen = 0;
  return SSL_TLSEXT_ERR_NOACK;
}

static int advertise_next_protocol_cb(SSL *ssl, const unsigned char **out,
                                      unsigned int *outlen, void *arg) {
  *out = npn_str;
  *outlen = npn_len;
  return SSL_TLSEXT_ERR_OK;
}

swoc::Errata H2Session::init(SSL_CTX *&svr_ctx, SSL_CTX *&clt_ctx) {
  swoc::Errata errata = super_type::init(svr_ctx, clt_ctx);

  if (!errata.is_ok()) {
    return errata;
  }

  // Initialize the protocol selection to include H2
  SSL_CTX_set_next_proto_select_cb(clt_ctx, select_next_proto_cb, nullptr);
  SSL_CTX_set_next_protos_advertised_cb(svr_ctx, advertise_next_protocol_cb,
                                        nullptr);

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
  // Set the protocols the client will advertise
  SSL_CTX_set_alpn_protos(clt_ctx, npn_str, npn_len);
  SSL_CTX_set_alpn_select_cb(svr_ctx, alpn_select_next_proto_cb, nullptr);
#else
  Error must be at least openssl 1.0.2
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L
  return errata;
}

swoc::Errata H2Session::session_init() {
  swoc::Errata errata;

  // Set up the H2 callback methods
  int ret = nghttp2_session_callbacks_new(&this->callbacks);

  if (ret != 0) {
    errata.error("nghttp2_session_callbacks_new {}", ret);
  }

  nghttp2_session_callbacks_set_on_header_callback(this->callbacks,
                                                   on_header_callback);

  nghttp2_session_callbacks_set_on_begin_headers_callback(
      this->callbacks, on_begin_headers_callback);

  //  nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
  //  nghttp2_session_callbacks_set_recv_callback(callbacks, recv_callback);

  nghttp2_session_callbacks_set_on_frame_send_callback(this->callbacks,
                                                       on_frame_send_cb);
  nghttp2_session_callbacks_set_on_frame_recv_callback(this->callbacks,
                                                       on_frame_recv_cb);
  nghttp2_session_callbacks_set_on_stream_close_callback(this->callbacks,
                                                         on_stream_close_cb);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
      this->callbacks, on_data_chunk_recv_cb);

  nghttp2_session_client_new(&this->_session, this->callbacks, this);

  return errata;
}

ChunkCodex::Result ChunkCodex::parse(swoc::TextView data,
                                     ChunkCallback const &cb) {
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
        break;
      }
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
        _state = State::SIZE;
        ++data;
        _off = 0;
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
          _state = State::FINAL;
          return DONE;
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
ChunkCodex::transmit(Session &session, swoc::TextView data, size_t chunk_size) {
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
        if (n == chunk_size) {
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
  if (n != ZERO_CHUNK.size()) {
    return {total, std::error_code(errno, std::system_category())};
  }
  return {total, NO_ERROR};
};

void HttpHeader::global_init() {
  FIELD_CONTENT_LENGTH = localize_lower("Content-Length"_tv);
  FIELD_TRANSFER_ENCODING = localize_lower("Transfer-Encoding"_tv);
  FIELD_HOST = localize_lower("Host"_tv);

  STATUS_NO_CONTENT[100] = true;
  STATUS_NO_CONTENT[204] = true;
  STATUS_NO_CONTENT[304] = true;
  for (auto code = 400; code < 600; code++) {
    STATUS_NO_CONTENT[code] = true;
  }

  RuleCheck::options_init();
}

void RuleCheck::options_init() {
  options = RuleOptions();

  // Overloaded resolution works with function pointers, but not with
  // std::functions. We have to help out the compiler, therefore, via casting
  // to the correct function type.
  using single_field_function_type = std::shared_ptr<RuleCheck> (*)(swoc::TextView, swoc::TextView);
  options[swoc::TextView(YAML_RULE_EQUALS)] = static_cast<single_field_function_type>(make_equality);
  options[swoc::TextView(YAML_RULE_PRESENCE)] = static_cast<single_field_function_type>(make_presence);
  options[swoc::TextView(YAML_RULE_ABSENCE)] = static_cast<single_field_function_type>(make_absence);

  duplicate_field_options = DuplicateFieldRuleOptions();
  using duplicate_field_function_type = std::shared_ptr<RuleCheck> (*)(swoc::TextView, std::list<swoc::TextView>&&);
  duplicate_field_options[swoc::TextView(YAML_RULE_EQUALS)] = static_cast<duplicate_field_function_type>(make_equality);
  duplicate_field_options[swoc::TextView(YAML_RULE_PRESENCE)] = static_cast<duplicate_field_function_type>(make_presence);
  duplicate_field_options[swoc::TextView(YAML_RULE_ABSENCE)] = static_cast<duplicate_field_function_type>(make_absence);
}

std::shared_ptr<RuleCheck> RuleCheck::make_rule_check(
    swoc::TextView localized_name,
    swoc::TextView localized_value,
    swoc::TextView rule_type) {
  swoc::Errata errata;

  auto fn_iter = options.find(rule_type);
  if (fn_iter == options.end()) {
    errata.info(R"(Invalid Test: Key: "{}")", rule_type);
    return nullptr;
  }
  return fn_iter->second(localized_name, localized_value);
}

std::shared_ptr<RuleCheck> RuleCheck::make_rule_check(
    swoc::TextView localized_name,
    std::list<swoc::TextView> &&localized_values,
    swoc::TextView rule_type) {
  swoc::Errata errata;

  auto fn_iter = duplicate_field_options.find(rule_type);
  if (fn_iter == duplicate_field_options.end()) {
    errata.info(R"(Invalid Test: Key: "{}")", rule_type);
    return nullptr;
  }
  return fn_iter->second(localized_name, std::move(localized_values));
}

std::shared_ptr<RuleCheck> RuleCheck::make_equality(
    swoc::TextView name,
    swoc::TextView value) {
  return std::shared_ptr<RuleCheck>(new EqualityCheck(name, value));
}

std::shared_ptr<RuleCheck> RuleCheck::make_equality(
    swoc::TextView name,
    std::list<swoc::TextView> &&values) {
  return std::shared_ptr<RuleCheck>(new EqualityCheck(name, std::move(values)));
}

std::shared_ptr<RuleCheck> RuleCheck::make_presence(
    swoc::TextView name,
    swoc::TextView value) {
  return std::shared_ptr<RuleCheck>(new PresenceCheck(name, !EXPECTS_DUPLICATE_FIELDS));
}

std::shared_ptr<RuleCheck> RuleCheck::make_presence(
    swoc::TextView name,
    std::list<swoc::TextView> &&values) {
  return std::shared_ptr<RuleCheck>(new PresenceCheck(name, EXPECTS_DUPLICATE_FIELDS));
}

std::shared_ptr<RuleCheck> RuleCheck::make_absence(
    swoc::TextView name,
    swoc::TextView value) {
  return std::shared_ptr<RuleCheck>(new AbsenceCheck(name, !EXPECTS_DUPLICATE_FIELDS));
}

std::shared_ptr<RuleCheck> RuleCheck::make_absence(
    swoc::TextView name,
    std::list<swoc::TextView> &&values) {
  return std::shared_ptr<RuleCheck>(new AbsenceCheck(name, EXPECTS_DUPLICATE_FIELDS));
}

EqualityCheck::EqualityCheck(swoc::TextView name, swoc::TextView value)
{
  _name = name;
  _value = value;
}

EqualityCheck::EqualityCheck(swoc::TextView name, std::list<swoc::TextView> &&values)
{
  _name = name;
  _values = std::move(values);
  _expects_duplicate_fields = true;
}

PresenceCheck::PresenceCheck(swoc::TextView name, bool expects_duplicate_fields)
{
  _name = name;
  _expects_duplicate_fields = expects_duplicate_fields;
}

AbsenceCheck::AbsenceCheck(swoc::TextView name, bool expects_duplicate_fields)
{
  _name = name;
  _expects_duplicate_fields = expects_duplicate_fields;
}

bool EqualityCheck::test(swoc::TextView key, swoc::TextView name,
                         swoc::TextView value) const {
  swoc::Errata errata;
  if (name.empty())
    errata.info(
        R"(Equals Violation: Absent. Key: "{}", Name: "{}", Correct Value: "{}")",
        key, _name, _value);
  else if (strcmp(value, _value))
    errata.info(
        R"(Equals Violation: Different. Key: "{}", Name: "{}", Correct Value: "{}", Actual Value: "{}")",
        key, _name, _value, value);
  else {
    errata.info(R"(Equals Success: Key: "{}", Name: "{}", Value: "{}")", key,
                _name, _value);
    return true;
  }
  return false;
}

bool EqualityCheck::test(swoc::TextView key, swoc::TextView name,
                         const std::list<swoc::TextView> &values) const {
  swoc::Errata errata;
  if (name.empty()) {
    errata.info(
        R"(Equals Violation: Absent. Key: "{}", Name: "{}", Correct Value: "{}")",
        key, _name, _value);
  } else if (_values != values) {
    MSG_BUFF message;
    message.print(R"(Equals Violation: Different. Key: "{}", Name: "{}", )", key, _name);

    message.print(R"(Correct Values:)");
    for (auto const& value: _values) {
      message.print(R"( "{}")", value);
    }
    message.print(R"(, Received Values:)");
    for (auto const& value: values) {
      message.print(R"( "{}")", value);
    }
    errata.info(message.view());
  } else {
    MSG_BUFF message;
    message.print(R"(Equals Success: Key: "{}", Name: "{}", Values:)", key, _name);
    for (auto const& value: values) {
      message.print(R"( "{}")", value);
    }
    errata.info(message.view());
    return true;
  }
  return false;
}

bool PresenceCheck::test(swoc::TextView key, swoc::TextView name,
                         swoc::TextView value) const {
  swoc::Errata errata;
  if (name.empty()) {
    errata.info(R"(Presence Violation: Absent. Key: "{}", Name: "{}")", key,
                _name);
    return false;
  }
  errata.info(R"(Presence Success: Key: "{}", Name: "{}", Value: "{}")", key,
              _name, value);
  return true;
}

bool PresenceCheck::test(swoc::TextView key, swoc::TextView name,
                         const std::list<swoc::TextView> &values) const {
  swoc::Errata errata;
  if (name.empty()) {
    errata.info(R"(Presence Violation: Absent. Key: "{}", Name: "{}")", key,
                _name);
    return false;
  }
  MSG_BUFF message;
  message.print(R"(Presence Success: Key: "{}", Name: "{}", Values:)", key, _name);
  for (auto const& value: values) {
    message.print(R"( "{}")", value);
  }
  errata.info(message.view());
  return true;
}

bool AbsenceCheck::test(swoc::TextView key, swoc::TextView name,
                        swoc::TextView value) const {
  swoc::Errata errata;
  if (!name.empty()) {
    errata.info(
        R"(Absence Violation: Present. Key: "{}", Name: "{}", Value: "{}")",
        key, _name, value);
    return false;
  }
  errata.info(R"(Absence Success: Key: "{}", Name: "{}")", key, _name);
  return true;
}

bool AbsenceCheck::test(swoc::TextView key, swoc::TextView name,
                        const std::list<swoc::TextView> &values) const {
  swoc::Errata errata;
  if (!name.empty()) {
    MSG_BUFF message;
    message.print(R"(Absence Violation: Present. Key: "{}", Name: "{}", Values:)", key, _name);
    for (auto const& value: values) {
      message.print(R"( "{}")", value);
    }
    errata.info(message.view());
    return false;
  }
  errata.info(R"(Absence Success: Key: "{}", Name: "{}")", key, _name);
  return true;
}

void HttpHeader::set_max_content_length(size_t n) {
  n = swoc::round_up<16>(n);
  _content.assign(static_cast<char *>(malloc(n)), n);
  for (size_t k = 0; k < n; k += 8) {
    swoc::FixedBufferWriter w{_content.data() + k, 8};
    w.print("{:07x} ", k / 8);
  };
}

swoc::Errata HttpHeader::update_content_length(swoc::TextView method) {
  swoc::Errata errata;
  size_t cl = std::numeric_limits<size_t>::max();
  _content_length_p = false;
  // Some methods ignore the Content-Length for the current transaction
  if (strcasecmp(method, "HEAD") == 0) {
    // Don't try chunked encoding later
    _content_size = 0;
    _content_length_p = true;
  } else if (auto spot{_fields_rules->_fields.find(FIELD_CONTENT_LENGTH)};
             spot != _fields_rules->_fields.end()) {
    cl = swoc::svtou(spot->second);
    _content_size = cl;
    _content_length_p = true;
  }
  return std::move(errata);
}

swoc::Errata HttpHeader::update_transfer_encoding() {
  _chunked_p = false;
  if (auto spot{_fields_rules->_fields.find(FIELD_TRANSFER_ENCODING)};
      spot != _fields_rules->_fields.end()) {
    if (0 == strcasecmp("chunked", spot->second)) {
      _chunked_p = true;
    }
  }
  return {};
}

swoc::Errata HttpHeader::serialize(swoc::BufferWriter &w) const {
  swoc::Errata errata;

  if (_status) {
    w.print("HTTP/{} {} {}{}", _http_version, _status, _reason, HTTP_EOL);
  } else if (_method) {
    w.print("{} {} HTTP/{}{}", _method, _url, _http_version, HTTP_EOL);
  } else {
    errata.error(R"(Unable to write header: no status nor method.)");
  }

  for (auto const &[name, value] : _fields_rules->_fields) {
    w.write(name).write(": ").write(value).write(HTTP_EOL);
  }
  w.write(HTTP_EOL);

  return std::move(errata);
}

void HttpFields::merge(HttpFields const &other) {
  for (auto const &field : other._fields) {
    _fields.emplace(field.first, field.second);
  }
  for (auto const &rule : other._rules) {
    _rules.emplace(rule.first, rule.second);
  }
}

swoc::Errata HttpFields::parse_global_rules(YAML::Node const &node) {
  swoc::Errata errata;

  if (auto rules_node{node[YAML_FIELDS_KEY]}; rules_node) {
    if (rules_node.IsSequence()) {
      if (rules_node.size() > 0) {
        auto result{
            this->parse_fields_and_rules(rules_node, !ASSUME_EQUALITY_RULE)};
        if (!result.is_ok()) {
          errata.error("Failed to parse fields and rules at {}", node.Mark());
          errata.note(result);
        }
      } else {
        errata.info(R"(Fields and rules node at {} is an empty list.)",
                    rules_node.Mark());
      }
    } else {
      errata.info(R"(Fields and rules node at {} is not a sequence.)",
                  rules_node.Mark());
    }
  } else {
    errata.info(R"(Node at {} is missing a fields node.)", node.Mark());
  }
  return std::move(errata);
}

swoc::Errata
HttpFields::parse_fields_and_rules(YAML::Node const &fields_rules_node,
                                   bool assume_equality_rule) {
  swoc::Errata errata;

  for (auto const &node : fields_rules_node) {
    if (!node.IsSequence()) {
      errata.error("Field or rule at {} is not a sequence as required.",
                   node.Mark());
      continue;
    }
    const auto node_size = node.size();
    if (node_size != 2 && node_size != 3) {
      errata.error("Field or rule node at {} is not a sequence of length 2 "
                   "or 3 as required.",
                   node.Mark());
      continue;
    }

    TextView name{
        HttpHeader::localize_lower(node[YAML_RULE_NAME_KEY].Scalar())};
    const YAML::Node ValueNode{node[YAML_RULE_DATA_KEY]};
    if (ValueNode.IsScalar()) {
      // There's only a single value associated with this field name.
      TextView value{HttpHeader::localize(node[YAML_RULE_DATA_KEY].Scalar())};
      _fields.emplace(name, value);
      if (node_size == 2 && assume_equality_rule) {
        _rules.emplace(name, RuleCheck::make_equality(name, value));
      } else if (node_size == 3) {
        // Contans a verification rule.
        TextView rule_type{node[YAML_RULE_TYPE_KEY].Scalar()};
        std::shared_ptr<RuleCheck> tester =
            RuleCheck::make_rule_check(name, value, rule_type);
        if (!tester) {
          errata.error("Field rule at {} does not have a valid flag ({})",
                       node.Mark(), rule_type);
          continue;
        } else {
          _rules.emplace(name, tester);
        }
      }
    } else if (ValueNode.IsSequence()) {
      // There's a list of values associated with this field. This
      // indicates duplicate fields for the same field name.
      std::list<TextView> values;
      for (auto const &value: ValueNode) {
        TextView localized_value{HttpHeader::localize(value.Scalar())};
        values.emplace_back(localized_value);
        _fields.emplace(name, localized_value);
      }
      if (node_size == 2 && assume_equality_rule) {
        _rules.emplace(name, RuleCheck::make_equality(name, std::move(values)));
      } else if (node_size == 3) {
        // Contans a verification rule.
        TextView rule_type{node[YAML_RULE_TYPE_KEY].Scalar()};
        std::shared_ptr<RuleCheck> tester =
            RuleCheck::make_rule_check(name, std::move(values), rule_type);
        if (!tester) {
          errata.error("Field rule at {} does not have a valid flag ({})",
                       node.Mark(), rule_type);
          continue;
        } else {
          _rules.emplace(name, tester);
        }
      }
    }
  }
  return std::move(errata);
}

void HttpFields::add_fields_to_ngnva(nghttp2_nv *l) const {
  int offset = 0;
  for (const auto &[key, value] : _fields) {
    l[offset++] =
        nghttp2_nv{const_cast<uint8_t *>((uint8_t *)key.data()),
                   const_cast<uint8_t *>((uint8_t *)value.data()), key.length(),
                   value.length(), NGHTTP2_NV_FLAG_NONE};
  }
}

swoc::Errata
HttpHeader::parse_url(TextView url)
{
  swoc::Errata errata;
  // Split out the path and scheme for http/2 required headers
  // See rfc3986 section-3.2.
  std::size_t end_scheme = url.find("://");
  if (end_scheme == std::string::npos) {
    _path = url;
    // Scheme, authority, and the like will have to come from the corresponding YAML nodes.
    return errata;
  }
  std::size_t auth_start = end_scheme + 3; // "://" is 3 characters.
  std::size_t end_host = auth_start;
  _scheme = this->localize(url.substr(0, end_scheme));
  // Look for the ':' for the port.
  std::size_t next_colon = url.find(":", auth_start);
  std::size_t next_slash = url.find("/", auth_start);
  end_host = std::min(next_colon, next_slash);
  if (end_host == std::string::npos) {
    // No ':' nor '/'. Assume the rest of the string is the host.
    end_host = url.length();
  }
  _authority = this->localize(url.substr(auth_start, end_host - auth_start));
  std::size_t path_start = url.find("/", end_host);
  if (path_start != std::string::npos) {
    _path = this->localize(url.substr(path_start));
  }
  return errata;
}

swoc::Errata HttpHeader::load(YAML::Node const &node) {
  swoc::Errata errata;

  if (node[YAML_HTTP_VERSION_KEY]) {
    _http_version = this->localize_lower(node[YAML_HTTP_VERSION_KEY].Scalar());
  } else {
    _http_version = "1.1";
  }

  if (node[YAML_HTTP_STATUS_KEY]) {
    auto status_node{node[YAML_HTTP_STATUS_KEY]};
    if (status_node.IsScalar()) {
      TextView text{status_node.Scalar()};
      TextView parsed;
      auto n = swoc::svtou(text, &parsed);
      if (parsed.size() == text.size() && 0 < n && n <= 599) {
        _status = n;
      } else {
        errata.error(
            R"("{}" value "{}" at {} must be an integer in the range [1..599].)",
            YAML_HTTP_STATUS_KEY, text, status_node.Mark());
      }
    } else {
      errata.error(
          R"("{}" value at {} must be an integer in the range [1..599].)",
          YAML_HTTP_STATUS_KEY, status_node.Mark());
    }
  }

  if (node[YAML_HTTP_REASON_KEY]) {
    auto reason_node{node[YAML_HTTP_REASON_KEY]};
    if (reason_node.IsScalar()) {
      _reason = this->localize(reason_node.Scalar());
    } else {
      errata.error(R"("{}" value at {} must be a string.)",
                   YAML_HTTP_REASON_KEY, reason_node.Mark());
    }
  }

  if (node[YAML_HTTP_METHOD_KEY]) {
    auto method_node{node[YAML_HTTP_METHOD_KEY]};
    if (method_node.IsScalar()) {
      _method = this->localize(method_node.Scalar());
    } else {
      errata.error(R"("{}" value at {} must be a string.)",
                   YAML_HTTP_REASON_KEY, method_node.Mark());
    }
  }

  if (node[YAML_HTTP_URL_KEY]) {
    auto url_node{node[YAML_HTTP_URL_KEY]};
    if (url_node.IsScalar()) {
      _url = this->localize(url_node.Scalar());
      this->parse_url(_url);
    } else {
      errata.error(R"("{}" value at {} must be a string.)", YAML_HTTP_URL_KEY,
                   url_node.Mark());
    }
  }

  if (node[YAML_HTTP_SCHEME_KEY]) {
    auto scheme_node{node[YAML_HTTP_SCHEME_KEY]};
    if (scheme_node.IsScalar()) {
      _scheme = this->localize(scheme_node.Scalar());
    } else {
      errata.error(R"("{}" value at {} must be a string.)", YAML_HTTP_SCHEME_KEY,
                   scheme_node.Mark());
    }
  }

  if (node[YAML_HDR_KEY]) {
    auto hdr_node{node[YAML_HDR_KEY]};
    if (hdr_node[YAML_FIELDS_KEY]) {
      auto field_list_node{hdr_node[YAML_FIELDS_KEY]};
      swoc::Errata result = _fields_rules->parse_fields_and_rules(
          field_list_node, _verify_strictly);
      if (result.is_ok()) {
        errata.note(this->update_content_length(_method));
        errata.note(this->update_transfer_encoding());
      } else {
        errata.error("Failed to parse response at {}", node.Mark());
        errata.note(result);
      }
    }
  }

  if (!_method.empty() && _authority.empty()) {
    // The URL didn't have the authority. Get it from the Host header if it exists.
    const auto it = _fields_rules->_fields.find(FIELD_HOST);
    if (it != _fields_rules->_fields.end()) {
      _authority = it->second;
    }
  }

  // Do this after header so it can override transfer encoding.
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
              R"(Invalid value "{}" for "{}" key at {} in "{}" node at )", xf,
              YAML_CONTENT_TRANSFER_KEY, xf_node.Mark(), YAML_CONTENT_KEY,
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
            errata.error(R"(Unknown encoding "{}" at {}.)", text,
                         enc_node.Mark());
          }
        }
        TextView content{this->localize(data_node.Scalar(), enc)};
        _content_data = content.data();
        int new_content_length = content.size();
        if (_content_length_p) {
          if (_content_size != new_content_length) {
            errata.diag(
                R"(Conflicting sizes for "Content-Length", using data value {} instead of header value {}.)",
                new_content_length, _content_size);
          }
        }
        _content_size = new_content_length;
      } else if (auto size_node{content_node[YAML_CONTENT_LENGTH_KEY]};
                 size_node) {
        int new_content_length = swoc::svtou(size_node.Scalar());
        // Cross check against previously read content-length header, if any
        if (_content_length_p) {
          if (_content_size != new_content_length) {
            errata.diag(
                R"(Conflicting sizes for "Content-Length", using rule value {} instead of header value {}.)",
                new_content_length, _content_size);
          }
        }
        _content_size = new_content_length;
      } else {
        errata.error(
            R"("{}" node at {} does not have a "{}" or "{}" key as required.)",
            YAML_CONTENT_KEY, node.Mark(), YAML_CONTENT_LENGTH_KEY,
            YAML_CONTENT_DATA_KEY);
      }
    } else {
      errata.error(R"("{}" node at {} is not a map.)", YAML_CONTENT_KEY,
                   content_node.Mark());
    }
  }

  return std::move(errata);
}

std::string HttpHeader::make_key() const {
  swoc::FixedBufferWriter w{nullptr};
  std::string key; // Should generally leave --key argument empty on cmd line.
  Binding binding(*this);
  w.print_n(binding, _key_format);
  key.resize(w.extent());
  swoc::FixedBufferWriter{key.data(), key.size()}.print_n(binding, _key_format);
  return std::move(key);
}

// Verify that the fields in 'this' correspond to the provided rules.
bool HttpHeader::verify_headers(swoc::TextView transaction_key,
                                const HttpFields &rules_) const {
  // Remains false if no issue is observed
  // Setting true does not break loop because test() calls errata.diag()
  bool issue_exists = false;
  auto const& rules = rules_._rules;
  auto const& fields = _fields_rules->_fields;
  for (auto const &[name, rule_check] : rules) {
    auto name_range = fields.equal_range(name);
    auto field_iter = name_range.first;
    if (rule_check->expects_duplicate_fields()) {
      if (field_iter == name_range.second) {
        if (!rule_check->test(transaction_key, swoc::TextView(), std::list<TextView>{})) {
          // We supply the empty name and value for the absence check which
          // expects this to indicate an absent field.
          issue_exists = true;
        }
      } else {
        std::list<TextView> values;
        while (field_iter != name_range.second) {
          values.push_back(field_iter->second);
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
        if (!rule_check->test(transaction_key, field_iter->first,
                               swoc::TextView(field_iter->second))) {
          issue_exists = true;
        }
      }
    }
  }
  return issue_exists;
}

HttpHeader::HttpHeader(bool verify_strictly)
    : _verify_strictly{verify_strictly}, _fields_rules{
                                             std::make_shared<HttpFields>()} {}

swoc::TextView HttpHeader::localize(char const *text) {
  return self_type::localize_helper(TextView{text, strlen(text) + 1},
                                    !SHOULD_LOWER);
}

swoc::TextView HttpHeader::localize_lower(char const *text) {
  return self_type::localize_lower(TextView{text, strlen(text) + 1});
}

swoc::TextView HttpHeader::localize(TextView text) {

  return HttpHeader::localize_helper(text, !SHOULD_LOWER);
}

swoc::TextView HttpHeader::localize_lower(TextView text) {
  // _names.find() does a case insensitive lookup, so cache lookup via _names
  // only should be used for case-insensitive localization. It's value applies
  // to well-known, common strings such as HTTP headers.
  auto spot = _names.find(text);
  if (spot != _names.end()) {
    return *spot;
  }
  return HttpHeader::localize_helper(text, SHOULD_LOWER);
}

swoc::TextView HttpHeader::localize_helper(TextView text, bool should_lower) {
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

swoc::TextView HttpHeader::localize(TextView text, Encoding enc) {
  if (Encoding::URI == enc) {
    auto span{_arena.require(text.size()).remnant().rebind<char>()};
    auto spot = text.begin(), limit = text.end();
    char *dst = span.begin();
    while (spot < limit) {
      if (*spot == '%' && (spot + 1 < limit && isxdigit(spot[1]) &&
                           (spot + 2 < limit && isxdigit(spot[2])))) {
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

bool icompare_pred(unsigned char a, unsigned char b) {
  return std::tolower(a) == std::tolower(b);
}

bool icompare(swoc::TextView const &a, swoc::TextView const &b) {
  if (a.length() == b.length()) {
    return std::equal(b.begin(), b.end(), a.begin(), icompare_pred);
  } else {
    return false;
  }
}

swoc::Rv<HttpHeader::ParseResult>
HttpHeader::parse_request(swoc::TextView data) {
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
      // Split out the path and scheme for http/2 required headers
      std::size_t offset = _url.find("://");
      if (offset != std::string::npos) {
        _scheme = _url.substr(offset);
      }
      offset = _url.find("/", offset);
      if (offset != std::string::npos) {
        _path = _url.substr(offset + 1);
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
          _fields_rules->_fields.emplace(name, value);
          if (icompare(name, "expect") && icompare(value, "100-continue")) {
            _send_continue = true;
          }
        } else {
          zret = PARSE_ERROR;
          zret.errata().error(R"(Malformed field "{}".)", field);
        }
      }
    } else {
      zret = PARSE_ERROR;
      zret.errata().error("Empty first line in request.");
    }
  }
  return std::move(zret);
}

swoc::Rv<HttpHeader::ParseResult>
HttpHeader::parse_response(swoc::TextView data) {
  swoc::Rv<ParseResult> zret{PARSE_OK};
  auto eoh = data.find(HTTP_EOH);

  if (swoc::TextView::npos == eoh) {
    zret = PARSE_INCOMPLETE;
  } else {
    data = data.prefix(eoh);

    auto first_line{data.take_prefix_at('\n').rtrim_if(&isspace)};
    if (first_line) {
      auto version{first_line.take_prefix_if(&isspace)};
      auto status{first_line.ltrim_if(&isspace).take_prefix_if(&isspace)};
      _status = swoc::svtou(status);

      while (data) {
        auto field{data.take_prefix_at('\n').rtrim_if(&isspace)};
        if (field.empty()) {
          continue;
        }
        auto value{field};
        auto name{value.take_prefix_at(':')};
        value.trim_if(&isspace);
        if (name) {
          _fields_rules->_fields.emplace(name, value);
        } else {
          zret = PARSE_ERROR;
          zret.errata().error(R"(Malformed field "{}".)", field);
        }
      }
    } else {
      zret = PARSE_ERROR;
      zret.errata().error("Empty first line in response.");
    }
  }
  return std::move(zret);
}

swoc::BufferWriter &HttpHeader::Binding::
operator()(BufferWriter &w, const swoc::bwf::Spec &spec) const {
  static constexpr TextView FIELD_PREFIX{"field."};
  TextView name{spec._name};
  if (name.starts_with_nocase(FIELD_PREFIX)) {
    name.remove_prefix(FIELD_PREFIX.size());
    if (auto spot{_hdr._fields_rules->_fields.find(name)};
        spot != _hdr._fields_rules->_fields.end()) {
      bwformat(w, spec, spot->second);
    } else {
      bwformat(w, spec, "*N/A*");
    }
  } else if (0 == strcasecmp("url"_tv, name)) {
    bwformat(w, spec, _hdr._url);
  } else {
    bwformat(w, spec, "*N/A*");
  }
  return w;
}

namespace swoc {
BufferWriter &bwformat(BufferWriter &w, bwf::Spec const &spec,
                       HttpHeader const &h) {
  w.write("Headers:\n"sv);
  for (auto const &[key, value] : h._fields_rules->_fields) {
    w.print(R"(- "{}": "{}"{})", key, value, '\n');
  }
  return w;
}

BufferWriter &bwformat(BufferWriter &w, bwf::Spec const &spec,
                       bwf::SSLError const &error) {

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
  if (spec.has_numeric_type()) { // if numeric type, print just the numeric
                                 // part.
    w.print(number_fmt, error._e);
  } else {
    w.write(short_name(error._e));
    w.write(ERR_reason_error_string(error._e));
    if (spec._type != 's' && spec._type != 'S') {
      w.write(' ');
      w.print(number_fmt, error._e);
    }
  }
  return w;
}
} // namespace swoc

swoc::Errata Load_Replay_File(swoc::file::path const &path,
                              ReplayFileHandler &handler) {
  auto errata = handler.file_open(path);
  if (errata.is_ok()) {
    std::error_code ec;
    std::string content{swoc::file::load(path, ec)};
    if (ec.value()) {
      errata.error(R"(Error loading "{}": {})", path, ec);
    } else {
      YAML::Node root;
      auto global_fields_rules = std::make_shared<HttpFields>();
      try {
        root = YAML::Load(content);
        yaml_merge(root);
      } catch (std::exception const &ex) {
        errata.warn(R"(Exception: {} in "{}".)", ex.what(), path);
      }
      if (errata.is_ok()) {
        if (root[YAML_META_KEY]) {
          auto meta_node{root[YAML_META_KEY]};
          if (meta_node[YAML_GLOBALS_KEY]) {
            auto globals_node{meta_node[YAML_GLOBALS_KEY]};
            // Path not passed to later calls than Load_Replay_File.
            errata.note(global_fields_rules->parse_global_rules(globals_node));
          }
        } else {
          errata.info(R"(No meta node ("{}") at "{}":{}.)", YAML_META_KEY, path,
                      root.Mark().line);
        }
        handler.global_config = VerificationConfig{global_fields_rules};
        if (root[YAML_SSN_KEY]) {
          auto ssn_list_node{root[YAML_SSN_KEY]};
          if (ssn_list_node.IsSequence()) {
            if (ssn_list_node.size() > 0) {
              for (auto const &ssn_node : ssn_list_node) {
                // HeaderRules ssn_rules = global_rules;
                auto result{handler.ssn_open(ssn_node)};
                if (result.is_ok()) {
                  if (ssn_node[YAML_TXN_KEY]) {
                    auto txn_list_node{ssn_node[YAML_TXN_KEY]};
                    if (txn_list_node.IsSequence()) {
                      if (txn_list_node.size() > 0) {
                        for (auto const &txn_node : txn_list_node) {
                          // HeaderRules txn_rules = ssn_rules;
                          result = handler.txn_open(txn_node);
                          if (result.is_ok()) {
                            HttpFields all_fields;
                            if (auto all_node{txn_node[YAML_ALL_MESSAGES_KEY]};
                                all_node) {
                              if (auto headers_node{all_node[YAML_HDR_KEY]};
                                  headers_node) {
                                result.note(all_fields.parse_global_rules(
                                    headers_node));
                              }
                            }
                            if (auto creq_node{txn_node[YAML_CLIENT_REQ_KEY]};
                                creq_node) {
                              result.note(handler.client_request(creq_node));
                            }
                            if (auto preq_node{txn_node[YAML_PROXY_REQ_KEY]};
                                preq_node) { // global_rules appears to be being
                                             // copied
                              result.note(handler.proxy_request(preq_node));
                            }
                            if (auto ursp_node{txn_node[YAML_SERVER_RSP_KEY]};
                                ursp_node) {
                              result.note(handler.server_response(ursp_node));
                            }
                            if (auto prsp_node{txn_node[YAML_PROXY_RSP_KEY]};
                                prsp_node) {
                              result.note(handler.proxy_response(prsp_node));
                            }
                            if (!all_fields._fields.empty()) {
                              result.note(
                                  handler.apply_to_all_messages(all_fields));
                            }
                            result.note(handler.txn_close());
                          }
                        }
                      } else {
                        result.info(
                            R"(Transaction list at {} in session at {} in "{}" is an empty list.)",
                            txn_list_node.Mark(), ssn_node.Mark(), path);
                      }
                    } else {
                      result.error(
                          R"(Transaction list at {} in session at {} in "{}" is not a list.)",
                          txn_list_node.Mark(), ssn_node.Mark(), path);
                    }
                  } else {
                    result.error(R"(Session at "{}":{} has no "{}" key.)", path,
                                 ssn_node.Mark().line, YAML_TXN_KEY);
                  }
                  result.note(handler.ssn_close());
                }
                errata.note(result);
              }
            } else {
              errata.diag(R"(Session list at "{}":{} is an empty list.)", path,
                          ssn_list_node.Mark().line);
            }
          } else {
            errata.error(R"("{}" value at "{}":{} is not a sequence.)",
                         YAML_SSN_KEY, path, ssn_list_node.Mark());
          }
        } else {
          errata.error(R"(No sessions list ("{}") at "{}":{}.)", YAML_META_KEY,
                       path, root.Mark().line);
        }
      }
    }
    handler.file_close();
  }
  return std::move(errata);
}

swoc::Errata
Load_Replay_Directory(swoc::file::path const &path,
                      swoc::Errata (*loader)(swoc::file::path const &),
                      int n_threads) {
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
        ".", &elements,
        [](const dirent *entry) -> int {
          auto extension =
              swoc::TextView{entry->d_name, strlen(entry->d_name)}.suffix_at(
                  '.');
          return 0 == strcasecmp(extension, "json") ||
                 0 == strcasecmp(extension, "yaml");
        },
        &alphasort);
    if (n_sessions > 0) {
      std::atomic<int> idx{0};
      swoc::MemSpan<dirent *> entries{elements,
                                      static_cast<size_t>(n_sessions)};

      // Lambda suitable to spawn in a thread to load files.
      auto load_wrapper = [&]() -> void {
        int k = 0;
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
    } else {
      errata.error(R"(No replay files found in "{}".)", path);
    }
  } else {
    errata.error(R"(Failed to access directory "{}": {}.)", path,
                 swoc::bwf::Errno{});
  }
  return std::move(errata);
}

swoc::Errata parse_ips(std::string arg, std::deque<swoc::IPEndpoint> &target) {
  swoc::Errata errata;
  int offset = 0;
  int new_offset = 0;
  while (offset != std::string::npos) {
    new_offset = arg.find(',', offset);
    std::string name = arg.substr(offset, new_offset - offset);
    offset = new_offset != std::string::npos ? new_offset + 1 : new_offset;
    swoc::IPEndpoint addr;
    if (!addr.parse(name)) {
      errata.error(R"("{}" is not a valid IP address.)", name);
      return std::move(errata);
    }
    target.push_back(addr);
  }
  return std::move(errata);
}

swoc::Errata resolve_ips(std::string arg,
                         std::deque<swoc::IPEndpoint> &target) {
  swoc::Errata errata;
  int offset = 0;
  int new_offset = 0;
  while (offset != std::string::npos) {
    new_offset = arg.find(',', offset);
    std::string name = arg.substr(offset, new_offset - offset);
    offset = new_offset != std::string::npos ? new_offset + 1 : new_offset;
    auto &&[tmp_target, result] = Resolve_FQDN(name);
    if (!result.is_ok()) {
      errata.error(R"("{}" is not a valid IP address.)", name);
      return std::move(errata);
    }
    target.push_back(tmp_target);
  }
  return std::move(errata);
}

swoc::Rv<swoc::IPEndpoint> Resolve_FQDN(swoc::TextView fqdn) {
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
            zret.errata().error(R"(Failed to resolve "{}": {}.)", host_str,
                                swoc::bwf::Errno(result));
          }
        }
      } else {
        zret.errata().error(R"(Port value {} out of range [ 1 .. {} ].)",
                            port_str, MAX_PORT);
      }
    } else {
      zret.errata().error(
          R"(Address "{}" does not have the require port specifier.)", fqdn);
    }

  } else {
    zret.errata().error(R"(Malformed address "{}".)", fqdn);
  }
  return std::move(zret);
}

using namespace std::chrono_literals;

void ThreadPool::wait_for_work(ThreadInfo *thread_info) {
  // ready to roll, add to the pool.
  {
    std::unique_lock<std::mutex> lock(_threadPoolMutex);
    _threadPool.push_back(thread_info);
    _threadPoolCvar.notify_all();
  }

  // wait for a notification there's a session to process.
  {
    std::unique_lock<std::mutex> lock(thread_info->_mutex);
    bool condition_awoke = false;
    while (!thread_info->data_ready() && !condition_awoke) {
      thread_info->_cvar.wait_for(lock, 100ms);
    }
  }
}

ThreadInfo *ThreadPool::get_worker() {
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

void ThreadPool::join_threads() {
  for (auto &thread : _allThreads) {
    thread.join();
  }
}
