/** @file
 * Common implementation for Proxy Verifier
 *
 * Copyright 2021, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "core/https.h"
#include "core/ProxyVerifier.h"

#include <dirent.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "swoc/bwf_ex.h"
#include "swoc/bwf_ip.h"
#include "swoc/bwf_std.h"

using swoc::Errata;
using swoc::TextView;
using namespace swoc::literals;
using namespace std::literals;

namespace chrono = std::chrono;
using chrono::milliseconds;

std::unordered_map<std::string, TLSHandshakeBehavior> TLSSession::_handshake_behavior_per_sni;

std::mutex TLSSession::tls_secrets_log_file_fd_mutex;
int TLSSession::tls_secrets_log_file_fd = -1;
swoc::file::path TLSSession::tls_secrets_log_file;

namespace swoc
{
inline namespace SWOC_VERSION_NS
{
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
    auto const *error_reason = ERR_reason_error_string(error._e);
    if (error_reason != nullptr) {
      w.write(error_reason);
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
  unsigned char const *alpn = protocol_negotiation_string;
  int alpn_len = protocol_negotiation_len;

  if (sni != nullptr) {
    std::string_view alpn_protocol_string = TLSSession::get_alpn_protocol_string_for_sni(sni);
    if (!alpn_protocol_string.empty()) {
      alpn = reinterpret_cast<unsigned char const *>(alpn_protocol_string.data());
      alpn_len = alpn_protocol_string.size();
    }
  }

  Errata errata;
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
  if (SSL_select_next_proto(
          out,
          outlen,
          protocol_negotiation_string,
          protocol_negotiation_len,
          in,
          inlen) == OPENSSL_NPN_NEGOTIATED)
  {
    return SSL_TLSEXT_ERR_OK;
  }
  *out = nullptr;
  *outlen = 0;
  return SSL_TLSEXT_ERR_NOACK;
}

int
advertise_next_protocol_cb(
    SSL * /* ssl */,
    unsigned char const **out,
    unsigned int *outlen,
    void * /* arg */)
{
  *out = protocol_negotiation_string;
  *outlen = protocol_negotiation_len;
  return SSL_TLSEXT_ERR_OK;
}
#endif /* !OPENSSL_NO_NEXTPROTONEG */

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

TLSSession::TLSSession(TextView const &client_sni, int client_verify_mode)
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
TLSSession::write(TextView view)
{
  TextView remaining = view;
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

// Complete the TLS handshake (server-side).
Errata
TLSSession::accept()
{
  Errata errata;
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
Errata
TLSSession::connect()
{
  return this->connect(client_context);
}

// Complete the TLS handshake (client-side).
Errata
TLSSession::connect(SSL_CTX *client_context)
{
  Errata errata;
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

// static
Errata
TLSSession::init(TextView tls_secrets_log_file)
{
  SSL_load_error_strings();
  SSL_library_init();
  Errata errata = TLSSession::client_init(client_context);
  errata.note(TLSSession::server_init(server_context));
  if (!tls_secrets_log_file.empty()) {
    errata.note(open_tls_secrets_log_file(tls_secrets_log_file));
  }
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

// static
swoc::Errata
TLSSession::open_tls_secrets_log_file(TextView tls_secrets_log_file)
{
  Errata errata;
  tls_secrets_log_file_fd = -1;
  if (tls_secrets_log_file.empty()) {
    return errata;
  }

  tls_secrets_log_file_fd = ::open(
      tls_secrets_log_file.data(),
      O_WRONLY | O_CREAT | O_APPEND,
      S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

  if (tls_secrets_log_file_fd < 0) {
    errata.error(
        "Failed to open TLS secrets log file {}: {}",
        tls_secrets_log_file,
        swoc::bwf::Errno{});
    return errata;
  }
  errata.diag("Writing TLS secrets to: {}", tls_secrets_log_file);
  return errata;
}

int
client_hello_callback(SSL *ssl, int * /* al */, void * /* arg */)
{
  int ret = SSL_CLIENT_HELLO_SUCCESS;
  Errata errata;

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
Errata
TLSSession::configure_host_cert(
    std::string_view _cert_path,
    std::string_view public_file,
    std::string_view private_file)
{
  Errata errata;
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
Errata
TLSSession::configure_client_cert(std::string_view cert_path)
{
  return TLSSession::configure_host_cert(cert_path, "client.pem", "client.key");
}

// static
Errata
TLSSession::configure_server_cert(std::string_view cert_path)
{
  return TLSSession::configure_host_cert(cert_path, "server.pem", "server.key");
}

// static
Errata
TLSSession::configure_ca_cert(std::string_view _cert_path)
{
  Errata errata;
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
Errata
TLSSession::configure_certificates(SSL_CTX *&context)
{
  Errata errata;
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
bool
TLSSession::tls_secrets_are_being_logged()
{
  return tls_secrets_log_file_fd != -1;
}

// static
void
TLSSession::keylog_callback(SSL const * /* ssl */, char const *line)
{
  if (tls_secrets_log_file_fd == -1) {
    // Likely a previous write has failed and the log was closed.
    return;
  }
  Errata errata;
  std::scoped_lock _{tls_secrets_log_file_fd_mutex};
  ssize_t rc = ::write(tls_secrets_log_file_fd, line, strlen(line));
  if (rc == -1) {
    errata.error("Failed to write to TLS secrets log file: {}", swoc::bwf::Errno{});
    ::close(tls_secrets_log_file_fd);
    tls_secrets_log_file_fd = -1;
  }

  constexpr char const *LF = "\n";
  rc = ::write(tls_secrets_log_file_fd, LF, strlen(LF));
  if (rc == -1) {
    errata.error("Failed to write to TLS secrets log file: {}", swoc::bwf::Errno{});
    ::close(tls_secrets_log_file_fd);
    tls_secrets_log_file_fd = -1;
  }
}

// static
Errata
TLSSession::client_init(SSL_CTX *&client_context)
{
  Errata errata;
  client_context = SSL_CTX_new(TLS_client_method());
  if (!client_context) {
    errata.error(R"(Failed to create client_context: {}.)", swoc::bwf::SSLError{});
    return errata;
  }
  errata.note(configure_certificates(client_context));

  if (tls_secrets_are_being_logged()) {
    SSL_CTX_set_keylog_callback(client_context, keylog_callback);
  }
  return errata;
}

Errata
TLSSession::server_init(SSL_CTX *&server_context)
{
  Errata errata;
  server_context = SSL_CTX_new(TLS_server_method());
  if (!server_context) {
    errata.error(R"(Failed to create server_context: {}.)", swoc::bwf::SSLError{});
    return errata;
  }
  errata.note(configure_certificates(server_context));

  /* Register for the client hello callback so we can inspect the SNI
   * for dynamic server behavior (such as requesting a client cert). */
  SSL_CTX_set_client_hello_cb(server_context, client_hello_callback, nullptr);

  if (tls_secrets_are_being_logged()) {
    SSL_CTX_set_keylog_callback(server_context, keylog_callback);
  }

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
