/** @file
 * Common data structures and definitions for Proxy Verifier tools.
 *
 * Copyright 2021, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "http.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>

#include "swoc/BufferWriter.h"
#include "swoc/bwf_base.h"
#include "swoc/Errata.h"
#include "swoc/MemArena.h"
#include "swoc/swoc_file.h"
#include "swoc/TextView.h"

class HttpHeader;

constexpr unsigned char protocol_negotiation_string[] =
    {2, 'h', '2', 7, 'h', 't', 't', 'p', '1', '.', '1'};
constexpr int protocol_negotiation_len = sizeof(protocol_negotiation_string);

int client_hello_callback(SSL *ssl, int * /* al */, void * /* arg */);

/** The callback for SSL_CTX_set_alpn_select_cb.
 *
 * This sets the protocols that the server will negotiate via ALPN.
 */
int alpn_select_next_proto_cb(
    SSL *ssl,
    unsigned char const **out,
    unsigned char *outlen,
    unsigned char const *in,
    unsigned int inlen,
    void * /* arg */);

#ifndef OPENSSL_NO_NEXTPROTONEG
/** The callback for SSL_CTX_set_next_proto_select_cb.
 *
 * This guides the client in the selection of a protocl via NPN.
 */
int select_next_proto_cb(
    SSL * /* ssl */,
    unsigned char **out,
    unsigned char *outlen,
    unsigned char const *in,
    unsigned int inlen,
    void * /* arg */);

/** The callback for SSL_CTX_set_next_protos_advertised_cb.
 *
 * This instructs the server for what protocols it will advertise via NPN.
 */
int advertise_next_protocol_cb(
    SSL * /* ssl */,
    unsigned char const **out,
    unsigned int *outlen,
    void * /* arg */);
#endif /* !OPENSSL_NO_NEXTPROTONEG */

/** Get a printable version of the ALPN wire format string.
 *
 * For example, given this character array:
 * {2, 'h', '2', 7, 'h', 't', 't', 'p', '1', '.', '1'}
 *
 * This will return:
 * "h2,http1.1"
 *
 * @param[in] alpn_wire_string The alpn char array as passed to
 * SSL_select_next_proto.
 *
 * @return a printable version of the alpn string.
 */
std::string get_printable_alpn_string(std::string_view alpn_wire_string);

namespace swoc
{
inline namespace SWOC_VERSION_NS
{
namespace bwf
{
/** Format wrapper for @c errno.
 * This stores a copy of the argument or @c errno if an argument isn't provided.
 * The output is then formatted with the short, long, and numeric value of @c
 * errno. If the format specifier is type 'd' then just the numeric value is
 * printed.
 */
struct SSLError
{
  unsigned long _e;
  explicit SSLError() : _e(ERR_peek_last_error()) { }
  explicit SSLError(int e) : _e(e) { }
  explicit SSLError(SSL const *ssl, int e) : _e(SSL_get_error(ssl, e)) { }
};
} // namespace bwf

BufferWriter &bwformat(BufferWriter &w, bwf::Spec const &spec, bwf::SSLError const &error);
} // namespace SWOC_VERSION_NS
} // namespace swoc

/** A class encapsulating how Proxy Verifier should behave in a TLS handshake.
 *
 * This is used by the Verifier Server. Instances of this are keyed off of SNI.
 */
class TLSHandshakeBehavior
{
public:
  TLSHandshakeBehavior() = default;
  // Make sure we don't accidentally copy these.
  TLSHandshakeBehavior(TLSHandshakeBehavior const &) = delete;
  TLSHandshakeBehavior(TLSHandshakeBehavior &&) = default;
  TLSHandshakeBehavior &operator=(TLSHandshakeBehavior &&) = default;
  ~TLSHandshakeBehavior() = default;

  /** Set the TLS verify mode to use via SSL_set_verify. */
  void set_verify_mode(int verify_mode);

  /** A getter for the TLS verify mode set via set_verify_mode. */
  int get_verify_mode() const;

  /** Set the raw bytes to use in SSL_select_next_proto to specify
   * the server's accepted protocols.
   *
   * @param[in] alpn_protocols The protos string accepted by
   * SSL_select_next_proto. This has its own specific length-value structure.
   * See https://www.openssl.org/docs/man1.1.0/man3/SSL_set_alpn_protos.html
   * for details.
   */
  void set_alpn_protocols_string(std::string_view alpn_protocols);

  /** A getter for the string set via set_alpn_protocols_string. */
  std::string_view get_alpn_wire_string() const;

private:
  /// The verify mode to pass to SSL_set_verify().
  int _verify_mode = SSL_VERIFY_NONE;
  /// The exact set of bytes to pass to SSL_CTX_set_alpn_protos.
  std::string _alpn_wire_string;
};

class TLSSession : public Session
{
public:
  using super_type = Session;

  TLSSession() = default;
  TLSSession(swoc::TextView const &client_sni, int client_verify_mode = SSL_VERIFY_NONE);
  ~TLSSession() override;

  /** @see Session::read */
  swoc::Rv<ssize_t> read(swoc::MemSpan<char> span) override;
  /** @see Session::write */
  swoc::Rv<ssize_t> write(swoc::TextView data) override;
  /** @see Session::write */
  swoc::Rv<ssize_t>
  write(HttpHeader const &hdr) override
  {
    // The base Session::write will serialize the header then polymorphically
    // call the TLSSession::write(TextView) version.
    return Session::write(hdr);
  }

  /** Poll until there is data on the socket after an SSL operation fails.
   *
   * Note that Proxy Verifier is organized using non-blocking sockets in which
   * read or write operations are attempted with a poll used after EAGAIN or
   * SSL_ERROR_WANT_READ/WRITE errors. This handles the poll for the latter
   * such SSL errors.
   *
   * @param[in] timeout The timeout, in milliseconds, for the poll.
   * @param[in] ssl_error The ssl_error retrieved after an SSL_write or SSL_read failure.
   *
   * @return 0 if the poll timed out, -1 on failure or the socket is closed, a
   * positive value on success.
   */
  virtual swoc::Rv<int> poll_for_data_on_ssl_socket(
      std::chrono::milliseconds timeout,
      int ssl_error);

  /** @see Session::close */
  void close() override;
  /** @see Session::accept */
  swoc::Errata accept() override;
  /** @see Session::connect */
  swoc::Errata connect() override;
  swoc::Errata connect(SSL_CTX *ctx);

  SSL *
  get_ssl()
  {
    return _ssl;
  }

  // static members
  /** Perform global TLS initialization.
   *
   * @param[in] tls_secrets_log_file The file to which TLS secrets should be
   * logged. An empty string implies that TLS secrets will not be logged.
   */
  static swoc::Errata init(swoc::TextView tls_secrets_log_file);
  static void terminate();

  /** Register the TLS handshake verification mode of the server per the SNI.
   *
   * This function is only relevant to the server.
   *
   * This specifies what verification mode should be done against the client in
   * the TLS handshake if the client uses the given SNI in the client hello.
   *
   * @param[in] sni The SNI which is the key for the handshake behavior.
   *
   * @param[in] handshake_behavior Dictates how proxy verifier should behave
   * during a TLS handshake with the given SNI.
   */
  static void register_tls_handshake_behavior(
      std::string_view sni,
      TLSHandshakeBehavior &&handshake_behavior);

  /** A lookup function for the registered verification mode given the SNI.
   *
   * This function is only relevant to the server.
   *
   * @param[in] sni The SNI key from which the mode value is queried.
   *
   * @return The verification mode for the given SNI previously registered via
   * register_sni_for_client_verification. If no such SNI has been registered,
   * then SSL_VERIFY_NONE will be returned as a default.
   */
  static int get_verify_mode_for_sni(std::string_view sni);

  /** A lookup function for the registered alpn protocol string given the SNI.
   *
   * This function is only relevant to the server.
   *
   * @param[in] sni The SNI key from which the alpn string is queried.
   *
   * @return The wire format alpn protocol string for the given SNI previously
   * registered via register_sni_for_client_verification. If no such SNI has
   * been registered, then an empty string will be returned as a default.
   */
  static std::string_view get_alpn_protocol_string_for_sni(std::string_view sni);

  /** Configure the use of a client certificate.
   *
   * @param[in] cert_path The path to a directory with "client.pem" and
   * "client.key" files, or the path to a file with both the private and public
   * keys.
   *
   * @return logging and status information via an Errata.
   */
  static swoc::Errata configure_client_cert(std::string_view cert_path);

  /** Configure the use of a server certificate.
   *
   * @param[in] cert_path The path to a directory with "client.pem" and
   * "client.key" files, or the path to a file with both the private and public
   * keys.
   *
   * @return logging and status information via an Errata.
   */
  static swoc::Errata configure_server_cert(std::string_view cert_path);

  /** Configure the use of a CA.
   *
   * @param[in] cert_path The path to a directory contain CA files or a file
   * containing CA information.
   *
   * @return logging and status information via an Errata.
   */
  static swoc::Errata configure_ca_cert(std::string_view cert_path);

  /** Configure a host certificate.
   *
   * @param[in] cert_path The path to a directory with private and public key
   * files or the path to a file with both the private and public keys.
   *
   * @param[in] public_file The name to expect for the public file if cert_path
   * is a directory.
   *
   * @param[in] private_file The name to expect for the private file if
   * cert_path is a directory.
   *
   * @return logging and status information via an Errata.
   */
  static swoc::Errata configure_host_cert(
      std::string_view cert_path,
      std::string_view public_file,
      std::string_view private_key);

  /** Configure the context to use any provided certificates.
   *
   * @param[in] context The context upon which to configure the host and CA certificates.
   *
   * @return An errata indicating the status of the configuration.
   */
  static swoc::Errata configure_certificates(SSL_CTX *&context);

  /** Return whether TLS secrets are currently being logged.
   *
   * @return true if TLS secrets are currently being logged, false otherwise.
   */
  static bool tls_secrets_are_being_logged();

  /** The TLS secrets logging callback function.
   *
   * Pass this to SSL_CTX_set_keylog_callback. See the OpenSSL documentation
   * for details about this function.
   */
  static void keylog_callback(SSL const *ssl, char const *line);

public:
  /// The client or server public key file. This may also contain the private
  /// key.
  static swoc::file::path certificate_file;

  /// The client or server private key file if not in the certificate_file.
  static swoc::file::path privatekey_file;

  /// The CA file which may contain mutiple CA certs.
  static swoc::file::path ca_certificate_file;

  /// The CA directory containing one or more CA cert files.
  static swoc::file::path ca_certificate_dir;

protected:
  static swoc::Errata client_init(SSL_CTX *&client_context);
  static swoc::Errata server_init(SSL_CTX *&server_context);
  static void terminate(SSL_CTX *&context);

protected:
  SSL *_ssl = nullptr;
  /** The SNI to be sent by the client (as opposed to the one expected by the
   * server from the proxy). This only applies to the client.
   */
  std::string _client_sni;

  /** The verify mode for the client in the TLS handshake with the proxy.
   * This only applies to the client.
   */
  int _client_verify_mode = SSL_VERIFY_NONE;

  static SSL_CTX *server_context;
  static SSL_CTX *client_context;

  /** The handshake behavior of the verifier server against the proxy in the TLS
   * handshake as specified per the SNI received from the proxy.
   */
  static std::unordered_map<std::string, TLSHandshakeBehavior> _handshake_behavior_per_sni;

private:
  /** Open the file for TLS secrets logging.
   *
   * @param[in] tls_secrets_log_file The path to the file to open for logging.
   */
  static swoc::Errata open_tls_secrets_log_file(swoc::TextView tls_secrets_log_file);

private:
  /// A mutex to ensure serialized writing to tls_secrets_log_file_fd.
  static std::mutex tls_secrets_log_file_fd_mutex;

  /// The file descriptor for TLS secrets logging.
  static int tls_secrets_log_file_fd;

  /// The file to which TLS secrets will be logged.
  static swoc::file::path tls_secrets_log_file;
};
