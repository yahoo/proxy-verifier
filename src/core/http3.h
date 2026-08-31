/** @file
 * Common data structures and definitions for HTTP/3 support.
 *
 * Copyright 2026, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "http.h"

#include <chrono>
#include <deque>
#include <list>
#include <memory>
#include <nghttp3/nghttp3.h>
#include <openssl/ssl.h>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "swoc/Errata.h"
#include "swoc/MemArena.h"
#include "swoc/swoc_file.h"
#include "swoc/swoc_ip.h"
#include "swoc/TextView.h"

class HttpHeader;
struct Txn;

/** The OpenSSL QUIC connection and its HTTP/3 streams. */
class QuicSocket
{
public:
  QuicSocket() = default;
  ~QuicSocket();
  QuicSocket(QuicSocket const &) = delete;
  QuicSocket &operator=(QuicSocket const &) = delete;

  /** Release the current QUIC connection and all associated streams. */
  void reset();

  /** Create a locally initiated QUIC stream.
   *
   * @param[in] unidirectional Whether to create a unidirectional stream.
   * @return The new stream, or error diagnostics.
   */
  swoc::Rv<SSL *> open_stream(bool unidirectional);

  /** Record a remotely initiated QUIC stream.
   *
   * @param[in] stream The OpenSSL stream object to own.
   */
  void add_stream(SSL *stream);

  /** Look up an OpenSSL stream by its QUIC stream identifier.
   *
   * @param[in] stream_id The QUIC stream identifier.
   * @return The stream object, or @c nullptr if it is not registered.
   */
  SSL *find_stream(int64_t stream_id) const;

  /** Configure QUIC logging for the provided directory.
   *
   * OpenSSL's native QUIC API does not currently expose qlog events. The
   * directory is still created and validated so the existing command-line
   * option remains compatible and can become active when OpenSSL adds that
   * support.
   *
   * @param[in] qlog_dir The directory into which QUIC log files should be
   * written.
   */
  static swoc::Errata configure_qlog_dir(swoc::TextView qlog_dir);

public:
  SSL *connection = nullptr;                            ///< The OpenSSL QUIC connection object.
  nghttp3_conn *h3conn = nullptr;                       ///< The nghttp3 connection object.
  std::unordered_map<int64_t, SSL *> streams;           ///< QUIC streams by stream identifier.
  std::unordered_set<int64_t> streams_with_fin;         ///< Streams whose receive side has ended.
  std::unordered_set<int64_t> streams_concluded;        ///< Streams whose send side has ended.
  std::unordered_set<int64_t> streams_pending_conclude; ///< Streams waiting to send FIN.

private:
  static swoc::file::path m_qlog_dir;
};

/** Representation of an HTTP/3 stream (a single transaction). */
class H3StreamState
{
public:
  /** Construct stream state.
   *
   * @param[in] is_client Whether this stream sends a request and receives a
   * response.
   */
  explicit H3StreamState(bool is_client);
  ~H3StreamState();

  /** Return whether this stream receives a request. */
  bool will_receive_request() const;

  /** Return whether this stream receives a response. */
  bool will_receive_response() const;

  /** Set the QUIC stream identifier.
   *
   * @param[in] stream_id The stream identifier.
   */
  void set_stream_id(int64_t stream_id);

  /** Return the QUIC stream identifier. */
  int64_t get_stream_id() const;

  /** Retain an nghttp3 reference-counted buffer and return a view of it.
   *
   * @param[in] rcbuf The nghttp3 buffer to retain.
   * @return A view of the buffer contents.
   */
  swoc::TextView register_rcbuf(nghttp3_rcbuf *rcbuf);

public:
  std::string key; ///< The key identifying this HTTP transaction.

  /** Storage for a URL composed from request pseudo headers. */
  std::string composed_url;

  bool have_received_headers = false; ///< Whether headers have been received.
  std::chrono::time_point<std::chrono::steady_clock> stream_start; ///< Stream start time.
  std::shared_ptr<HttpHeader> request_from_client;  ///< The received request headers.
  std::shared_ptr<HttpHeader> response_from_server; ///< The received response headers.
  HttpHeader const *specified_request = nullptr;    ///< Expected request headers.
  HttpHeader const *specified_response = nullptr;   ///< Expected response headers.
  std::string body_received;                        ///< The received body.
  swoc::TextView body_to_send;                      ///< The body to send.
  bool wait_for_continue = false;    ///< Whether the request waits for a 100 response.
  size_t num_data_bytes_written = 0; ///< Unacknowledged DATA payload bytes.

  /** How long to wait after the HEADERS frame is on the wire before the DATA
   * frame is sent.
   *
   * This is the @c content @c delay of the message being written. It is zero
   * for messages which do not specify one. While it is non-zero the nghttp3
   * data reader reports that it would block so that only the HEADERS frame is
   * flushed. H3Session::write zeroes it and resumes the stream once the delay
   * has elapsed.
   */
  std::chrono::microseconds content_delay{0};

private:
  bool m_will_receive_request = false;
  int64_t m_stream_id = 0;
  std::deque<nghttp3_rcbuf *> m_rcbufs_to_free;
};

/** Representation of a client-side HTTP/3 connection. */
class H3Session : public Session
{
public:
  using super_type = Session;

  H3Session();
  H3Session(swoc::TextView const &client_sni, int client_verify_mode = SSL_VERIFY_NONE);
  ~H3Session() override;

  swoc::Rv<ssize_t> read(swoc::MemSpan<char> span) override;
  swoc::Rv<ssize_t> write(swoc::TextView data) override;
  swoc::Rv<ssize_t> write(HttpHeader const &hdr) override;

  /** Populate nghttp3 name/value entries from an HTTP header.
   *
   * @param[in] hdr The header to convert.
   * @param[out] nv_hdr The allocated name/value array.
   * @param[out] hdr_count The number of populated entries.
   * @return Any conversion diagnostics.
   */
  swoc::Errata pack_headers(HttpHeader const &hdr, nghttp3_nv *&nv_hdr, int &hdr_count);

  swoc::Rv<int> poll_for_headers(std::chrono::milliseconds timeout) override;
  swoc::Rv<std::shared_ptr<HttpHeader>> read_and_parse_request(swoc::FixedBufferWriter &w) override;
  swoc::Rv<size_t> drain_body(
      HttpHeader const &hdr,
      size_t expected_content_size,
      swoc::TextView bytes_read,
      std::shared_ptr<RuleCheck> rule_check = nullptr) override;

  /** Report that server-side OpenSSL QUIC is unsupported. */
  swoc::Errata accept() override;

  /** Complete the client-side QUIC handshake. */
  swoc::Errata connect() override;

  /** Establish an HTTP/3 connection.
   *
   * @param[in] interface The optional local interface.
   * @param[in] target The remote endpoint.
   * @param[in] pp_msg Ignored because QUIC does not support PROXY protocol.
   * @return Connection diagnostics.
   */
  swoc::Errata do_connect(
      swoc::TextView interface,
      swoc::IPEndpoint const *target,
      ProxyProtocolMsg *pp_msg = nullptr) override;

  /** Perform process-wide HTTP/3 initialization.
   *
   * @param[in] process_exit_code The exit status updated on verification
   * failures.
   * @param[in] qlog_dir The requested qlog directory.
   * @return Initialization diagnostics.
   */
  static swoc::Errata init(int *process_exit_code, swoc::TextView qlog_dir);

  /** Release process-wide HTTP/3 resources. */
  static void terminate();

  /** Mark the process exit status as unsuccessful. */
  static void set_non_zero_exit_status();

  swoc::Errata run_transactions(
      std::list<Txn> const &transactions,
      swoc::TextView interface,
      swoc::IPEndpoint const *target,
      double rate_multiplier) override;
  swoc::Errata run_transaction(Txn const &transaction) override;

  /** Record that a stream has ended.
   *
   * @param[in] stream_id The ended stream identifier.
   * @param[in] key The transaction key.
   */
  void set_stream_has_ended(int64_t stream_id, std::string_view key);

  /** Return whether a completed stream is ready for processing. */
  bool get_a_stream_has_ended() const;

  /** Associate HTTP/3 state with a QUIC stream.
   *
   * @param[in] stream_id The stream identifier.
   * @param[in] stream_state The state to associate.
   */
  void record_stream_state(int64_t stream_id, std::shared_ptr<H3StreamState> stream_state);

  /** Remember a response finalized before its close callback.
   *
   * nghttp3 keeps a raw pointer to the stream state as its stream user data and
   * hands it back to the data reader. The stream is dropped from @a stream_map
   * as soon as the peer ends its half of it, which can happen while our own
   * body is still queued behind a content delay or flow control, so ownership
   * is parked here until nghttp3 reports the stream closed.
   *
   * @param[in] stream_id The stream identifier.
   * @param[in] stream_state The state to retain until the close callback.
   */
  void mark_completed_response_stream(
      int64_t stream_id,
      std::shared_ptr<H3StreamState> stream_state);

  /** Remove a remembered finalized response stream.
   *
   * @param[in] stream_id The stream identifier.
   * @return Whether the stream was remembered.
   */
  bool clear_completed_response_stream(int64_t stream_id);

public:
  std::unordered_map<int64_t, std::shared_ptr<H3StreamState>> stream_map;
  QuicSocket quic_socket;

protected:
  /** Initialize the client-side OpenSSL QUIC context. */
  static swoc::Errata client_ssl_ctx_init(SSL_CTX *&client_context);

  /** Server-side HTTP/3 is not implemented. */
  static swoc::Errata server_ssl_ctx_init(SSL_CTX *&server_context);

  /** Release an SSL context.
   *
   * @param[in,out] client_context The context to release and clear.
   */
  static void terminate(SSL_CTX *&client_context);

protected:
  std::string m_client_sni;
  int m_client_verify_mode = SSL_VERIFY_NONE;

private:
  nghttp3_nv tv_to_nv(char const *name, swoc::TextView v);
  swoc::Errata configure_udp_socket(swoc::TextView interface, swoc::IPEndpoint const *target);
  swoc::Errata client_ssl_session_init(SSL_CTX *client_context);
  swoc::Errata initialize_http3_connection();
  swoc::Errata receive_responses();

  /** Wait out the @c content @c delay of a message whose body is withheld.
   *
   * The connection is serviced for the duration of the wait so that incoming
   * packets, including a peer closing the connection, are processed rather than
   * stalled behind the delay.
   *
   * @param[in,out] stream_state The stream whose body is withheld. Its
   * @c content_delay is zeroed and the stream resumed before returning.
   *
   * @return Any errata from servicing the connection during the delay.
   */
  swoc::Errata content_delay(H3StreamState &stream_state);

  bool request_has_outstanding_stream_dependencies(HttpHeader const &request) const;

private:
  std::deque<int64_t> m_ended_streams;
  swoc::IPEndpoint const *m_endpoint = nullptr;
  std::unordered_set<std::string> m_finished_streams;

  /// Streams finalized on their end-stream callback, held until they are closed.
  std::unordered_map<int64_t, std::shared_ptr<H3StreamState>> m_completed_response_streams;

  /** The expected response to attach to the next request stream @c write creates.
   *
   * @c write services incoming packets while it holds a content delay, so the
   * expected response has to be on the stream before the request headers go out
   * rather than after @c write returns. Otherwise a response which arrives
   * ahead of the delayed request body is not verified against.
   */
  HttpHeader const *m_specified_response_for_next_request = nullptr;

  static SSL_CTX *m_h3_client_context;
  static SSL_CTX *m_h3_server_context;
  static int *m_process_exit_code;
};
