/** @file
 * Common data structures and definitions for Proxy Verifier tools.
 *
 * Copyright 2021, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "https.h"

#include <chrono>
#include <deque>
#include <list>
#include <memory>
#include <openssl/ssl.h>
#include <nghttp2/nghttp2.h>
#include <string>
#include <unordered_map>

#include "swoc/BufferWriter.h"
#include "swoc/Errata.h"
#include "swoc/MemArena.h"
#include "swoc/swoc_ip.h"
#include "swoc/TextView.h"

class HttpHeader;
struct Txn;

class H2StreamState
{
public:
  H2StreamState();
  ~H2StreamState();

  /** Increment the nghttp2 reference count on buf and return a view of it.
   *
   * A reference count to the buffer will be held for the remainder of the
   * lifetime of the stream.
   *
   * @param[in] buf The nghttp2 ref counted buffer to register and for which a
   * TextView will be returned.
   *
   * @return A view representation of the given buffer.
   */
  swoc::TextView register_rcbuf(nghttp2_rcbuf *rcbuf);

  /** Indicate that the stream has closed. */
  void set_stream_has_closed();

  /** Return whether this stream has closed. */
  bool get_stream_has_closed() const;

  /** Set the stream_id for this and the appropriate members. */
  void set_stream_id(int32_t id);

  /** Retrieve the stream id for this stream. */
  int32_t get_stream_id() const;

  /** Store the nghttp2 response headers to be freed upon destruction. */
  void store_nv_response_headers_to_free(nghttp2_nv *hdrs);

  /** Store the nghttp2 request headers to be freed upon destruction. */
  void store_nv_request_headers_to_free(nghttp2_nv *hdrs);

public:
  size_t _send_body_offset = 0;
  char const *_body_to_send = nullptr;
  size_t _send_body_length = 0;
  size_t _received_body_length = 0;
  bool _wait_for_continue = false;
  std::string _key;
  /** The composed URL parts from :method, :authority, and :path pseudo headers
   * from the request.
   *
   * This is stored in this object to persist its storage because parse_url
   * assigns from this string TextViews.
   */
  std::string _composed_url;
  std::chrono::time_point<std::chrono::system_clock> _stream_start;
  HttpHeader const *_specified_response = nullptr;

  /// The HTTP request headers for this stream.
  std::shared_ptr<HttpHeader> _request_from_client;
  /// The HTTP response headers for this stream.
  std::shared_ptr<HttpHeader> _response_from_server;

private:
  int32_t _stream_id = -1;
  std::deque<nghttp2_rcbuf *> _rcbufs_to_free;
  bool _stream_has_closed = false;
  nghttp2_nv *_request_nv_headers = nullptr;
  nghttp2_nv *_response_nv_headers = nullptr;
};

class H2Session : public TLSSession
{
public:
  using super_type = TLSSession;
  H2Session();
  H2Session(swoc::TextView const &client_sni, int client_verify_mode = SSL_VERIFY_NONE);
  ~H2Session();
  swoc::Rv<ssize_t> read(swoc::MemSpan<char> span) override;
  swoc::Rv<ssize_t> write(swoc::TextView data) override;
  swoc::Rv<ssize_t> write(HttpHeader const &hdr) override;

  /** For HTTP/2, we read on the socket until an entire stream is done.
   *
   * For HTTP/1, we first read headers to get the Content-Length or other
   * header information to direct reading the body. For HTTP/2, this isn't
   * an issue because bodies are explicitly framed.
   */
  swoc::Rv<int> poll_for_headers(std::chrono::milliseconds timeout) override;
  swoc::Rv<std::shared_ptr<HttpHeader>> read_and_parse_request(swoc::FixedBufferWriter &w) override;
  swoc::Rv<size_t> drain_body(
      HttpHeader const &hdr,
      size_t expected_content_size,
      swoc::TextView bytes_read) override;

  swoc::Errata accept() override;
  swoc::Errata connect() override;
  static swoc::Errata init(int *process_exit_code);
  static void terminate();
  swoc::Errata client_session_init();
  swoc::Errata server_session_init();
  swoc::Errata send_connection_settings();
  swoc::Errata run_transactions(
      std::list<Txn> const &txn,
      swoc::TextView interface,
      swoc::IPEndpoint const *real_target,
      double rate_multiplier) override;
  swoc::Errata run_transaction(Txn const &txn) override;

  nghttp2_session *
  get_session()
  {
    return _session;
  }

  /** Indicate that the stream has ended (received the END_STREAM flag).
   *
   * @param[in] stream_id The stream identifier for which the end stream has
   * been processed.
   */
  void set_stream_has_ended(int32_t stream_id);

  /// Whether an entire stream has been received and is ready for processing.
  bool get_a_stream_has_ended() const;

  /// Return whether this session is for a listening server.
  bool get_is_server() const;

  void record_stream_state(int32_t stream_id, std::shared_ptr<H2StreamState> stream_state);

  /** Indicates that that the user should receive a non-zero status code.
   *
   * Most of this code is blocking a procedural and this can be communicated to
   * the caller via Errata. But the HTTP/2 nghttp2 callbacks do not return
   * directly to a caller. Therefore this is used to communicate a non-zero
   * status.
   */
  static void set_non_zero_exit_status();

public:
  /// A mapping from stream_id to H2StreamState.
  std::unordered_map<int32_t, std::shared_ptr<H2StreamState>> _stream_map;

protected:
  static swoc::Errata client_init(SSL_CTX *&client_context);
  static swoc::Errata server_init(SSL_CTX *&server_context);
  static void terminate(SSL_CTX *&client_context);

private:
  /** Populate an nghttp2 vector from the information in an HttpHeader instance.
   *
   * @param[in] hdr The instance from which to pack headers.
   * @param[out] nv_hdr The packed headers.
   * @param[out] hdr_count The size of the nv_hdr vector.
   *
   * @return Any errata information from the packing operation.
   */
  swoc::Errata pack_headers(HttpHeader const &hdr, nghttp2_nv *&nv_hdr, int &hdr_count);
  nghttp2_nv tv_to_nv(char const *name, swoc::TextView v);
  void set_expected_response_for_last_request(HttpHeader const &response);

private:
  /// Whether this session is for a listening server.
  bool _is_server = false;

  nghttp2_session *_session = nullptr;
  nghttp2_session_callbacks *_callbacks = nullptr;
  nghttp2_option *_options = nullptr;
  bool _h2_is_negotiated = false;

  std::deque<int32_t> _ended_streams;
  std::shared_ptr<H2StreamState> _last_added_stream;

#ifndef OPENSSL_NO_NEXTPROTONEG
  static unsigned char next_proto_list[256];
  static size_t next_proto_list_len;
#endif /* !OPENSSL_NO_NEXTPROTONEG */

  /** The client context to use for HTTP/2 connections.
   *
   * This is used per HTTP/2 connection so that ALPN advertises h2. For HTTP/1
   * TLS connections, client_context is used which does not advertise h2
   * support.
   *
   * A dedicated server context is not needed because, if H2Session::init() is
   * used, the same server_context is used for both TLS and HTTP/2 sessions.
   */
  static SSL_CTX *h2_client_context;

  /// The system status code. This is set to non-zero if problems are detected.
  static int *process_exit_code;
};
