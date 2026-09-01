/** @file
 * HTTP/3 over OpenSSL native QUIC.
 *
 * Copyright 2026, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "core/http3.h"
#include "core/https.h"
#include "core/verification.h"
#include "core/ProxyVerifier.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <limits>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/quic.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <vector>

#include "swoc/bwf_ex.h"
#include "swoc/bwf_ip.h"
#include "swoc/bwf_std.h"

#if OPENSSL_VERSION_NUMBER < 0x30500000L
#error "HTTP/3 requires OpenSSL 3.5 or newer"
#endif

using swoc::Errata;
using swoc::TextView;
using swoc::bwf::Errno;
using namespace swoc::literals;
using namespace std::literals;
using std::this_thread::sleep_for;

namespace chrono = std::chrono;
using ClockType = chrono::steady_clock;
using chrono::duration_cast;
using chrono::milliseconds;

namespace
{
constexpr auto QUIC_HANDSHAKE_TIMEOUT = 10s;
constexpr auto QUIC_EVENT_FALLBACK_TIMEOUT = 10ms;
constexpr size_t QUIC_STREAM_BUFFER_SIZE = 64 * 1024;
constexpr size_t MAX_HTTP3_VECTORS = 16;
constexpr uint64_t H3_STREAM_CREATION_ERROR = 0x103;
constexpr bool UNIDIRECTIONAL = true;
constexpr unsigned char H3_ALPN[] = {2, 'h', '3'};

/** The longest single wait taken while serving a @c content @c delay.
 *
 * Bounding the wait keeps the QUIC connection's timers serviced and shutdown
 * requests honored while the body is being held back.
 */
constexpr auto Content_Delay_Service_Interval = 20ms;

char const *
nghttp3_error(int error)
{
  auto const *message = nghttp3_strerror(error);
  return message == nullptr ? "unknown nghttp3 error" : message;
}

milliseconds
quic_event_timeout(SSL *connection, milliseconds maximum)
{
  struct timeval timeout = {};
  int is_infinite = 1;
  if (SSL_get_event_timeout(connection, &timeout, &is_infinite) != 1 || is_infinite) {
    return std::min(maximum, QUIC_EVENT_FALLBACK_TIMEOUT);
  }

  auto const timeout_us = chrono::seconds{timeout.tv_sec} + chrono::microseconds{timeout.tv_usec};
  auto timeout_ms = chrono::ceil<milliseconds>(timeout_us);
  return std::min(maximum, timeout_ms);
}

swoc::Rv<int>
poll_for_quic(H3Session &session, milliseconds timeout, int ssl_error = SSL_ERROR_WANT_READ)
{
  swoc::Rv<int> zret{0};
  short events = POLLIN;
  if (ssl_error == SSL_ERROR_WANT_WRITE || SSL_net_write_desired(session.quic_socket.connection)) {
    events |= POLLOUT;
  }

  auto &&[poll_result, poll_errata] = session.poll_for_data_on_socket(
      quic_event_timeout(session.quic_socket.connection, timeout),
      events);
  zret = poll_result;
  zret.note(std::move(poll_errata));
  return zret;
}

void
finalize_h3_stream(int64_t stream_id, H3StreamState &stream_state)
{
  Errata errata;

  if (stream_state.will_receive_request()) {
    if (stream_state.specified_request && stream_state.specified_request->_content_rule &&
        !stream_state.specified_request->_content_rule
             ->test(stream_state.key, "body", TextView(stream_state.body_received)))
    {
      errata.note(S_DIAG, R"(Body content did not match expected value.)");
    }
  } else if (
      stream_state.specified_response && stream_state.specified_response->_content_rule &&
      !stream_state.specified_response->_content_rule
           ->test(stream_state.key, "body", TextView(stream_state.body_received)))
  {
    errata.note(S_DIAG, R"(Body content did not match expected value.)");
  }

  auto const elapsed_ms =
      duration_cast<milliseconds>(ClockType::now() - stream_state.stream_start) -
      duration_cast<milliseconds>(stream_state.content_delay_served);
  if (elapsed_ms > Transaction_Delay_Cutoff) {
    errata.note(
        S_ERROR,
        R"(HTTP/3 transaction in stream id {} with key {} took {}.)",
        stream_id,
        stream_state.key,
        elapsed_ms);
  }
}

ssize_t
cb_h3_readfunction(
    nghttp3_conn *,
    int64_t stream_id,
    nghttp3_vec *vec,
    size_t,
    uint32_t *pflags,
    void *,
    void *stream_user_data)
{
  Errata errata;
  auto *stream_state = static_cast<H3StreamState *>(stream_user_data);

  if (stream_state->wait_for_continue) {
    errata.note(S_DIAG, R"(Not sending HTTP/3 body for "Expect: 100" request.)");
    *pflags = NGHTTP3_DATA_FLAG_EOF;
    return 0;
  }
  if (stream_state->content_delay > 0us) {
    // The HEADERS frame has to reach the wire before the content delay starts,
    // so report that the body is not available yet. H3Session::write waits out
    // the delay and then resumes the stream, at which point this callback is
    // called again with the delay cleared.
    errata.note(
        S_DIAG,
        "Withholding the HTTP/3 body for key {} of stream id {} per the content delay "
        "specification.",
        stream_state->key,
        stream_id);
    return NGHTTP3_ERR_WOULDBLOCK;
  }

  vec[0].base = reinterpret_cast<uint8_t *>(const_cast<char *>(stream_state->body_to_send.data()));
  vec[0].len = stream_state->body_to_send.size();
  stream_state->num_data_bytes_written += vec[0].len;
  *pflags = NGHTTP3_DATA_FLAG_EOF;
  errata.note(
      S_DIAG,
      "Sent an HTTP/3 body of {} bytes for key {} of stream id {}:\n{}",
      vec[0].len,
      stream_state->key,
      stream_id,
      TextView{stream_state->body_to_send.data(), vec[0].len});
  return 1;
}

int
cb_h3_acked_stream_data(
    nghttp3_conn *,
    int64_t stream_id,
    uint64_t datalen,
    void *,
    void *stream_user_data)
{
  Errata errata;
  auto *stream_state = static_cast<H3StreamState *>(stream_user_data);
  auto const outstanding_bytes = stream_state->num_data_bytes_written;
  errata.note(
      S_DIAG,
      "HTTP/3 stream with id {} acked {} bytes with {} bytes outstanding",
      stream_id,
      datalen,
      outstanding_bytes);

  if (datalen >= outstanding_bytes) {
    stream_state->num_data_bytes_written = 0;
  } else {
    stream_state->num_data_bytes_written -= datalen;
  }
  return 0;
}

int
cb_h3_stream_close(
    nghttp3_conn *,
    int64_t stream_id,
    uint64_t,
    void *conn_user_data,
    void *stream_user_data)
{
  auto *session = static_cast<H3Session *>(conn_user_data);
  auto iter = session->stream_map.find(stream_id);
  if (iter == session->stream_map.end()) {
    session->clear_completed_response_stream(stream_id);
    return 0;
  }

  auto &stream_state = *static_cast<H3StreamState *>(stream_user_data);
  finalize_h3_stream(stream_id, stream_state);
  session->stream_map.erase(iter);
  return 0;
}

int
cb_h3_recv_data(
    nghttp3_conn *,
    int64_t stream_id,
    uint8_t const *buf,
    size_t buflen,
    void *,
    void *stream_user_data)
{
  Errata errata;
  auto *stream_state = static_cast<H3StreamState *>(stream_user_data);
  errata.note(
      S_DIAG,
      "Received an HTTP/3 body of {} bytes for transaction with key {}, "
      "stream id {}, with content:\n{}",
      buflen,
      stream_state->key,
      stream_id,
      TextView(reinterpret_cast<char const *>(buf), buflen));
  stream_state->body_received.append(reinterpret_cast<char const *>(buf), buflen);
  return 0;
}

int
cb_h3_deferred_consume(nghttp3_conn *, int64_t, size_t, void *, void *)
{
  // OpenSSL manages QUIC flow-control credit internally.
  return 0;
}

int
cb_h3_recv_header(
    nghttp3_conn *,
    int64_t,
    int32_t,
    nghttp3_rcbuf *name,
    nghttp3_rcbuf *value,
    uint8_t,
    void *,
    void *stream_user_data)
{
  auto *stream_state = static_cast<H3StreamState *>(stream_user_data);
  stream_state->have_received_headers = true;

  TextView const name_view = stream_state->register_rcbuf(name);
  TextView const value_view = stream_state->register_rcbuf(value);

  if (stream_state->will_receive_request()) {
    auto &request_headers = stream_state->request_from_client;
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
  } else {
    auto &response_headers = stream_state->response_from_server;
    if (name_view == ":status") {
      response_headers->_status = swoc::svtou(value_view);
      response_headers->_status_string = std::string(value_view);
      if (stream_state->wait_for_continue && value_view == "100") {
        stream_state->wait_for_continue = false;
      }
    }
    response_headers->_fields_rules->add_field(name_view, value_view);
  }
  return 0;
}

int
cb_h3_end_headers(
    nghttp3_conn *,
    int64_t stream_id,
    int,
    void *conn_user_data,
    void *stream_user_data)
{
  Errata errata;
  auto *session = static_cast<H3Session *>(conn_user_data);
  auto *stream_state = static_cast<H3StreamState *>(stream_user_data);
  if (stream_state->will_receive_request()) {
    auto &request_from_client = *stream_state->request_from_client;
    request_from_client.derive_key();
    stream_state->key = request_from_client.get_key();
    auto &composed_url = stream_state->composed_url;
    composed_url = request_from_client._scheme;
    if (!composed_url.empty()) {
      composed_url.append("://");
    }
    composed_url.append(request_from_client._authority);
    composed_url.append(request_from_client._path);
    request_from_client.parse_url(composed_url);
    if (auto spot{
            request_from_client._fields_rules->_fields.find(HttpHeader::FIELD_CONTENT_LENGTH)};
        spot != request_from_client._fields_rules->_fields.end())
    {
      stream_state->body_received.reserve(swoc::svtou(spot->second));
    }
    errata.note(
        S_DIAG,
        "Received an HTTP/3 request for key {} with stream id {}:\n{}",
        stream_state->key,
        stream_id,
        request_from_client);
  } else {
    auto &response_from_wire = *stream_state->response_from_server;
    response_from_wire.derive_key();
    if (stream_state->key.empty()) {
      stream_state->key = response_from_wire.get_key();
      errata.note(
          S_ERROR,
          "Incoming HTTP/3 response has no key set from the request. Using key from "
          "response: {}.",
          stream_state->key);
    } else {
      response_from_wire.set_key(stream_state->key);
    }

    if (auto spot{response_from_wire._fields_rules->_fields.find(HttpHeader::FIELD_CONTENT_LENGTH)};
        spot != response_from_wire._fields_rules->_fields.end())
    {
      stream_state->body_received.reserve(swoc::svtou(spot->second));
    }
    errata.note(
        S_DIAG,
        "Received an HTTP/3 response for key {} with stream id {}:\n{}",
        stream_state->key,
        stream_id,
        response_from_wire);

    auto const *specified_response = stream_state->specified_response;
    if (specified_response != nullptr) {
      specified_response->mark_verification_performed();
      if (response_from_wire.verify_headers(stream_state->key, *specified_response->_fields_rules))
      {
        errata.note(S_ERROR, R"(HTTP/3 response headers did not match expected response headers.)");
        session->set_non_zero_exit_status();
      }
      if (specified_response->_status != 0 &&
          response_from_wire._status != specified_response->_status &&
          (response_from_wire._status != 200 || specified_response->_status != 304) &&
          (response_from_wire._status != 304 || specified_response->_status != 200))
      {
        errata.note(
            S_ERROR,
            R"(HTTP/3 Status Violation: expected {} got {}, key: {}.)",
            specified_response->_status,
            response_from_wire._status,
            stream_state->key);
      }
    }
  }

  if (!stream_state->have_received_headers) {
    errata.note(S_ERROR, "Stream did not receive any headers for key: {}", stream_state->key);
  }
  return 0;
}

int
cb_h3_end_stream(nghttp3_conn *, int64_t stream_id, void *conn_user_data, void *stream_user_data)
{
  Errata errata;
  auto *session = static_cast<H3Session *>(conn_user_data);
  auto *stream_state = static_cast<H3StreamState *>(stream_user_data);
  std::string key;
  if (stream_state->will_receive_request()) {
    auto &request_from_client = *stream_state->request_from_client;
    request_from_client.derive_key();
    key = request_from_client.get_key();
  } else {
    auto &response_from_wire = *stream_state->response_from_server;
    response_from_wire.derive_key();
    if (stream_state->key.empty()) {
      stream_state->key = response_from_wire.get_key();
      errata.note(
          S_ERROR,
          "Incoming HTTP/3 response has no key set from the request. Using key from "
          "response: {}.",
          stream_state->key);
    } else {
      response_from_wire.set_key(stream_state->key);
    }
    key = stream_state->key;
  }

  session->set_stream_has_ended(stream_id, key);
  if (stream_state->will_receive_response()) {
    finalize_h3_stream(stream_id, *stream_state);
    std::shared_ptr<H3StreamState> retained_state;
    if (auto const spot = session->stream_map.find(stream_id); spot != session->stream_map.end()) {
      retained_state = std::move(spot->second);
      session->stream_map.erase(spot);
    }
    // Our half of the stream may still have a body to send, and nghttp3 will
    // call back into this state with its raw pointer while it does.
    session->mark_completed_response_stream(stream_id, std::move(retained_state));
  }
  return 0;
}

int
cb_h3_send_stop_sending(
    nghttp3_conn *,
    int64_t stream_id,
    uint64_t app_error_code,
    void *conn_user_data,
    void *)
{
  auto *session = static_cast<H3Session *>(conn_user_data);
  auto *stream = session->quic_socket.find_stream(stream_id);
  if (stream == nullptr) {
    return 0;
  }

  SSL_STREAM_RESET_ARGS args{.quic_error_code = app_error_code};
  if (SSL_stream_reset(stream, &args, sizeof(args)) != 1) {
    Errata errata;
    errata.note(S_ERROR, "Failed to reset HTTP/3 stream {}: {}", stream_id, swoc::bwf::SSLError{});
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

int
cb_h3_reset_stream(
    nghttp3_conn *,
    int64_t stream_id,
    uint64_t app_error_code,
    void *conn_user_data,
    void *stream_user_data)
{
  auto *session = static_cast<H3Session *>(conn_user_data);
  auto *stream_state = static_cast<H3StreamState *>(stream_user_data);
  auto *stream = session->quic_socket.find_stream(stream_id);
  if (stream == nullptr) {
    return 0;
  }

  SSL_STREAM_RESET_ARGS args{.quic_error_code = app_error_code};
  auto const result = SSL_stream_reset(stream, &args, sizeof(args));
  Errata errata;
  errata.note(
      S_DIAG,
      "Received an HTTP/3 reset stream for key {} with stream id {}, app error code {} "
      "result {}",
      stream_state == nullptr ? "" : stream_state->key,
      stream_id,
      app_error_code,
      result);
  return result == 1 ? 0 : NGHTTP3_ERR_CALLBACK_FAILURE;
}

nghttp3_callbacks const NGHTTP3_CLIENT_CALLBACKS = [] {
  nghttp3_callbacks callbacks{};
  callbacks.acked_stream_data = cb_h3_acked_stream_data;
  callbacks.stream_close = cb_h3_stream_close;
  callbacks.recv_data = cb_h3_recv_data;
  callbacks.deferred_consume = cb_h3_deferred_consume;
  callbacks.recv_header = cb_h3_recv_header;
  callbacks.end_headers = cb_h3_end_headers;
  callbacks.recv_trailer = cb_h3_recv_header;
  callbacks.stop_sending = cb_h3_send_stop_sending;
  callbacks.end_stream = cb_h3_end_stream;
  callbacks.reset_stream = cb_h3_reset_stream;
  return callbacks;
}();

swoc::Rv<bool>
progress_http3_egress(H3Session &session)
{
  swoc::Rv<bool> zret{false};
  auto &quic_socket = session.quic_socket;

  std::vector<int64_t> pending_concludes{
      quic_socket.streams_pending_conclude.begin(),
      quic_socket.streams_pending_conclude.end()};
  for (auto const stream_id : pending_concludes) {
    auto *stream = quic_socket.find_stream(stream_id);
    if (stream == nullptr) {
      quic_socket.streams_pending_conclude.erase(stream_id);
      continue;
    }
    auto const conclude_result = SSL_stream_conclude(stream, 0);
    if (conclude_result == 1) {
      quic_socket.streams_pending_conclude.erase(stream_id);
      quic_socket.streams_concluded.insert(stream_id);
      zret = true;
      continue;
    }
    auto const ssl_error = SSL_get_error(stream, conclude_result);
    if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE) {
      zret.note(
          S_ERROR,
          "Failed to conclude HTTP/3 stream {}: {}",
          stream_id,
          swoc::bwf::SSLError{});
      return zret;
    }
  }

  for (;;) {
    std::array<nghttp3_vec, MAX_HTTP3_VECTORS> vectors;
    int64_t stream_id = -1;
    int fin = 0;
    auto const vector_count = nghttp3_conn_writev_stream(
        quic_socket.h3conn,
        &stream_id,
        &fin,
        vectors.data(),
        vectors.size());
    if (vector_count < 0) {
      zret.note(
          S_ERROR,
          "nghttp3_conn_writev_stream failed: {} ({})",
          nghttp3_error(vector_count),
          vector_count);
      return zret;
    }
    if (stream_id == -1) {
      return zret;
    }

    auto *stream = quic_socket.find_stream(stream_id);
    if (stream == nullptr) {
      zret.note(S_ERROR, "nghttp3 selected unknown QUIC stream {} for writing.", stream_id);
      return zret;
    }

    nghttp3_ssize vector_index = 0;
    while (vector_index < vector_count && vectors[static_cast<size_t>(vector_index)].len == 0) {
      ++vector_index;
    }

    bool can_conclude = fin != 0;
    size_t accepted = 0;
    if (vector_index < vector_count) {
      auto const &vector = vectors[static_cast<size_t>(vector_index)];
      size_t written = 0;
      auto const result = SSL_write_ex(stream, vector.base, vector.len, &written);
      if (result != 1) {
        auto const ssl_error = SSL_get_error(stream, result);
        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
          return zret;
        }
        zret.note(
            S_ERROR,
            "Failed writing HTTP/3 stream {}: SSL error {}, {}",
            stream_id,
            ssl_error,
            swoc::bwf::SSLError{});
        return zret;
      }
      if (written == 0) {
        return zret;
      }

      accepted = written;
      Session::increment_total_bytes_written(written);
      auto const write_result =
          nghttp3_conn_add_write_offset(quic_socket.h3conn, stream_id, written);
      // OpenSSL copies accepted stream bytes into its QUIC send buffers. It
      // does not expose per-stream acknowledgement callbacks, so accepted
      // bytes can immediately be released by nghttp3.
      auto const ack_result = nghttp3_conn_add_ack_offset(quic_socket.h3conn, stream_id, written);
      if (write_result != 0 || ack_result != 0) {
        zret.note(
            S_ERROR,
            "Failed to update nghttp3 offsets for stream {}: write {}, ack {}.",
            stream_id,
            write_result,
            ack_result);
        return zret;
      }
      zret = true;

      can_conclude = can_conclude && written == vector.len;
      for (++vector_index; vector_index < vector_count; ++vector_index) {
        if (vectors[static_cast<size_t>(vector_index)].len != 0) {
          can_conclude = false;
          break;
        }
      }
      if (!can_conclude) {
        continue;
      }
    }

    if (can_conclude &&
        quic_socket.streams_concluded.find(stream_id) == quic_socket.streams_concluded.end())
    {
      auto const conclude_result = SSL_stream_conclude(stream, 0);
      if (conclude_result == 1) {
        quic_socket.streams_concluded.insert(stream_id);
        zret = true;
      } else {
        auto const ssl_error = SSL_get_error(stream, conclude_result);
        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
          quic_socket.streams_pending_conclude.insert(stream_id);
          return zret;
        }
        zret.note(
            S_ERROR,
            "Failed to conclude HTTP/3 stream {} after accepting {} bytes: {}",
            stream_id,
            accepted,
            swoc::bwf::SSLError{});
        return zret;
      }
    }
  }
}

swoc::Rv<bool>
progress_http3_ingress(H3Session &session)
{
  swoc::Rv<bool> zret{false};
  auto &quic_socket = session.quic_socket;
  while (auto *stream = SSL_accept_stream(quic_socket.connection, SSL_ACCEPT_STREAM_NO_BLOCK)) {
    quic_socket.add_stream(stream);
    zret = true;
  }

  std::array<uint8_t, QUIC_STREAM_BUFFER_SIZE> buffer;
  for (auto const &[stream_id, stream] : quic_socket.streams) {
    if ((SSL_get_stream_type(stream) & SSL_STREAM_TYPE_READ) == 0 ||
        quic_socket.streams_with_fin.find(stream_id) != quic_socket.streams_with_fin.end())
    {
      continue;
    }

    for (;;) {
      size_t bytes_read = 0;
      auto const result = SSL_read_ex(stream, buffer.data(), buffer.size(), &bytes_read);
      if (result == 1) {
        Session::increment_total_bytes_read(bytes_read);
        auto const consumed =
            nghttp3_conn_read_stream(quic_socket.h3conn, stream_id, buffer.data(), bytes_read, 0);
        if (consumed < 0) {
          zret.note(
              S_ERROR,
              "nghttp3_conn_read_stream failed for stream {}: {} ({})",
              stream_id,
              nghttp3_error(consumed),
              consumed);
          return zret;
        }
        zret = true;
        continue;
      }

      auto const ssl_error = SSL_get_error(stream, result);
      if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
        break;
      }
      if (ssl_error == SSL_ERROR_ZERO_RETURN) {
        auto const consumed =
            nghttp3_conn_read_stream(quic_socket.h3conn, stream_id, nullptr, 0, 1);
        if (consumed < 0) {
          zret.note(
              S_ERROR,
              "nghttp3 failed to process FIN on stream {}: {} ({})",
              stream_id,
              nghttp3_error(consumed),
              consumed);
          return zret;
        }
        quic_socket.streams_with_fin.insert(stream_id);
        zret = true;
        break;
      }

      zret.note(
          S_ERROR,
          "Failed reading HTTP/3 stream {}: SSL error {}, {}",
          stream_id,
          ssl_error,
          swoc::bwf::SSLError{});
      return zret;
    }
  }
  return zret;
}

/** Return whether the QUIC connection has been closed.
 *
 * @param[in] session The session whose connection to inspect.
 * @return Whether the connection is closed, by either peer.
 */
bool
quic_connection_is_closed(H3Session const &session)
{
  auto *connection = session.quic_socket.connection;
  if (connection == nullptr) {
    return true;
  }
  SSL_CONN_CLOSE_INFO close_info{};
  return SSL_get_conn_close_info(connection, &close_info, sizeof(close_info)) == 1;
}

swoc::Rv<bool>
progress_http3(H3Session &session, milliseconds timeout)
{
  swoc::Rv<bool> zret{false};
  auto const deadline = ClockType::now() + timeout;

  for (;;) {
    auto &&[egress_progress, egress_errata] = progress_http3_egress(session);
    zret.note(std::move(egress_errata));
    if (!zret.is_ok()) {
      return zret;
    }

    if (SSL_handle_events(session.quic_socket.connection) != 1) {
      zret.note(S_ERROR, "SSL_handle_events failed: {}", swoc::bwf::SSLError{});
      return zret;
    }

    auto &&[ingress_progress, ingress_errata] = progress_http3_ingress(session);
    zret.note(std::move(ingress_errata));
    if (!zret.is_ok()) {
      return zret;
    }

    auto &&[final_egress_progress, final_egress_errata] = progress_http3_egress(session);
    zret.note(std::move(final_egress_errata));
    if (!zret.is_ok()) {
      return zret;
    }

    if (egress_progress || ingress_progress || final_egress_progress) {
      zret = true;
      return zret;
    }
    if (timeout <= 0ms || ClockType::now() >= deadline) {
      return zret;
    }

    auto const remaining = duration_cast<milliseconds>(deadline - ClockType::now());
    auto &&[poll_result, poll_errata] = poll_for_quic(session, remaining);
    zret.note(std::move(poll_errata));
    if (!zret.is_ok() || poll_result < 0) {
      zret.note(S_ERROR, "Failed polling the OpenSSL QUIC socket.");
      return zret;
    }
  }
}

} // namespace

swoc::file::path QuicSocket::m_qlog_dir;
SSL_CTX *H3Session::m_h3_client_context = nullptr;
SSL_CTX *H3Session::m_h3_server_context = nullptr;
int *H3Session::m_process_exit_code = nullptr;

QuicSocket::~QuicSocket()
{
  reset();
}

void
QuicSocket::reset()
{
  if (h3conn != nullptr) {
    nghttp3_conn_del(h3conn);
    h3conn = nullptr;
  }
  for (auto &[stream_id, stream] : streams) {
    static_cast<void>(stream_id);
    SSL_free(stream);
  }
  streams.clear();
  streams_with_fin.clear();
  streams_concluded.clear();
  streams_pending_conclude.clear();

  if (connection != nullptr) {
    SSL_SHUTDOWN_EX_ARGS args{.quic_error_code = 0, .quic_reason = "Proxy Verifier shutdown"};
    SSL_shutdown_ex(
        connection,
        SSL_SHUTDOWN_FLAG_RAPID | SSL_SHUTDOWN_FLAG_NO_BLOCK,
        &args,
        sizeof(args));
    SSL_free(connection);
    connection = nullptr;
  }
}

swoc::Rv<SSL *>
QuicSocket::open_stream(bool unidirectional)
{
  swoc::Rv<SSL *> zret{nullptr};
  auto const flags = SSL_STREAM_FLAG_NO_BLOCK | (unidirectional ? SSL_STREAM_FLAG_UNI : 0);
  auto *stream = SSL_new_stream(connection, flags);
  if (stream == nullptr) {
    zret.note(S_ERROR, "Failed to create an OpenSSL QUIC stream: {}", swoc::bwf::SSLError{});
    return zret;
  }
  add_stream(stream);
  zret = stream;
  return zret;
}

void
QuicSocket::add_stream(SSL *stream)
{
  SSL_set_blocking_mode(stream, 0);
  SSL_set_event_handling_mode(stream, SSL_VALUE_EVENT_HANDLING_MODE_EXPLICIT);
  SSL_set_mode(stream, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE);
  auto const stream_id = SSL_get_stream_id(stream);
  streams.emplace(static_cast<int64_t>(stream_id), stream);
}

SSL *
QuicSocket::find_stream(int64_t stream_id) const
{
  auto const spot = streams.find(stream_id);
  return spot == streams.end() ? nullptr : spot->second;
}

Errata
QuicSocket::configure_qlog_dir(TextView qlog_dir)
{
  Errata errata;
  m_qlog_dir = qlog_dir;
  if (qlog_dir.empty()) {
    return errata;
  }

  std::error_code ec;
  auto stat = swoc::file::status(m_qlog_dir, ec);
  if (ec.value() == ENOENT) {
    std::filesystem::create_directories(qlog_dir, ec);
    if (ec) {
      errata.note(S_ERROR, R"(Could not create qlog directory path "{}": {})", qlog_dir, ec);
      return errata;
    }
  } else if (ec) {
    errata.note(S_ERROR, R"(Invalid qlog directory path "{}": {}.)", qlog_dir, ec);
    return errata;
  }
  stat = swoc::file::status(m_qlog_dir, ec);
  if (!swoc::file::is_dir(stat)) {
    errata.note(S_ERROR, R"(Specified qlog path is not a directory: "{}")", qlog_dir);
    return errata;
  }
  errata.note(
      S_INFO,
      "OpenSSL native QUIC does not expose qlog events; no qlog files will be written to {}.",
      qlog_dir);
  return errata;
}

TextView
H3StreamState::register_rcbuf(nghttp3_rcbuf *rcbuf)
{
  nghttp3_rcbuf_incref(rcbuf);
  m_rcbufs_to_free.push_back(rcbuf);
  auto const buf = nghttp3_rcbuf_get_buf(rcbuf);
  return TextView(reinterpret_cast<char *>(buf.base), buf.len);
}

H3StreamState::H3StreamState(bool is_client)
  : stream_start{ClockType::now()}
  , request_from_client{std::make_shared<HttpHeader>()}
  , response_from_server{std::make_shared<HttpHeader>()}
  , m_will_receive_request{!is_client}
{
  request_from_client->set_is_request(HTTP_PROTOCOL_TYPE::HTTP_3);
  response_from_server->set_is_response(HTTP_PROTOCOL_TYPE::HTTP_3);
}

H3StreamState::~H3StreamState()
{
  for (auto *rcbuf : m_rcbufs_to_free) {
    nghttp3_rcbuf_decref(rcbuf);
  }
}

bool
H3StreamState::will_receive_request() const
{
  return m_will_receive_request;
}

bool
H3StreamState::will_receive_response() const
{
  return !m_will_receive_request;
}

void
H3StreamState::set_stream_id(int64_t stream_id)
{
  m_stream_id = stream_id;
}

int64_t
H3StreamState::get_stream_id() const
{
  return m_stream_id;
}

H3Session::H3Session() = default;

H3Session::H3Session(TextView const &client_sni, int client_verify_mode)
  : m_client_sni{client_sni}
  , m_client_verify_mode{client_verify_mode}
{
}

H3Session::~H3Session()
{
  m_completed_response_streams.clear();
  quic_socket.reset();
}

swoc::Rv<ssize_t> H3Session::read(swoc::MemSpan<char>)
{
  swoc::Rv<ssize_t> zret{0};
  zret.note(S_ERROR, "HTTP/3 read() called for the unsupported MemSpan overload.");
  return zret;
}

swoc::Rv<ssize_t> H3Session::write(TextView)
{
  swoc::Rv<ssize_t> zret{0};
  zret.note(S_ERROR, "HTTP/3 write() called for the unsupported TextView overload.");
  return zret;
}

nghttp3_nv
H3Session::tv_to_nv(char const *name, TextView value)
{
  return nghttp3_nv{
      reinterpret_cast<uint8_t *>(const_cast<char *>(name)),
      reinterpret_cast<uint8_t *>(const_cast<char *>(value.data())),
      std::strlen(name),
      value.length(),
      NGHTTP3_NV_FLAG_NONE};
}

Errata
H3Session::pack_headers(HttpHeader const &hdr, nghttp3_nv *&nv_hdr, int &hdr_count)
{
  Errata errata;
  hdr_count = static_cast<int>(hdr._fields_rules->_fields.size());
  nv_hdr = static_cast<nghttp3_nv *>(std::malloc(sizeof(nghttp3_nv) * hdr_count));
  if (nv_hdr == nullptr) {
    errata.note(S_ERROR, "Failed to allocate {} HTTP/3 header fields.", hdr_count);
    return errata;
  }

  int offset = 0;
  if (hdr.is_response()) {
    nv_hdr[offset++] = tv_to_nv(":status", hdr._status_string);
  } else {
    nv_hdr[offset++] = tv_to_nv(":method", hdr._method);
    nv_hdr[offset++] = tv_to_nv(":scheme", hdr._scheme);
    nv_hdr[offset++] = tv_to_nv(":path", hdr._path);
    nv_hdr[offset++] = tv_to_nv(":authority", hdr._authority);
  }
  hdr._fields_rules->add_fields_to_ngnva(nv_hdr + offset);
  return errata;
}

Errata
H3Session::content_delay(H3StreamState &stream_state)
{
  Errata errata;

  auto const content_delay = stream_state.content_delay;
  auto const stream_id = stream_state.get_stream_id();
  errata.note(
      S_DIAG,
      "Delaying the body for key {} of stream id {} per the content delay specification: {}.",
      stream_state.key,
      stream_id,
      duration_cast<milliseconds>(content_delay));
  // Make sure the diagnostic for the delay is emitted before the body.
  errata.sink();

  auto const deadline = ClockType::now() + content_delay;
  for (auto remaining = content_delay; remaining > 0us;
       remaining = duration_cast<chrono::microseconds>(deadline - ClockType::now()))
  {
    // Service the connection in bounded slices so its timers keep running and
    // shutdown requests stay responsive, and so a sub-millisecond remainder
    // does not spin. The body itself stays withheld: the data reader reports
    // NGHTTP3_ERR_WOULDBLOCK while content_delay is set.
    auto const slice =
        std::clamp(duration_cast<milliseconds>(remaining), 1ms, Content_Delay_Service_Interval);
    auto &&[progressed, progress_errata] = progress_http3(*this, slice);
    static_cast<void>(progressed);
    errata.note(std::move(progress_errata));
    if (!errata.is_ok()) {
      if (!quic_connection_is_closed(*this)) {
        // A protocol or TLS failure is a genuine replay failure and has to keep
        // its severity.
        errata.note(
            S_ERROR,
            "Failed to service the HTTP/3 connection during the content delay for key {}.",
            stream_state.key);
        break;
      }
      // A peer which gives up during the delay is the expected outcome for some
      // replay files, so make the connection between the two explicit rather
      // than reporting a bare I/O failure.
      errata.sink();
      errata.note(
          S_DIAG,
          "The peer closed the connection or stopped responding during the content delay of {} "
          "for key {}.",
          duration_cast<milliseconds>(content_delay),
          stream_state.key);
      break;
    }
    if (shutdown_requested()) {
      errata.note(
          S_DIAG,
          "Shutdown was requested during the content delay for key {}.",
          stream_state.key);
      break;
    }
  }
  // This wait was asked for by the replay file, so it does not count against
  // Transaction_Delay_Cutoff.
  stream_state.content_delay_served += content_delay;

  // Let the body flow again regardless of how the delay ended. If the peer is
  // gone the write simply fails and is reported by the caller.
  stream_state.content_delay = 0us;
  if (auto const rv = nghttp3_conn_resume_stream(quic_socket.h3conn, stream_id); rv != 0) {
    errata.note(
        S_ERROR,
        "Failed to resume the HTTP/3 body for key {} on stream {} after the content delay: {} ({})",
        stream_state.key,
        stream_id,
        nghttp3_error(rv),
        rv);
  }
  return errata;
}

swoc::Rv<ssize_t>
H3Session::write(HttpHeader const &hdr)
{
  swoc::Rv<ssize_t> zret{0};
  auto const key = hdr.get_key();
  H3StreamState *stream_state = nullptr;
  std::shared_ptr<H3StreamState> new_stream_state;
  /** A reference held for the duration of this write.
   *
   * Servicing the connection, which happens during a content delay, can retire
   * a stream from the stream map. Holding a reference keeps @a stream_state
   * valid until this write is finished with it.
   */
  std::shared_ptr<H3StreamState> stream_state_reference;
  int64_t stream_id = 0;

  if (hdr.is_response()) {
    stream_id = hdr._stream_id;
    auto const spot = stream_map.find(stream_id);
    if (spot == stream_map.end()) {
      zret.note(S_ERROR, "Could not find registered stream for stream id: {}", stream_id);
      return zret;
    }
    stream_state_reference = spot->second;
    stream_state = stream_state_reference.get();
  } else {
    auto &&[stream, stream_errata] = quic_socket.open_stream(!UNIDIRECTIONAL);
    zret.note(std::move(stream_errata));
    if (!zret.is_ok() || stream == nullptr) {
      zret.note(S_ERROR, "Failed to create an HTTP/3 request stream for key {}.", key);
      return zret;
    }
    stream_id = static_cast<int64_t>(SSL_get_stream_id(stream));
    new_stream_state = std::make_shared<H3StreamState>(hdr.is_request());
    stream_state = new_stream_state.get();
    // See the comment on this member: this has to happen before any of the
    // request is written.
    stream_state->specified_response = m_specified_response_for_next_request;
    stream_state->set_stream_id(stream_id);
    record_stream_state(stream_id, new_stream_state);
  }
  stream_state->key = key;

  int num_headers = 0;
  nghttp3_nv *headers = nullptr;
  zret.note(pack_headers(hdr, headers, num_headers));
  if (!zret.is_ok()) {
    zret.note(S_ERROR, "Failed to pack headers for key: {}", key);
    return zret;
  }

  int submit_result = 0;
  if (hdr._content_length > 0 && (hdr.is_request() || !HttpHeader::STATUS_NO_CONTENT[hdr._status]))
  {
    TextView content;
    if (hdr._content_data_list.front()) {
      content = TextView{hdr._content_data_list.front(), hdr._content_length};
    } else {
      content = TextView{HttpHeader::_content.data(), hdr._content_length};
    }
    nghttp3_data_reader data_reader{.read_data = cb_h3_readfunction};
    stream_state->body_to_send = content;
    stream_state->wait_for_continue = hdr.is_request_with_expect_100_continue();
    // A request awaiting a 100 Continue has no body to write at this point, so
    // there is nothing to hold back. This matches the HTTP/1 write path.
    stream_state->content_delay = stream_state->wait_for_continue ? 0us : hdr._content_delay;
    if (hdr.is_response()) {
      submit_result = nghttp3_conn_submit_response(
          quic_socket.h3conn,
          stream_id,
          headers,
          num_headers,
          &data_reader);
    } else {
      submit_result = nghttp3_conn_submit_request(
          quic_socket.h3conn,
          stream_id,
          headers,
          num_headers,
          &data_reader,
          stream_state);
    }
  } else if (hdr.is_response()) {
    submit_result =
        nghttp3_conn_submit_response(quic_socket.h3conn, stream_id, headers, num_headers, nullptr);
  } else {
    submit_result = nghttp3_conn_submit_request(
        quic_socket.h3conn,
        stream_id,
        headers,
        num_headers,
        nullptr,
        stream_state);
  }

  if (submit_result == 0) {
    zret.note(
        S_DIAG,
        "Sent the following HTTP/3 {}{} headers for key {} with stream id {}:\n{}",
        swoc::bwf::If(hdr.is_request(), "request"),
        swoc::bwf::If(hdr.is_response(), "response"),
        key,
        stream_id,
        hdr);
  } else {
    zret.note(
        S_ERROR,
        "Submitting an HTTP/3 {}{} for key {} with stream id {} failed: {} ({})",
        swoc::bwf::If(hdr.is_request(), "request"),
        swoc::bwf::If(hdr.is_response(), "response"),
        key,
        stream_id,
        nghttp3_error(submit_result),
        submit_result);
  }
  std::free(headers);

  if (zret.is_ok()) {
    zret.errata().sink();
    auto &&[progressed, progress_errata] = progress_http3(*this, 0ms);
    static_cast<void>(progressed);
    zret.note(std::move(progress_errata));
  }
  if (zret.is_ok() && stream_state->content_delay > 0us) {
    // The headers are on the wire and the body was withheld from nghttp3. Wait
    // out the content delay and then let the body follow.
    zret.note(content_delay(*stream_state));
    if (zret.is_ok()) {
      // Make sure the logging of the delay is emitted before the body.
      zret.errata().sink();
    }
    auto &&[progressed, progress_errata] = progress_http3(*this, 0ms);
    static_cast<void>(progressed);
    zret.note(std::move(progress_errata));
  }
  return zret;
}

Errata
H3Session::configure_udp_socket(TextView interface, swoc::IPEndpoint const *target)
{
  Errata errata;
  quic_socket.reset();
  if (!is_closed()) {
    close();
  }

  int const socket_fd = ::socket(target->family(), SOCK_DGRAM, 0);
  if (socket_fd < 0) {
    errata.note(S_ERROR, R"(Failed to open a UDP socket - {})", Errno{});
    return errata;
  }

  static constexpr int ENABLE_OPTION = 1;
  struct linger linger_option = {.l_onoff = 0, .l_linger = 0};
  setsockopt(socket_fd, SOL_SOCKET, SO_LINGER, &linger_option, sizeof(linger_option));
  if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &ENABLE_OPTION, sizeof(ENABLE_OPTION)) < 0) {
    errata.note(S_ERROR, R"(Could not set reuseaddr on socket {} - {}.)", socket_fd, Errno{});
    ::close(socket_fd);
    return errata;
  }
  if (!interface.empty()) {
    InterfaceNameToEndpoint interface_to_endpoint{interface, target->family()};
    auto &&[device_endpoint, device_errata] = interface_to_endpoint.find_ip_endpoint();
    errata.note(std::move(device_errata));
    if (!errata.is_ok()) {
      ::close(socket_fd);
      return errata;
    }
    if (::bind(socket_fd, device_endpoint, device_endpoint.size()) == -1) {
      errata.note(S_ERROR, "Failed to bind on interface {}: {}", interface, Errno{});
      ::close(socket_fd);
      return errata;
    }
  }

  if (::connect(socket_fd, &target->sa, target->size()) == -1) {
    errata.note(S_ERROR, R"(Failed to connect socket {}: - {})", *target, Errno{});
    ::close(socket_fd);
    return errata;
  }
  if (::fcntl(socket_fd, F_SETFL, fcntl(socket_fd, F_GETFL, 0) | O_NONBLOCK) != 0) {
    errata.note(
        S_ERROR,
        R"(Failed to make the client socket non-blocking {}: - {})",
        *target,
        Errno{});
    ::close(socket_fd);
    return errata;
  }
  errata.note(set_fd(socket_fd));
  if (!errata.is_ok()) {
    ::close(socket_fd);
    return errata;
  }
  m_endpoint = target;
  return errata;
}

Errata
H3Session::client_ssl_session_init(SSL_CTX *client_context)
{
  Errata errata;
  assert(quic_socket.connection == nullptr);
  quic_socket.connection = SSL_new(client_context);
  if (quic_socket.connection == nullptr) {
    errata.note(S_ERROR, "SSL_new failed: {}", swoc::bwf::SSLError{});
    return errata;
  }

  auto *connection = quic_socket.connection;
  if (SSL_set_blocking_mode(connection, 0) != 1 ||
      SSL_set_event_handling_mode(connection, SSL_VALUE_EVENT_HANDLING_MODE_EXPLICIT) != 1 ||
      SSL_set_default_stream_mode(connection, SSL_DEFAULT_STREAM_MODE_NONE) != 1 ||
      SSL_set_incoming_stream_policy(
          connection,
          SSL_INCOMING_STREAM_POLICY_ACCEPT,
          H3_STREAM_CREATION_ERROR) != 1)
  {
    errata.note(
        S_ERROR,
        "Failed to configure OpenSSL QUIC stream handling: {}",
        swoc::bwf::SSLError{});
    return errata;
  }
  SSL_set_mode(connection, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE);

  auto *bio = BIO_new(BIO_s_datagram());
  if (bio == nullptr || BIO_set_fd(bio, get_fd(), BIO_NOCLOSE) != 1) {
    BIO_free(bio);
    errata.note(
        S_ERROR,
        "Failed to configure the OpenSSL QUIC datagram BIO: {}",
        swoc::bwf::SSLError{});
    return errata;
  }
  SSL_set_bio(connection, bio, bio);

  auto *peer_address = BIO_ADDR_new();
  if (peer_address == nullptr) {
    errata.note(S_ERROR, "BIO_ADDR_new failed: {}", swoc::bwf::SSLError{});
    return errata;
  }
  int address_result = 0;
  if (m_endpoint->family() == AF_INET) {
    auto const *address = reinterpret_cast<sockaddr_in const *>(&m_endpoint->sa);
    address_result = BIO_ADDR_rawmake(
        peer_address,
        AF_INET,
        &address->sin_addr,
        sizeof(address->sin_addr),
        address->sin_port);
  } else if (m_endpoint->family() == AF_INET6) {
    auto const *address = reinterpret_cast<sockaddr_in6 const *>(&m_endpoint->sa);
    address_result = BIO_ADDR_rawmake(
        peer_address,
        AF_INET6,
        &address->sin6_addr,
        sizeof(address->sin6_addr),
        address->sin6_port);
  }
  if (address_result != 1 || SSL_set1_initial_peer_addr(connection, peer_address) != 1) {
    BIO_ADDR_free(peer_address);
    errata.note(S_ERROR, "Failed to set the OpenSSL QUIC peer address: {}", swoc::bwf::SSLError{});
    return errata;
  }
  BIO_ADDR_free(peer_address);

  if (SSL_set_alpn_protos(connection, H3_ALPN, sizeof(H3_ALPN)) != 0) {
    errata.note(S_ERROR, "SSL_set_alpn_protos failed: {}", swoc::bwf::SSLError{});
    return errata;
  }
  if (!m_client_sni.empty()) {
    errata.note(S_DIAG, R"(Setting client-side H3 SNI to: "{}")", m_client_sni);
    if (SSL_set_tlsext_host_name(connection, m_client_sni.c_str()) != 1) {
      errata
          .note(S_ERROR, "Failed to set client SNI to {}: {}", m_client_sni, swoc::bwf::SSLError{});
      return errata;
    }
  }
  if (m_client_verify_mode != SSL_VERIFY_NONE) {
    errata.note(
        S_DIAG,
        R"(Setting client H3 verification mode against the proxy to: {}.)",
        m_client_verify_mode);
    SSL_set_verify(connection, m_client_verify_mode, nullptr);
  }
  return errata;
}

Errata
H3Session::initialize_http3_connection()
{
  Errata errata;
  if (quic_socket.h3conn != nullptr) {
    return errata;
  }

  nghttp3_settings settings;
  nghttp3_settings_default(&settings);
  auto const result = nghttp3_conn_client_new(
      &quic_socket.h3conn,
      &NGHTTP3_CLIENT_CALLBACKS,
      &settings,
      nghttp3_mem_default(),
      this);
  if (result != 0) {
    errata.note(S_ERROR, "nghttp3_conn_client_new failed: {} ({})", nghttp3_error(result), result);
    return errata;
  }

  auto &&[control_stream, control_errata] = quic_socket.open_stream(UNIDIRECTIONAL);
  errata.note(std::move(control_errata));
  auto &&[encoder_stream, encoder_errata] = quic_socket.open_stream(UNIDIRECTIONAL);
  errata.note(std::move(encoder_errata));
  auto &&[decoder_stream, decoder_errata] = quic_socket.open_stream(UNIDIRECTIONAL);
  errata.note(std::move(decoder_errata));
  if (!errata.is_ok()) {
    return errata;
  }

  auto const control_id = static_cast<int64_t>(SSL_get_stream_id(control_stream));
  auto const encoder_id = static_cast<int64_t>(SSL_get_stream_id(encoder_stream));
  auto const decoder_id = static_cast<int64_t>(SSL_get_stream_id(decoder_stream));
  if (auto const bind_result = nghttp3_conn_bind_control_stream(quic_socket.h3conn, control_id);
      bind_result != 0)
  {
    errata.note(
        S_ERROR,
        "nghttp3_conn_bind_control_stream failed: {} ({})",
        nghttp3_error(bind_result),
        bind_result);
    return errata;
  }
  if (auto const bind_result =
          nghttp3_conn_bind_qpack_streams(quic_socket.h3conn, encoder_id, decoder_id);
      bind_result != 0)
  {
    errata.note(
        S_ERROR,
        "nghttp3_conn_bind_qpack_streams failed: {} ({})",
        nghttp3_error(bind_result),
        bind_result);
  }
  return errata;
}

Errata
H3Session::connect()
{
  Errata errata = client_ssl_session_init(m_h3_client_context);
  if (!errata.is_ok()) {
    errata.note(S_ERROR, "TLS initialization failed.");
    return errata;
  }

  auto *connection = quic_socket.connection;
  auto const deadline = ClockType::now() + QUIC_HANDSHAKE_TIMEOUT;
  for (;;) {
    auto const result = SSL_connect(connection);
    if (result == 1) {
      break;
    }
    auto const ssl_error = SSL_get_error(connection, result);
    if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE) {
      errata.note(
          S_ERROR,
          "OpenSSL QUIC handshake failed with SSL error {}: {}",
          ssl_error,
          swoc::bwf::SSLError{});
      return errata;
    }
    if (ClockType::now() >= deadline) {
      errata.note(S_ERROR, "OpenSSL QUIC handshake timed out after {}.", QUIC_HANDSHAKE_TIMEOUT);
      return errata;
    }
    if (SSL_handle_events(connection) != 1) {
      errata.note(
          S_ERROR,
          "SSL_handle_events failed during QUIC handshake: {}",
          swoc::bwf::SSLError{});
      return errata;
    }
    auto const remaining = duration_cast<milliseconds>(deadline - ClockType::now());
    auto &&[poll_result, poll_errata] = poll_for_quic(*this, remaining, ssl_error);
    errata.note(std::move(poll_errata));
    if (!errata.is_ok() || poll_result < 0) {
      errata.note(S_ERROR, "Failed polling during the OpenSSL QUIC handshake.");
      return errata;
    }
  }

  unsigned char const *alpn = nullptr;
  unsigned int alpn_length = 0;
  SSL_get0_alpn_selected(connection, &alpn, &alpn_length);
  if (alpn == nullptr || alpn_length != 2 || std::memcmp(alpn, "h3", 2) != 0) {
    errata.note(
        S_ERROR,
        "Negotiated ALPN: {}, HTTP/3 failed to negotiate.",
        alpn == nullptr ? TextView{"none"} :
                          TextView{reinterpret_cast<char const *>(alpn), alpn_length});
    return errata;
  }
  errata.note(S_DIAG, "Negotiated ALPN: h3, HTTP/3 is negotiated.");
  errata.note(initialize_http3_connection());
  if (errata.is_ok()) {
    auto &&[progressed, progress_errata] = progress_http3(*this, 0ms);
    static_cast<void>(progressed);
    errata.note(std::move(progress_errata));
  }
  return errata;
}

Errata
H3Session::do_connect(TextView interface, swoc::IPEndpoint const *target, ProxyProtocolMsg *)
{
  Errata errata = configure_udp_socket(interface, target);
  if (errata.is_ok()) {
    errata.note(connect());
  }
  return errata;
}

swoc::Rv<int>
H3Session::poll_for_headers(milliseconds timeout)
{
  if (get_a_stream_has_ended()) {
    return 1;
  }
  swoc::Rv<int> zret{-1};
  auto &&[progressed, progress_errata] = progress_http3(*this, timeout);
  static_cast<void>(progressed);
  zret.note(std::move(progress_errata));
  if (!zret.is_ok()) {
    return zret;
  }
  zret = get_a_stream_has_ended() ? 1 : 0;
  return zret;
}

bool
H3Session::get_a_stream_has_ended() const
{
  return !m_ended_streams.empty();
}

void
H3Session::record_stream_state(int64_t stream_id, std::shared_ptr<H3StreamState> stream_state)
{
  stream_map.emplace(stream_id, std::move(stream_state));
}

void
H3Session::mark_completed_response_stream(
    int64_t stream_id,
    std::shared_ptr<H3StreamState> stream_state)
{
  m_completed_response_streams.insert_or_assign(stream_id, std::move(stream_state));
}

bool
H3Session::clear_completed_response_stream(int64_t stream_id)
{
  return m_completed_response_streams.erase(stream_id) != 0;
}

void
H3Session::set_stream_has_ended(int64_t stream_id, std::string_view key)
{
  m_ended_streams.push_back(stream_id);
  if (!key.empty()) {
    m_finished_streams.emplace(key);
  }
}

swoc::Rv<std::shared_ptr<HttpHeader>>
H3Session::read_and_parse_request(swoc::FixedBufferWriter &)
{
  swoc::Rv<std::shared_ptr<HttpHeader>> zret{nullptr};
  if (m_ended_streams.empty()) {
    zret.note(S_ERROR, "No completed HTTP/3 request stream is available.");
    return zret;
  }

  auto const stream_id = m_ended_streams.front();
  m_ended_streams.pop_front();
  auto const spot = stream_map.find(stream_id);
  if (spot == stream_map.end()) {
    zret.note(S_ERROR, "Requested headers for stream id {}, but none are available.", stream_id);
    return zret;
  }
  zret = spot->second->request_from_client;
  return zret;
}

swoc::Rv<size_t>
H3Session::drain_body(HttpHeader const &, size_t, TextView, std::shared_ptr<RuleCheck>)
{
  return {0};
}

Errata
H3Session::accept()
{
  Errata errata;
  errata.note(S_ERROR, "Server-side HTTP/3 is not implemented by Proxy Verifier.");
  return errata;
}

bool
H3Session::request_has_outstanding_stream_dependencies(HttpHeader const &request) const
{
  for (auto const &stream_dependency : request._keys_to_await) {
    if (m_finished_streams.find(stream_dependency) == m_finished_streams.end()) {
      return true;
    }
  }
  return false;
}

Errata
H3Session::run_transactions(
    std::list<Txn> const &transactions,
    TextView interface,
    swoc::IPEndpoint const *target,
    double rate_multiplier)
{
  Errata errata;
  auto const first_time = ClockType::now();
  for (auto const &transaction : transactions) {
    Errata txn_errata;
    auto const key = transaction._req.get_key();
    if (is_closed()) {
      txn_errata.note(do_connect(interface, target));
      if (!txn_errata.is_ok()) {
        txn_errata.note(S_ERROR, R"(Failed to reconnect HTTP/3 key: {}.)", key);
        break;
      }
    }

    while (request_has_outstanding_stream_dependencies(transaction._req)) {
      auto &&[progressed, progress_errata] = progress_http3(*this, Poll_Timeout);
      txn_errata.note(std::move(progress_errata));
      if (!txn_errata.is_ok() || !progressed) {
        errata.note(S_ERROR, R"(Failed HTTP/3 transaction with key: {}.)", key);
        return errata;
      }
    }

    if (rate_multiplier != 0 || transaction._user_specified_delay_duration > 0us) {
      chrono::duration<double, std::micro> delay_time = 0ms;
      auto current_time = ClockType::now();
      auto next_time = current_time;
      if (transaction._user_specified_delay_duration > 0us) {
        delay_time = transaction._user_specified_delay_duration;
        next_time += duration_cast<ClockType::duration>(delay_time);
      } else {
        next_time =
            duration_cast<ClockType::duration>(rate_multiplier * transaction._start) + first_time;
        delay_time = next_time - current_time;
      }
      while (delay_time > 0us) {
        auto &&[progressed, progress_errata] =
            progress_http3(*this, duration_cast<milliseconds>(delay_time));
        static_cast<void>(progressed);
        txn_errata.note(std::move(progress_errata));
        current_time = ClockType::now();
        delay_time = next_time - current_time;
        if (delay_time > 0us &&
            !interruptible_sleep_for(duration_cast<chrono::nanoseconds>(delay_time))) {
          break;
        }
      }
    }
    if (shutdown_requested()) {
      break;
    }
    txn_errata.note(run_transaction(transaction));
    if (!txn_errata.is_ok()) {
      errata.note(S_ERROR, R"(Failed HTTP/3 transaction with key: {}.)", key);
    }
  }
  errata.note(receive_responses());
  return errata;
}

Errata
H3Session::run_transaction(Txn const &transaction)
{
  Errata errata;
  // Register the expected response before the request is written. write()
  // services incoming packets while it waits out a content delay, so a response
  // which arrives ahead of the delayed request body has to find the expected
  // response already attached to its stream.
  m_specified_response_for_next_request = &transaction._rsp;
  auto &&[bytes_written, write_errata] = write(transaction._req);
  m_specified_response_for_next_request = nullptr;
  static_cast<void>(bytes_written);
  errata.note(std::move(write_errata));
  return errata;
}

Errata
H3Session::receive_responses()
{
  Errata errata;
  while (!stream_map.empty()) {
    if (is_closed()) {
      errata.note(S_ERROR, "The connection was closed while awaiting HTTP/3 responses.");
      break;
    }
    auto &&[progressed, progress_errata] = progress_http3(*this, Poll_Timeout);
    errata.note(std::move(progress_errata));
    if (!errata.is_ok()) {
      errata.note(S_ERROR, "Encountered a problem while receiving responses.");
      break;
    }
    if (!progressed) {
      errata.note(S_ERROR, "Timed out while awaiting HTTP/3 responses.");
      break;
    }
  }
  return errata;
}

Errata
H3Session::init(int *process_exit_code, TextView qlog_dir)
{
  Errata errata;
  m_process_exit_code = process_exit_code;
  errata.note(QuicSocket::configure_qlog_dir(qlog_dir));
  errata.note(client_ssl_ctx_init(m_h3_client_context));
  errata.note(server_ssl_ctx_init(m_h3_server_context));
  errata.note(S_DIAG, "Finished H3Session::init");
  return errata;
}

void
H3Session::terminate()
{
  terminate(m_h3_client_context);
  terminate(m_h3_server_context);
}

void
H3Session::terminate(SSL_CTX *&context)
{
  SSL_CTX_free(context);
  context = nullptr;
}

Errata
H3Session::client_ssl_ctx_init(SSL_CTX *&client_context)
{
  Errata errata;
  client_context = SSL_CTX_new(OSSL_QUIC_client_method());
  if (client_context == nullptr) {
    errata.note(
        S_ERROR,
        "Failed to create the OpenSSL QUIC client context: {}",
        swoc::bwf::SSLError{});
    return errata;
  }
  SSL_CTX_set_default_verify_paths(client_context);
  if (TLSSession::tls_secrets_are_being_logged()) {
    SSL_CTX_set_keylog_callback(client_context, TLSSession::keylog_callback);
  }
  return errata;
}

Errata
H3Session::server_ssl_ctx_init(SSL_CTX *&server_context)
{
  server_context = nullptr;
  return {};
}

void
H3Session::set_non_zero_exit_status()
{
  if (m_process_exit_code != nullptr) {
    *m_process_exit_code = 1;
  }
}
