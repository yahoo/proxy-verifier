/** @file
 * Common implementation for Proxy Verifier
 *
 * Copyright 2022, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "core/http2.h"
#include "core/verification.h"
#include "core/ProxyVerifier.h"

#include <cassert>
#include <netdb.h>
#include <thread>

#include "swoc/bwf_ex.h"
#include "swoc/bwf_ip.h"
#include "swoc/bwf_std.h"

using swoc::Errata;
using swoc::TextView;
using namespace swoc::literals;
using namespace std::literals;
using std::this_thread::sleep_for;

namespace chrono = std::chrono;
using ClockType = std::chrono::system_clock;
using chrono::duration_cast;
using chrono::milliseconds;

namespace swoc
{
inline namespace SWOC_VERSION_NS
{
BufferWriter &
bwformat(BufferWriter &w, bwf::Spec const &spec, nghttp2_settings const &settings)
{
  static const std::array<std::string_view, 6> SETTING_NAME = {{
      "HEADER_TABLE_SIZE"_sv,
      "ENABLE_PUSH"_sv,
      "MAX_CONCURRENT_STREAMS"_sv,
      "INITIAL_WINDOW_SIZE"_sv,
      "MAX_FRAME_SIZE"_sv,
      "MAX_HEADER_LIST_SIZE"_sv,
  }};
  auto setting_name = [](int n) {
    return 0 <= n && n < int(SETTING_NAME.size()) ? SETTING_NAME[n] : "Unknown: "sv;
  };
  static const bwf::Format number_fmt{"{}:{}"sv}; // numeric value format.
  for (size_t i = 0; i < settings.niv; ++i) {
    nghttp2_settings_entry const &setting{settings.iv[i]};
    if (i > 0) {
      w.print(", "sv);
    }
    if (spec.has_numeric_type()) {
      w.print(number_fmt, setting.settings_id, setting.value);
    } else {
      w.print(number_fmt, setting_name(setting.settings_id - 1), setting.value);
    }
  }
  return w;
}

BufferWriter &
bwformat(BufferWriter &w, bwf::Spec const & /* spec */, nghttp2_window_update const &window_update)
{
  static const bwf::Format fmt{"{}"sv};
  return w.print(fmt, window_update.window_size_increment);
}

} // namespace SWOC_VERSION_NS
} // namespace swoc

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
    zret.note(
        S_ERROR,
        "Requested request headers for stream id {}, but none are available.",
        stream_id);
    return zret;
  }
  auto &stream_state = stream_map_iter->second;
  zret = stream_state->_request_from_client;
  return zret;
}

swoc::Rv<size_t>
H2Session::drain_body(
    HttpHeader const &hdr,
    size_t expected_content_size,
    TextView initial,
    std::shared_ptr<RuleCheck> rule_check)
{
  if (!_h2_is_negotiated) {
    return TLSSession::drain_body(hdr, expected_content_size, initial, rule_check);
  }
  // For HTTP/2, we process entire streams once they are ended. Therefore there
  // is never body to drain.
  return {0};
}

// Complete the TLS handshake (server-side).
Errata
H2Session::accept()
{
  Errata errata = TLSSession::accept();
  if (!errata.is_ok()) {
    errata.note(S_ERROR, R"(Failed to accept SSL server object)");
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
    errata.note(
        S_DIAG,
        R"(Negotiated ALPN: {}, HTTP/2 is negotiated.)",
        TextView{(char *)alpn, alpnlen});
    _h2_is_negotiated = true;
  } else {
    errata.note(
        S_DIAG,
        R"(Negotiated ALPN: {}, HTTP/2 is not negotiated. Assuming HTTP/1)",
        (alpn == nullptr) ? "none" : TextView{(char *)alpn, alpnlen});
    _h2_is_negotiated = false;
    // The rest of the code in this function is for HTTP/2 behavior.
    return errata;
  }

  this->server_session_init();
  errata.note(S_DIAG, "Finished accept using H2Session");
  // Send initial H2 session frames
  send_connection_settings();
  send_nghttp2_data(_session, nullptr, 0, 0, this);
  return errata;
}

// Complete the TLS handshake (client-side).
Errata
H2Session::connect()
{
  // Complete the TLS handshake
  Errata errata = super_type::connect(h2_client_context);
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
    errata.note(S_DIAG, R"(h2 is negotiated.)");
    _h2_is_negotiated = true;
  } else {
    errata.note(S_DIAG, R"(h2 is not negotiated. Assuming HTTP/1)");
    _h2_is_negotiated = false;
    return errata;
  }

  this->client_session_init();

  // Send initial H2 session frames
  send_connection_settings();
  send_nghttp2_data(_session, nullptr, 0, 0, this);
  return errata;
}

Errata
H2Session::run_transactions(
    std::list<Txn> const &txn_list,
    swoc::TextView interface,
    swoc::IPEndpoint const *real_target,
    double rate_multiplier)
{
  Errata errata;

  auto const first_time = ClockType::now();
  for (auto const &txn : txn_list) {
    Errata txn_errata;
    auto const key{txn._req.get_key()};
    if (this->is_closed()) {
      txn_errata.note(this->do_connect(interface, real_target));
      if (!txn_errata.is_ok()) {
        txn_errata.note(S_ERROR, R"(Failed to reconnect HTTP/2 key: {})", key);
        // If we don't have a valid connection, there's no point in continuing.
        break;
      }
    }
    if (rate_multiplier != 0 || txn._user_specified_delay_duration > 0us) {
      std::chrono::duration<double, std::micro> delay_time = 0ms;
      auto current_time = ClockType::now();
      auto next_time = current_time + delay_time;
      if (txn._user_specified_delay_duration > 0us) {
        delay_time = txn._user_specified_delay_duration;
        next_time = current_time + delay_time;
      } else {
        auto const start_offset = txn._start;
        next_time = (rate_multiplier * start_offset) + first_time;
        delay_time = next_time - current_time;
      }
      while (delay_time > 0ms) {
        // Make use of our delay time to read any incoming responses.
        auto const ret = receive_nghttp2_data(
            this->get_session(),
            nullptr,
            0,
            0,
            this,
            duration_cast<milliseconds>(delay_time));
        current_time = ClockType::now();
        delay_time = next_time - current_time;
        if (ret < 0) {
          // There was a problem reading bytes on the socket.
          txn_errata.note(
              S_ERROR,
              "An unexpected error was received reading bytes on a socket while delaying a "
              "transaction for --rate.");
          sleep_for(delay_time);
        }
      }
    }
    txn_errata.note(this->run_transaction(txn));
    if (!txn_errata.is_ok()) {
      errata.note(S_ERROR, R"(Failed HTTP/2 transaction with key: {})", key);
    }
  }
  receive_nghttp2_responses(this->get_session(), nullptr, 0, 0, this);
  return errata;
}

Errata
H2Session::run_transaction(Txn const &txn)
{
  Errata errata;
  auto &&[bytes_written, write_errata] = this->write(txn._req);
  errata.note(std::move(write_errata));
  _last_added_stream->_specified_response = &txn._rsp;
  return errata;
}

static int
on_begin_headers_callback(
    nghttp2_session * /* session */,
    nghttp2_frame const *frame,
    void *user_data)
{
  Errata errata;
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
      errata.note(
          S_ERROR,
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
    errata.note(S_ERROR, "Got HTTP/2 headers for an unimplemented category: {}", headers_category);
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
  Errata errata;
  int const headers_category = frame->headers.cat;
  auto const stream_id = frame->hd.stream_id;
  H2Session *session_data = reinterpret_cast<H2Session *>(user_data);
  auto stream_map_iter = session_data->_stream_map.find(stream_id);
  if (stream_map_iter == session_data->_stream_map.end()) {
    errata.note(
        S_ERROR,
        "Got HTTP/2 headers for an unregistered stream id of {}. Headers category: {}",
        stream_id,
        headers_category);
    return 0;
  }
  auto &stream_state = stream_map_iter->second;

  TextView name_view = stream_state->register_rcbuf(name);
  TextView value_view = stream_state->register_rcbuf(value);

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
    errata.note(
        S_ERROR,
        "Got HTTP/2 an header for an unimplemented category: {}",
        headers_category);
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
      errata.note(S_ERROR, "Failure calling nghttp2_session_mem_send: {}", datalen);
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
  Errata errata;
  unsigned char buffer[10 * 1024];

  if (session_data->is_closed()) {
    errata.note(S_ERROR, "Socket closed while waiting for an HTTP/2 response.");
    return -1;
  }
  int n = SSL_read(session_data->get_ssl(), buffer, sizeof(buffer));
  if (n <= 0) {
    auto const ssl_error = SSL_get_error(session_data->get_ssl(), n);
    auto &&[poll_return, poll_errata] =
        session_data->poll_for_data_on_ssl_socket(timeout, ssl_error);
    errata.note(std::move(poll_errata));
    if (!errata.is_ok()) {
      errata.note(
          S_ERROR,
          R"(Failed SSL_read for HTTP/2 responses during poll: {}.)",
          swoc::bwf::Errno{});
      return -1;
    } else if (poll_return < 0) {
      session_data->close();
      errata.note(S_ERROR, "Socket closed while polling for an HTTP/2 response.");
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
      errata.note(
          S_ERROR,
          "SSL_read error in receive_nghttp2_data: {}",
          swoc::bwf::SSLError{ssl_error});
      return -1;
    }
  }

  // n > 0: Some bytes have been read. Pass that into the nghttp2 system.
  int rv = nghttp2_session_mem_recv(session_data->get_session(), buffer, (size_t)n);
  if (rv < 0) {
    errata.note(
        S_ERROR,
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

  auto timeout_count = 0;
  while (!session_data->_stream_map.empty()) {
    auto const received_bytes =
        receive_nghttp2_data(session, nullptr, 0, 0, user_data, Poll_Timeout);
    if (received_bytes < 0) {
      break;
    }
    if (received_bytes == 0) { // timeout
      ++timeout_count;
      if (timeout_count > 2) {
        Errata errata;
        errata.note(S_INFO, "{} timeouts while waiting for the following streams:", timeout_count);
        for (auto &&[id, stream_state] : session_data->_stream_map) {
          errata.note(S_INFO, "    {}: {}", id, stream_state->_key);
        }
      }
    } else { // Not timeout.
      timeout_count = 0;
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
  Errata errata;
  unsigned char buffer[10 * 1024];
  int total_recv = 0;

  auto const start_time = ClockType::now();
  while (!session_data->is_closed() && session_data->get_is_server() &&
         !session_data->get_a_stream_has_ended())
  {
    if (start_time - ClockType::now() > timeout) {
      return 0;
    }
    int n = SSL_read(session_data->get_ssl(), buffer, sizeof(buffer));
    while (n <= 0) {
      auto const ssl_error = SSL_get_error(session_data->get_ssl(), n);
      auto &&[poll_return, poll_errata] =
          session_data->poll_for_data_on_ssl_socket(timeout, ssl_error);
      errata.note(std::move(poll_errata));
      if (!errata.is_ok()) {
        errata.note(
            S_ERROR,
            R"(Failed SSL_read for HTTP/2 request headers during poll: {}.)",
            swoc::bwf::Errno{});
        return (ssize_t)total_recv;
      } else if (poll_return < 0) {
        session_data->close();
        return (ssize_t)total_recv;
      } else if (poll_return == 0) {
        return (ssize_t)total_recv;
      }
      // Poll succeeded. Repeat the attempt to read.
      n = SSL_read(session_data->get_ssl(), buffer, sizeof(buffer));
    }
    int rv = nghttp2_session_mem_recv(session, buffer, (size_t)n);
    if (rv < 0) {
      errata.note(
          S_ERROR,
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
  Errata errata;

  switch (frame->hd.type) {
  case NGHTTP2_DATA:
    break;
  case NGHTTP2_HEADERS:
    break;
  case NGHTTP2_PRIORITY:
    break;
  case NGHTTP2_RST_STREAM:
    break;
  case NGHTTP2_SETTINGS: {
    nghttp2_settings const &settings_frame{frame->settings};
    errata.note(
        S_DIAG,
        "Received SETTINGS frame with stream id {}: {}",
        frame->hd.stream_id,
        settings_frame);
  } break;
  case NGHTTP2_WINDOW_UPDATE: {
    nghttp2_window_update const &window_update_frame{frame->window_update};
    errata.note(
        S_DIAG,
        "Received WINDOW_UPDATE frame with stream id {}: {}",
        frame->hd.stream_id,
        window_update_frame);
  } break;
  case NGHTTP2_PUSH_PROMISE:
    break;
  case NGHTTP2_GOAWAY:
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
        if (auto spot{
                request_from_client._fields_rules->_fields.find(HttpHeader::FIELD_CONTENT_LENGTH)};
            spot != request_from_client._fields_rules->_fields.end())
        {
          size_t expected_size = swoc::svtou(spot->second);
          stream_state._body_received.reserve(expected_size);
        }
        errata.note(
            S_DIAG,
            "Received an HTTP/2 request for key {} with stream id {}:\n{}",
            stream_state._key,
            stream_id,
            request_from_client);
      } else if (headers_category == NGHTTP2_HCAT_RESPONSE) {
        auto &response_from_wire = *stream_state._response_from_server;
        response_from_wire.derive_key();
        if (stream_state._key.empty()) {
          // A response for which we didn't process the request, presumably. A
          // server push? Maybe? In theory we can support that but currently we
          // do not. Emit a warning for now.
          stream_state._key = response_from_wire.get_key();
          errata.note(
              S_ERROR,
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
        if (auto spot{
                response_from_wire._fields_rules->_fields.find(HttpHeader::FIELD_CONTENT_LENGTH)};
            spot != response_from_wire._fields_rules->_fields.end())
        {
          size_t expected_size = swoc::svtou(spot->second);
          stream_state._body_received.reserve(expected_size);
        }
        errata.note(
            S_DIAG,
            "Received an HTTP/2 response for key {} with stream id {}:\n{}",
            stream_state._key,
            stream_id,
            response_from_wire);
        auto const &key = stream_state._key;
        auto const &specified_response = stream_state._specified_response;
        if (response_from_wire.verify_headers(key, *specified_response->_fields_rules)) {
          errata.note(
              S_ERROR,
              R"(HTTP/2 response headers did not match expected response headers.)");
          session_data->set_non_zero_exit_status();
        }
        if (specified_response->_status != 0 &&
            response_from_wire._status != specified_response->_status &&
            (response_from_wire._status != 200 || specified_response->_status != 304) &&
            (response_from_wire._status != 304 || specified_response->_status != 200))
        {
          errata.note(
              S_ERROR,
              R"(HTTP/2 Status Violation: expected {} got {}, key: {})",
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
  Errata errata;
  errata.note(S_DIAG, "HTTP/2 stream is closed with id: {}", stream_id);
  H2Session *session_data = reinterpret_cast<H2Session *>(user_data);
  auto iter = session_data->_stream_map.find(stream_id);
  if (iter == session_data->_stream_map.end()) {
    errata.note(
        S_ERROR,
        "HTTP/2 stream is closed with id {} but could not find it tracked internally",
        stream_id);
    return 0;
  }
  H2StreamState &stream_state = *iter->second;

  if (session_data->get_is_server()) {
    if (stream_state._specified_request->_content_rule) {
      if (!stream_state._specified_request->_content_rule
               ->test(stream_state._key, "body", swoc::TextView(stream_state._body_received)))
      {
        errata.note(S_DIAG, R"(Body content did not match expected value.)");
      }
    }
  } else {
    if (stream_state._specified_response->_content_rule) {
      if (!stream_state._specified_response->_content_rule
               ->test(stream_state._key, "body", swoc::TextView(stream_state._body_received)))
      {
        errata.note(S_DIAG, R"(Body content did not match expected value.)");
      }
    }
  }

  auto const &message_start = stream_state._stream_start;
  auto const message_end = ClockType::now();
  auto const elapsed_ms = duration_cast<chrono::milliseconds>(message_end - message_start);
  if (elapsed_ms > Transaction_Delay_Cutoff) {
    errata.note(
        S_ERROR,
        R"(HTTP/2 transaction in stream id {} with key {} took {}.)",
        stream_id,
        stream_state._key,
        elapsed_ms);
  }
  session_data->_stream_map.erase(iter);
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
  Errata errata;
  auto *session_data = reinterpret_cast<H2Session *>(user_data);
  auto iter = session_data->_stream_map.find(stream_id);
  if (iter == session_data->_stream_map.end()) {
    errata.note(S_ERROR, "Could not find a stream with stream id: {}", stream_id);
    return 0;
  }
  H2StreamState &stream_state = *iter->second;
  errata.note(
      S_DIAG,
      "Received an HTTP/2 body of {} bytes for key {} with stream id {}:\n{}",
      len,
      stream_state._key,
      stream_id,
      TextView(reinterpret_cast<char const *>(data), len));
  stream_state._body_received += std::string(reinterpret_cast<char const *>(data), len);
  return 0;
}

H2StreamState::H2StreamState()
  : _stream_start{ClockType::now()}
  , _request_from_client{std::make_shared<HttpHeader>()}
  , _response_from_server{std::make_shared<HttpHeader>()}
{
  _request_from_client->set_is_request(HTTP_PROTOCOL_TYPE::HTTP_2);
  _response_from_server->set_is_response(HTTP_PROTOCOL_TYPE::HTTP_2);
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

TextView
H2StreamState::register_rcbuf(nghttp2_rcbuf *rcbuf)
{
  nghttp2_rcbuf_incref(rcbuf);
  _rcbufs_to_free.push_back(rcbuf);
  auto buf = nghttp2_rcbuf_get_buf(rcbuf);
  return TextView(reinterpret_cast<char *>(buf.base), buf.len);
}

H2Session::H2Session() : _session{nullptr}, _callbacks{nullptr}, _options{nullptr} { }

H2Session::H2Session(TextView const &client_sni, int client_verify_mode)
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
H2Session::write(TextView data)
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
  Errata errata;
  size_t num_to_copy = 0;
  H2StreamState *stream_state =
      reinterpret_cast<H2StreamState *>(nghttp2_session_get_stream_user_data(session, stream_id));
  if (stream_state == nullptr) {
    auto *session_data = reinterpret_cast<H2Session *>(user_data);
    auto iter = session_data->_stream_map.find(stream_id);
    if (iter == session_data->_stream_map.end()) {
      errata.note(S_ERROR, "Could not find a stream with stream id: {}", stream_id);
      return 0;
    }
    stream_state = iter->second.get();
  }
  TextView body_sent = "";
  if (!stream_state->_wait_for_continue) {
    num_to_copy =
        std::min(length, stream_state->_send_body_length - stream_state->_send_body_offset);
    if (num_to_copy > 0) {
      body_sent =
          TextView{stream_state->_body_to_send + stream_state->_send_body_offset, num_to_copy};
      memcpy(buf, body_sent.data(), body_sent.length());
      stream_state->_send_body_offset += num_to_copy;
    } else {
      num_to_copy = 0;
    }
    if (stream_state->_send_body_offset >= stream_state->_send_body_length) {
      *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }
  }
  errata.note(
      S_DIAG,
      "Sent an HTTP/2 body of {} bytes for key {} of stream id {}:\n{}",
      num_to_copy,
      stream_state->_key,
      stream_id,
      body_sent);
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
  if (hdr.is_response()) {
    stream_id = hdr._stream_id;
    auto stream_map_iter = _stream_map.find(stream_id);
    if (stream_map_iter == _stream_map.end()) {
      zret.note(S_ERROR, "Could not find registered stream for stream id: {}", stream_id);
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
  if (hdr.is_response()) {
    stream_state->store_nv_response_headers_to_free(hdrs);
  } else {
    stream_state->store_nv_request_headers_to_free(hdrs);
  }

  stream_state->_key = hdr.get_key();
  if (hdr._content_size > 0 && (hdr.is_request() || !HttpHeader::STATUS_NO_CONTENT[hdr._status])) {
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
    if (hdr.is_response()) {
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
    if (hdr.is_response()) {
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

  if (hdr.is_response()) {
    stream_id = stream_state->get_stream_id();
    if (submit_result < 0) {
      zret.note(
          S_ERROR,
          "Submitting an HTTP/2 response with stream id {} failed: {}",
          stream_id,
          submit_result);
    }
  } else { // request
    if (submit_result < 0) {
      zret.note(S_ERROR, "Submitting an HTTP/2 request failed: {}", submit_result);
    } else {
      stream_id = submit_result;
      stream_state->set_stream_id(stream_id);
      record_stream_state(stream_id, new_stream_state);
    }
  }
  if (zret.is_ok()) {
    zret.note(
        S_DIAG,
        "Sent the following HTTP/2 {}{} headers for key {} with stream id {}:\n{}",
        swoc::bwf::If(hdr.is_request(), "request"),
        swoc::bwf::If(hdr.is_response(), "response"),
        stream_state->_key,
        stream_id,
        hdr);
    // Make sure the logging of the headers are emitted before the body.
    zret.errata().sink();
  }

  // Kick off the send logic to put the data on the wire
  zret.result() = send_nghttp2_data(_session, nullptr, 0, 0, this);

  return zret;
}

Errata
H2Session::pack_headers(HttpHeader const &hdr, nghttp2_nv *&nv_hdr, int &hdr_count)
{
  Errata errata;
  if (!_h2_is_negotiated) {
    errata.note(S_ERROR, "Should not be packing headers if h2 is not negotiated.");
    return errata;
  }
  hdr_count = hdr._fields_rules->_fields.size();

  if (!hdr._contains_pseudo_headers_in_fields_array) {
    if (hdr.is_response()) {
      hdr_count += 1;
    } else if (hdr.is_request()) {
      hdr_count += 4;
    } else {
      hdr_count = 0;
      errata.note(
          S_ERROR,
          R"(Unable to write header: could not determine request/response state.)");
      return errata;
    }
  }

  nv_hdr = reinterpret_cast<nghttp2_nv *>(malloc(sizeof(nghttp2_nv) * hdr_count));
  int offset = 0;

  // nghttp2 requires pseudo header fields to be at the start of the
  // nv array. Thus we add them here before calling add_fields_to_ngnva
  // which then skips the pseueo headers if they are in there.
  if (hdr.is_response()) {
    nv_hdr[offset++] = tv_to_nv(":status", hdr._status_string);
  } else if (hdr.is_request()) {
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
H2Session::tv_to_nv(char const *name, TextView v)
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

Errata
H2Session::send_connection_settings()
{
  Errata errata;
  nghttp2_settings_entry iv[1] = {{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
  int rv = 0;

  /* client 24 bytes magic string will be sent by nghttp2 library */
  rv = nghttp2_submit_settings(this->_session, NGHTTP2_FLAG_NONE, iv, 1);
  if (rv != 0) {
    errata.note(S_ERROR, R"(Could not submit SETTINGS)");
  }
  return errata;
}

// static
Errata
H2Session::init(int *process_exit_code)
{
  H2Session::process_exit_code = process_exit_code;
  Errata errata = H2Session::client_init(h2_client_context);
  errata.note(H2Session::server_init(server_context));
  errata.note(S_DIAG, "Finished H2Session::init");
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
Errata
H2Session::client_init(SSL_CTX *&client_context)
{
  Errata errata = super_type::client_init(client_context);

  if (!errata.is_ok()) {
    return errata;
  }

#ifndef OPENSSL_NO_NEXTPROTONEG
  // Initialize the protocol selection to include H2
  SSL_CTX_set_next_proto_select_cb(client_context, select_next_proto_cb, nullptr);
#endif /* !OPENSSL_NO_NEXTPROTONEG */

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
  // Set the protocols the client will advertise
  SSL_CTX_set_alpn_protos(client_context, protocol_negotiation_string, protocol_negotiation_len);
#else
  static_assert(false, "Error must be at least openssl 1.0.2");
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L

  if (TLSSession::tls_secrets_are_being_logged()) {
    SSL_CTX_set_keylog_callback(client_context, TLSSession::keylog_callback);
  }

  return errata;
}

// static
Errata
H2Session::server_init(SSL_CTX *&server_context)
{
  Errata errata;
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

Errata
H2Session::client_session_init()
{
  Errata errata;

  // Set up the H2 callback methods
  int ret = nghttp2_session_callbacks_new(&this->_callbacks);

  if (ret != 0) {
    errata.note(S_ERROR, "nghttp2_session_callbacks_new {}", ret);
  }

  if (0 != nghttp2_option_new(&_options)) {
    errata.note(S_ERROR, "nghttp2_option_new could not allocate memory.");
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

Errata
H2Session::server_session_init()
{
  Errata errata;
  if (!_h2_is_negotiated) {
    return errata;
  }

  _is_server = true;

  // Set up the H2 callback methods
  auto ret = nghttp2_session_callbacks_new(&this->_callbacks);
  if (0 != ret) {
    errata.note(S_ERROR, "nghttp2_session_callbacks_new {}", ret);
    return errata;
  }

  if (0 != nghttp2_option_new(&_options)) {
    errata.note(S_ERROR, "nghttp2_option_new could not allocate memory.");
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
    errata.note(S_ERROR, "nghttp2_session_server_new could not initialize a new session.");
    return errata;
  }

  return errata;
}
