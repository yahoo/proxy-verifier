/** @file
 * Common implementation for Proxy Verifier
 *
 * Copyright 2022, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "core/http3.h"
#include "core/https.h"
#include "core/verification.h"
#include "core/ProxyVerifier.h"

#include <cassert>
#include <filesystem>
#include <fcntl.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_openssl.h>
#include <netdb.h>

#include "swoc/bwf_ex.h"
#include "swoc/bwf_ip.h"
#include "swoc/bwf_std.h"

/*
 * ngtcp2/nghttp3 does not currently have any code examples. The curl
 * implementation was helpful in forming this code:
 *
 * From curl/lib/quic/:
 *
 *   #ifdef ENABLE_QUIC
 *   #ifdef USE_NGTCP2
 *   #include "vquic/ngtcp2.h" // <------ Use this
 *   #endif
 *   #ifdef USE_QUICHE
 *   #include "vquic/quiche.h"
 *   #endif
 */

using swoc::Errata;
using swoc::TextView;
using swoc::bwf::Ngtcp2Error;
using swoc::bwf::Nghttp3Error;
using swoc::bwf::Errno;
using namespace swoc::literals;
using namespace std::literals;
using std::this_thread::sleep_for;

namespace chrono = std::chrono;
using ClockType = chrono::system_clock;
using chrono::duration_cast;
using chrono::milliseconds;
using chrono::nanoseconds;

constexpr auto QUIC_MAX_STREAMS = 256 * 1024;
constexpr auto QUIC_MAX_DATA = 1 * 1024 * 1024;
constexpr auto QUIC_IDLE_TIMEOUT = 60s;

// TextView H3_ALPN_H3_29_H3 = "\x5h3-29\x2h3";
TextView H3_ALPN_H3_29_H3 = "\x5h3-29";
constexpr char const *QUIC_CIPHERS = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_"
                                     "POLY1305_SHA256:TLS_AES_128_CCM_SHA256";

constexpr char const *QUIC_GROUPS = "P-256:X25519:P-384:P-521";

int *H3Session::process_exit_code = nullptr;

std::random_device QuicSocket::_rd;
std::mt19937 QuicSocket::_rng(_rd());
std::uniform_int_distribution<int> QuicSocket::_uni_id(0, std::numeric_limits<uint8_t>::max());
swoc::file::path QuicSocket::_qlog_dir;
std::mutex QuicSocket::_qlog_mutex;

namespace swoc
{
inline namespace SWOC_VERSION_NS
{
BufferWriter &
bwformat(BufferWriter &w, bwf::Spec const &spec, bwf::Ngtcp2Error const &error)
{
  // Hand rolled, might not be totally compliant everywhere, but probably close
  // enough. The long string will be locally accurate. Clang requires the double
  // braces.
  static const std::unordered_map<int, std::string_view> SHORT_NAME = {
      {-201, "NGTCP2_ERR_INVALID_ARGUMENT: "},
      {-203, "NGTCP2_ERR_NOBUF: "},
      {-205, "NGTCP2_ERR_PROTO: "},
      {-206, "NGTCP2_ERR_INVALID_STATE: "},
      {-207, "NGTCP2_ERR_ACK_FRAME: "},
      {-208, "NGTCP2_ERR_STREAM_ID_BLOCKED: "},
      {-209, "NGTCP2_ERR_STREAM_IN_USE: "},
      {-210, "NGTCP2_ERR_STREAM_DATA_BLOCKED: "},
      {-211, "NGTCP2_ERR_FLOW_CONTROL: "},
      {-212, "NGTCP2_ERR_CONNECTION_ID_LIMIT: "},
      {-213, "NGTCP2_ERR_STREAM_LIMIT: "},
      {-214, "NGTCP2_ERR_FINAL_SIZE: "},
      {-215, "NGTCP2_ERR_CRYPTO: "},
      {-216, "NGTCP2_ERR_PKT_NUM_EXHAUSTED: "},
      {-217, "NGTCP2_ERR_REQUIRED_TRANSPORT_PARAM: "},
      {-218, "NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM: "},
      {-219, "NGTCP2_ERR_FRAME_ENCODING: "},
      {-220, "NGTCP2_ERR_TLS_DECRYPT: "},
      {-221, "NGTCP2_ERR_STREAM_SHUT_WR: "},
      {-222, "NGTCP2_ERR_STREAM_NOT_FOUND: "},
      {-226, "NGTCP2_ERR_STREAM_STATE: "},
      {-229, "NGTCP2_ERR_RECV_VERSION_NEGOTIATION: "},
      {-230, "NGTCP2_ERR_CLOSING: "},
      {-231, "NGTCP2_ERR_DRAINING: "},
      {-234, "NGTCP2_ERR_TRANSPORT_PARAM: "},
      {-235, "NGTCP2_ERR_DISCARD_PKT: "},
      {-236, "NGTCP2_ERR_PATH_VALIDATION_FAILED: "},
      {-237, "NGTCP2_ERR_CONN_ID_BLOCKED: "},
      {-238, "NGTCP2_ERR_INTERNAL: "},
      {-239, "NGTCP2_ERR_CRYPTO_BUFFER_EXCEEDED: "},
      {-240, "NGTCP2_ERR_WRITE_MORE: "},
      {-241, "NGTCP2_ERR_RETRY: "},
      {-242, "NGTCP2_ERR_DROP_CONN: "},
      {-243, "NGTCP2_ERR_AEAD_LIMIT_REACHED: "},
      {-244, "NGTCP2_ERR_NO_VIABLE_PATH: "},
      {-500, "NGTCP2_ERR_FATAL: "},
      {-501, "NGTCP2_ERR_NOMEM: "},
      {-502, "NGTCP2_ERR_CALLBACK_FAILURE: "},
  };

  auto short_name = [](int n) -> std::string_view {
    if (n > -201 || n < -502) {
      return "Unknown ngtcp2 error: ";
    }
    auto spot = SHORT_NAME.find(n);
    if (spot == SHORT_NAME.end()) {
      return "Unknown ngtcp2 error: ";
    }
    return spot->second;
  };
  static const bwf::Format number_fmt{"[{}]"sv}; // numeric value format.
  if (spec.has_numeric_type()) {                 // if numeric type, print just the numeric
                                                 // part.
    w.print(number_fmt, error._e);
  } else {
    w.write(short_name(error._e));
    auto const *error_reason = ngtcp2_strerror(error._e);
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

BufferWriter &
bwformat(BufferWriter &w, bwf::Spec const &spec, bwf::Nghttp3Error const &error)
{
  // Hand rolled, might not be totally compliant everywhere, but probably close
  // enough. The long string will be locally accurate. Clang requires the double
  // braces.
  static const std::unordered_map<int, std::string_view> SHORT_NAME = {
      {-101, "NGHTTP3_ERR_INVALID_ARGUMENT: "},
      {-102, "NGHTTP3_ERR_NOBUF: "},
      {-103, "NGHTTP3_ERR_INVALID_STATE: "},
      {-104, "NGHTTP3_ERR_WOULDBLOCK: "},
      {-105, "NGHTTP3_ERR_STREAM_IN_USE: "},
      {-106, "NGHTTP3_ERR_PUSH_ID_BLOCKED: "},
      {-107, "NGHTTP3_ERR_MALFORMED_HTTP_HEADER: "},
      {-108, "NGHTTP3_ERR_REMOVE_HTTP_HEADER: "},
      {-109, "NGHTTP3_ERR_MALFORMED_HTTP_MESSAGING: "},
      {-111, "NGHTTP3_ERR_QPACK_FATAL: "},
      {-112, "NGHTTP3_ERR_QPACK_HEADER_TOO_LARGE: "},
      {-113, "NGHTTP3_ERR_IGNORE_STREAM: "},
      {-114, "NGHTTP3_ERR_STREAM_NOT_FOUND: "},
      {-115, "NGHTTP3_ERR_IGNORE_PUSH_PROMISE: "},
      {-116, "NGHTTP3_ERR_CONN_CLOSING: "},
      {-402, "NGHTTP3_ERR_QPACK_DECOMPRESSION_FAILED: "},
      {-403, "NGHTTP3_ERR_QPACK_ENCODER_STREAM_ERROR: "},
      {-404, "NGHTTP3_ERR_QPACK_DECODER_STREAM_ERROR: "},
      {-408, "NGHTTP3_ERR_H3_FRAME_UNEXPECTED: "},
      {-409, "NGHTTP3_ERR_H3_FRAME_ERROR: "},
      {-665, "NGHTTP3_ERR_H3_MISSING_SETTINGS: "},
      {-667, "NGHTTP3_ERR_H3_INTERNAL_ERROR: "},
      {-668, "NGHTTP3_ERR_H3_CLOSED_CRITICAL_STREAM: "},
      {-669, "NGHTTP3_ERR_H3_GENERAL_PROTOCOL_ERROR: "},
      {-670, "NGHTTP3_ERR_H3_ID_ERROR: "},
      {-671, "NGHTTP3_ERR_H3_SETTINGS_ERROR: "},
      {-672, "NGHTTP3_ERR_H3_STREAM_CREATION_ERROR: "},
      {-900, "NGHTTP3_ERR_FATAL: "},
      {-901, "NGHTTP3_ERR_NOMEM: "},
      {-902, "NGHTTP3_ERR_CALLBACK_FAILURE: "},
  };

  auto short_name = [](int n) -> std::string_view {
    if (n > -201 || n < -502) {
      return "Unknown nghttp3 error: ";
    }
    auto spot = SHORT_NAME.find(n);
    if (spot == SHORT_NAME.end()) {
      return "Unknown nghttp3 error: ";
    }
    return spot->second;
  };
  static const bwf::Format number_fmt{"[{}]"sv}; // numeric value format.
  if (spec.has_numeric_type()) {                 // if numeric type, print just the numeric
                                                 // part.
    w.print(number_fmt, error._e);
  } else {
    w.write(short_name(error._e));
    auto const *error_reason = nghttp3_strerror(error._e);
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

/** Receive data off of the socket.
 *
 * @return -1 on failure, otherwise the number of bytes received.
 */
static swoc::Rv<int> ngtcp2_process_ingress(H3Session &session, milliseconds timeout);

/** Send data on the socket.
 *
 * @return -1 on failure, otherwise the number of bytes sent.
 */
static swoc::Rv<int> ngtcp2_flush_egress(H3Session &session);

/** Return a representation of the current time compatible with ngtcp
 * expectations.
 *
 * @return The current time.
 */
static long
timestamp()
{
  auto const current_time = ClockType::now();
  auto const duration_since_epoch = current_time.time_since_epoch();
  return duration_cast<nanoseconds>(duration_since_epoch).count();
}

// --------------------------------------------
// Begin ngtcp2 callbacks.
// --------------------------------------------
static int
cb_handshake_completed(ngtcp2_conn * /* tconn */, void * /* user_data */)
{
  Errata errata;
  errata.note(S_DIAG, R"(h3 is negotiated.)");
  return 0;
}

static int
cb_recv_stream_data(
    ngtcp2_conn *tconn,
    uint32_t flags,
    int64_t stream_id,
    uint64_t /* offset */,
    const uint8_t *buf,
    size_t buflen,
    void *conn_data,
    void * /* stream_user_data */)
{
  H3Session *h3_session = reinterpret_cast<H3Session *>(conn_data);
  int fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) ? 1 : 0;

  ssize_t nconsumed =
      nghttp3_conn_read_stream(h3_session->quic_socket.h3conn, stream_id, buf, buflen, fin);
  if (nconsumed < 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  /* A comment from the CURL code:
   *
   * number of bytes inside buflen which consists of framing overhead
   * including QPACK HEADERS. In other words, it does not consume payload of
   * DATA frame. */
  ngtcp2_conn_extend_max_stream_offset(tconn, stream_id, nconsumed);
  ngtcp2_conn_extend_max_offset(tconn, nconsumed);

  return 0;
}

static int
cb_acked_stream_data_offset(
    ngtcp2_conn * /* tconn */,
    int64_t stream_id,
    uint64_t /* offset */,
    uint64_t datalen,
    void *conn_data,
    void * /* stream_user_data */)
{
  H3Session *h3_session = reinterpret_cast<H3Session *>(conn_data);
  int rv = nghttp3_conn_add_ack_offset(h3_session->quic_socket.h3conn, stream_id, datalen);
  if (rv != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int
cb_stream_close(
    ngtcp2_conn * /* tconn */,
    uint32_t flags,
    int64_t stream_id,
    uint64_t app_error_code,
    void *conn_data,
    void * /* stream_user_data */)
{
  H3Session *h3_session = reinterpret_cast<H3Session *>(conn_data);

  if (!(flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET)) {
    app_error_code = NGHTTP3_H3_NO_ERROR;
  }

  int rv = nghttp3_conn_close_stream(h3_session->quic_socket.h3conn, stream_id, app_error_code);
  if (rv != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static void
cb_rand(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx * /* rand_ctx */)
{
  QuicSocket::randomly_populate_array(dest, destlen);
}

static int
cb_get_new_connection_id(
    ngtcp2_conn * /* tconn */,
    ngtcp2_cid *cid,
    uint8_t *token,
    size_t cidlen,
    void * /* user_data */)
{
  QuicSocket::randomly_populate_array(cid->data, cidlen);
  cid->datalen = cidlen;
  QuicSocket::randomly_populate_array(token, NGTCP2_STATELESS_RESET_TOKENLEN);
  return 0;
}

static int
cb_stream_reset(
    ngtcp2_conn * /* tconn */,
    int64_t stream_id,
    uint64_t /* final_size */,
    uint64_t /* app_error_code */,
    void *conn_data,
    void * /* stream_user_data */)
{
  H3Session *h3_session = reinterpret_cast<H3Session *>(conn_data);
  int rv = nghttp3_conn_shutdown_stream_read(h3_session->quic_socket.h3conn, stream_id);
  if (rv != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int
cb_stream_stop_sending(
    ngtcp2_conn * /* tconn */,
    int64_t stream_id,
    uint64_t /* app_error_code */,
    void *conn_data,
    void * /* stream_user_data */)
{
  H3Session *h3_session = reinterpret_cast<H3Session *>(conn_data);
  int rv = nghttp3_conn_shutdown_stream_read(h3_session->quic_socket.h3conn, stream_id);
  if (rv) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int
cb_extend_max_local_streams_bidi(
    ngtcp2_conn * /* tconn */,
    uint64_t /*max_streams */,
    void * /*user_data */)
{
  return 0;
}

static int
cb_extend_max_stream_data(
    ngtcp2_conn * /* tconn */,
    int64_t stream_id,
    uint64_t /* max_data */,
    void *conn_data,
    void * /* stream_user_data */)
{
  H3Session *h3_session = reinterpret_cast<H3Session *>(conn_data);
  int rv = nghttp3_conn_unblock_stream(h3_session->quic_socket.h3conn, stream_id);
  if (rv != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

/// @return 0 on success, 1 on failure.
static int initialize_nghttp3_connection(H3Session *session);

static int
quic_set_encryption_secrets(
    SSL *ssl,
    OSSL_ENCRYPTION_LEVEL ossl_level,
    const uint8_t *rx_secret,
    const uint8_t *tx_secret,
    size_t secretlen)
{
  auto *h3_session = reinterpret_cast<H3Session *>(SSL_get_app_data(ssl));
  auto &qs = h3_session->quic_socket;
  auto const level = ngtcp2_crypto_openssl_from_ossl_encryption_level(ossl_level);

  if (ngtcp2_crypto_derive_and_install_rx_key(
          qs.qconn,
          nullptr,
          nullptr,
          nullptr,
          level,
          rx_secret,
          secretlen) != 0)
    return 0;

  if (ngtcp2_crypto_derive_and_install_tx_key(
          qs.qconn,
          nullptr,
          nullptr,
          nullptr,
          level,
          tx_secret,
          secretlen) != 0)
    return 0;

  if (level == NGTCP2_CRYPTO_LEVEL_APPLICATION) {
    if (initialize_nghttp3_connection(h3_session) != 0) {
      return 0;
    }
  }

  return 1;
}

static int
write_client_handshake(
    QuicSocket *qs,
    ngtcp2_crypto_level level,
    const uint8_t *data,
    size_t data_len)
{
  Errata errata;
  assert(level <= QuicSocket::MAX_NGTCP2_CRYPTO_LEVEL);
  QuicHandshake *crypto_data = &qs->crypto_data[level];
  auto &buf = crypto_data->buf;

  // If the accumulated amount of data sent is greater than our reserved size
  // for buf, then we'll be in trouble because the following insert call may
  // result in resizing buf's std::vector memory. This will free the memory
  // referenced via previous calls to ngtcp2_conn_submit_crypto_data, resulting
  // in a use-after-free.
  assert((buf.size() + data_len) <= QuicHandshake::max_handshake_size);

  // Get the initial pointer to the end of the current buffer, which will be
  // the beginning of the copied data.
  uint8_t *copied_data_start = reinterpret_cast<uint8_t *>(buf.data() + buf.size());

  // Copy data into our buffer so that we will preserve it for the OpenSSL API.
  buf.insert(buf.end(), data, data + data_len);

  int rv = ngtcp2_conn_submit_crypto_data(qs->qconn, level, copied_data_start, data_len);
  if (rv != 0) {
    errata.note(S_ERROR, "write_client_handshake failed");
    return 0;
  }
  return 1;
}

static int
quic_add_handshake_data(SSL *ssl, OSSL_ENCRYPTION_LEVEL ossl_level, const uint8_t *data, size_t len)
{
  auto *h3_session = reinterpret_cast<H3Session *>(SSL_get_app_data(ssl));
  auto &qs = h3_session->quic_socket;
  auto const level = ngtcp2_crypto_openssl_from_ossl_encryption_level(ossl_level);

  return write_client_handshake(&qs, level, data, len);
}

static int
quic_flush_flight(SSL * /* ssl */)
{
  return 1;
}

static int
quic_send_alert(SSL *ssl, enum ssl_encryption_level_t /* level */, uint8_t alert)
{
  auto *h3_session = reinterpret_cast<H3Session *>(SSL_get_app_data(ssl));
  auto &qs = h3_session->quic_socket;
  qs.tls_alert = alert;
  return 1;
}

static SSL_QUIC_METHOD ssl_quic_method =
    {quic_set_encryption_secrets, quic_add_handshake_data, quic_flush_flight, quic_send_alert};

static ngtcp2_callbacks client_ngtcp2_callbacks = {
    ngtcp2_crypto_client_initial_cb,
    nullptr, /* recv_client_initial */
    ngtcp2_crypto_recv_crypto_data_cb,
    cb_handshake_completed,
    nullptr, /* recv_version_negotiation */
    ngtcp2_crypto_encrypt_cb,
    ngtcp2_crypto_decrypt_cb,
    ngtcp2_crypto_hp_mask_cb,
    cb_recv_stream_data,
    cb_acked_stream_data_offset,
    nullptr, /* stream_open */
    cb_stream_close,
    nullptr, /* recv_stateless_reset */
    ngtcp2_crypto_recv_retry_cb,
    cb_extend_max_local_streams_bidi,
    nullptr, /* extend_max_local_streams_uni */
    cb_rand,
    cb_get_new_connection_id,
    nullptr,                     /* remove_connection_id */
    ngtcp2_crypto_update_key_cb, /* update_key */
    nullptr,                     /* path_validation */
    nullptr,                     /* select_preferred_addr */
    cb_stream_reset,
    nullptr, /* extend_max_remote_streams_bidi */
    nullptr, /* extend_max_remote_streams_uni */
    cb_extend_max_stream_data,
    nullptr, /* dcid_status */
    nullptr, /* handshake_confirmed */
    nullptr, /* recv_new_token */
    ngtcp2_crypto_delete_crypto_aead_ctx_cb,
    ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
    nullptr, /* recv_datagram */
    nullptr, /* ack_datagram */
    nullptr, /* lost_datagram */
    ngtcp2_crypto_get_path_challenge_data_cb,
    cb_stream_stop_sending,
    nullptr, /* version_negotiation */
};

// TODO: fill this out when we add server-side code.
#if 0
static ngtcp2_callbacks server_ngtcp2_callbacks = {
  nullptr, /* client_initial */
  ngtcp2_crypto_recv_client_initial_cb, /* recv_client_initial */
  ngtcp2_crypto_recv_crypto_data_cb,
  cb_handshake_completed,
  nullptr, /* recv_version_negotiation */
  ngtcp2_crypto_encrypt_cb,
  ngtcp2_crypto_decrypt_cb,
  ngtcp2_crypto_hp_mask_cb,
  cb_recv_stream_data,
  cb_acked_stream_data_offset,
  nullptr, /* stream_open */
  cb_stream_close,
  nullptr, /* recv_stateless_reset */
  ngtcp2_crypto_recv_retry_cb,
  cb_extend_max_local_streams_bidi,
  nullptr, /* extend_max_local_streams_uni */
  cb_rand,
  cb_get_new_connection_id,
  nullptr, /* remove_connection_id */
  ngtcp2_crypto_update_key_cb, /* update_key */
  nullptr, /* path_validation */
  nullptr, /* select_preferred_addr */
  cb_stream_reset,
  nullptr, /* extend_max_remote_streams_bidi */
  nullptr, /* extend_max_remote_streams_uni */
  cb_extend_max_stream_data,
  nullptr, /* dcid_status */
  nullptr, /* handshake_confirmed */
  nullptr, /* recv_new_token */
  ngtcp2_crypto_delete_crypto_aead_ctx_cb,
  ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
  nullptr /* recv_datagram */
};
#endif

// --------------------------------------------
// End ngtcp2 callbacks.
// --------------------------------------------

static swoc::Rv<int>
ngtcp2_process_ingress(H3Session &session, milliseconds timeout)
{
  uint8_t buf[65536];
  size_t bufsize = sizeof(buf);
  struct sockaddr_storage remote_addr;
  socklen_t remote_addrlen = sizeof(remote_addr);
  ssize_t num_bytes_received = 0;
  swoc::Rv<int> zret{-1};

  for (;;) {
    num_bytes_received = recvfrom(
        session.get_fd(),
        (char *)buf,
        bufsize,
        0,
        (struct sockaddr *)&remote_addr,
        &remote_addrlen);
    if (num_bytes_received > 0) {
      // Success. We read data off the socket.
      break;
    }
    if (num_bytes_received == -1) {
      if (errno == EINTR) {
        continue;
      } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
        auto &&[poll_return, poll_errata] = session.poll_for_data_on_socket(timeout);
        zret.note(std::move(poll_errata));
        if (!zret.is_ok()) {
          zret.note(std::move(poll_errata));
          zret.note(S_ERROR, "Failed to poll for HTTP/3 data.");
          session.close();
          zret = -1;
          return zret;
        } else if (poll_return > 0) {
          // Simply repeat the read now that poll says something is ready.
        } else if (poll_return == 0) {
          zret.note(S_ERROR, "Poll timed out waiting to read HTTP/3 content.");
          session.close();
          zret = -1;
          return zret;
        } else if (poll_return < 0) {
          // Connection was closed. Nothing to do.
          zret.note(S_DIAG, "The peer closed the HTTP/3 connection while reading during poll.");
          zret = 0;
          return zret;
        }
        continue;
      } else {
        zret.note(S_ERROR, "ngtcp2_process_ingress: unexpected recvfrom() errno: {}", Errno{});
        session.close();
        zret = -1;
        return zret;
      }
    }
  }

  ngtcp2_path path;
  ngtcp2_tstamp ts = timestamp();
  ngtcp2_pkt_info pi = {0};

  auto &qs = session.quic_socket;
  assert(local_addr.is_valid());
  ngtcp2_addr_init(&path.local, qs.local_addr, qs.local_addr.size());
  ngtcp2_addr_init(&path.remote, (struct sockaddr *)&remote_addr, remote_addrlen);

  // Process the packet.
  int rv = ngtcp2_conn_read_pkt(qs.qconn, &path, &pi, buf, num_bytes_received, ts);
  if (rv != 0) {
    if (rv == NGTCP2_ERR_CRYPTO) {
      zret.note(
          S_ERROR,
          "ngtcp2_process_ingress: ngtcp2_conn_read_pkt() had an error return "
          "(likely a certificate verification problem): {}",
          Ngtcp2Error{rv});
    } else {
      zret.note(
          S_ERROR,
          "ngtcp2_process_ingress: ngtcp2_conn_read_pkt() had an error return: {}",
          Ngtcp2Error{rv});
    }
    zret = -1;
    return zret;
  }
  zret.result() += num_bytes_received;
  return zret;
}

static swoc::Rv<int>
ngtcp2_flush_egress(H3Session &session)
{
  swoc::Rv<int> zret{0};
  auto &qs = session.quic_socket;

  assert(qs.local_addr.is_valid());

  ngtcp2_tstamp ts = timestamp();
  int rv = ngtcp2_conn_handle_expiry(qs.qconn, ts);
  if (rv != 0) {
    zret.note(S_ERROR, "ngtcp2_conn_handle_expiry returned error: {}", Ngtcp2Error{rv});
    zret = -1;
    return zret;
  }

  ngtcp2_path_storage ps;
  ngtcp2_path_storage_zero(&ps);

  for (;;) {
    ssize_t veccnt = 0;
    int64_t stream_id = -1;
    int fin = 0;
    nghttp3_vec vec[16];

    if (qs.h3conn && ngtcp2_conn_get_max_data_left(qs.qconn)) {
      veccnt = nghttp3_conn_writev_stream(
          qs.h3conn,
          &stream_id,
          &fin,
          vec,
          sizeof(vec) / sizeof(vec[0]));
      if (veccnt < 0) {
        zret.note(
            S_ERROR,
            "nghttp3_conn_writev_stream returned error: {}",
            Nghttp3Error{(int)veccnt});
        zret = -1;
        return zret;
      }
    }

    uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE | (fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0);
    uint8_t out[NGTCP2_MAX_UDP_PAYLOAD_SIZE];
    ssize_t ndatalen = 0;
    ssize_t outlen = ngtcp2_conn_writev_stream(
        qs.qconn,
        &ps.path,
        nullptr,
        out,
        sizeof(out),
        &ndatalen,
        flags,
        stream_id,
        (const ngtcp2_vec *)vec,
        veccnt,
        ts);
    if (outlen == 0) {
      // Nothing more to write.
      break;
    }
    if (outlen < 0) {
      switch (outlen) {
      case NGTCP2_ERR_STREAM_DATA_BLOCKED: {
        assert(ndatalen == -1);
        rv = nghttp3_conn_block_stream(qs.h3conn, stream_id);
        if (rv != 0) {
          zret.note(S_ERROR, "nghttp3_conn_block_stream returned error: {}", Nghttp3Error{rv});
          zret = -1;
          return zret;
        }
        continue;
      }
      case NGTCP2_ERR_STREAM_SHUT_WR: {
        assert(ndatalen == -1);
        rv = nghttp3_conn_shutdown_stream_write(qs.h3conn, stream_id);
        if (rv != 0) {
          zret.note(
              S_ERROR,
              "nghttp3_conn_shutdown_stream_write returned error: {}",
              Nghttp3Error{rv});
          zret = -1;
          return zret;
        }
        continue;
      }
      case NGTCP2_ERR_WRITE_MORE: {
        assert(ndatalen >= 0);
        rv = nghttp3_conn_add_write_offset(qs.h3conn, stream_id, ndatalen);
        if (rv != 0) {
          zret.note(S_ERROR, "nghttp3_conn_add_write_offset returned error: {}", Nghttp3Error{rv});
          zret = -1;
          return zret;
        }
        continue;
      }
      default: {
        assert(ndatalen == -1);
        zret.note(
            S_ERROR,
            "ngtcp2_conn_writev_stream returned error: {}",
            Ngtcp2Error{(int)outlen});
        zret = -1;
        return zret;
      }
      }
    } else if (ndatalen >= 0) {
      rv = nghttp3_conn_add_write_offset(qs.h3conn, stream_id, ndatalen);
      if (rv != 0) {
        zret.note(S_ERROR, "nghttp3_conn_add_write_offset returned error: {}", Nghttp3Error{rv});
        zret = -1;
        return zret;
      }
    }

    ssize_t sent = 0;
    while ((sent = send(session.get_fd(), (const char *)out, outlen, 0)) == -1) {
      if (errno == EINTR) {
        continue;
      } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
        auto &&[poll_return, poll_errata] = session.poll_for_data_on_socket(Poll_Timeout, POLLOUT);
        zret.note(std::move(poll_errata));
        if (poll_return > 0) {
          // The socket is available again for writing. Simply repeat the write.
          continue;
        } else if (!zret.is_ok()) {
          zret.note(S_ERROR, "Error polling on a socket to write: {}", swoc::bwf::Errno{});
          zret = -1;
          return zret;
        } else if (poll_return == 0) {
          zret.note(S_ERROR, "Timed out waiting to write to a socket.");
          zret = -1;
          return zret;
        } else if (poll_return < 0) {
          zret.note(S_DIAG, "write failed during poll: session is closed");
          zret = 0;
          return zret;
        }
      } else {
        zret.note(S_ERROR, "send() failed: {}", swoc::bwf::Errno{});
        zret = -1;
        return zret;
      }
    }
    zret.result() += sent;
  }

  return zret;
}

/** Listen on the Session's socket for incoming data and then respond with any
 * resulting packets.
 *
 * Listening on the socket will poll() until data comes in or a timeout is
 * experienced. Writing any packets will not delay if there is nothing to write.
 */
static Errata
nghttp3_receive_and_send_data(H3Session &session, milliseconds timeout)
{
  Errata errata;
  // This may poll until packets come in to read.
  auto &&[num_bytes_received, ingress_errata] = ngtcp2_process_ingress(session, timeout);
  errata.note(std::move(ingress_errata));
  if (!errata.is_ok() || num_bytes_received < 0) {
    return errata;
  }

  // Write packets that came in from ngtcp2_process_ingress, if there are any.
  auto &&[num_bytes_written, egress_errata] = ngtcp2_flush_egress(session);
  errata.note(std::move(egress_errata));
  if (!errata.is_ok() || num_bytes_written < 0) {
    return errata;
  }
  return errata;
}

// --------------------------------------------
// Begin nghttp3 callbacks.
// --------------------------------------------

/** Called to populate data frames of a request or response.
 *
 * @return The number of objects populated in vec.
 */
static ssize_t
cb_h3_readfunction(
    nghttp3_conn * /* conn */,
    int64_t stream_id,
    nghttp3_vec *vec,
    size_t /* veccnt */,
    uint32_t *pflags,
    void * /* conn_data */,
    void *stream_user_data)
{
  Errata errata;
  auto *stream_state = reinterpret_cast<H3StreamState *>(stream_user_data);

  if (stream_state->wait_for_continue) {
    errata.note(S_DIAG, R"(Not sending HTTP/3 body for "Expect: 100" request.)");
    *pflags = NGHTTP3_DATA_FLAG_EOF;
    return 0;
  }
  vec[0].base = (uint8_t *)stream_state->body_to_send.data();

  auto const body_size = stream_state->body_to_send.size();
  vec[0].len = body_size;
  stream_state->num_data_bytes_written += body_size;

  *pflags = NGHTTP3_DATA_FLAG_EOF;
  errata.note(
      S_DIAG,
      "Sent an HTTP/3 body of {} bytes for key {} of stream id {}:\n{}",
      body_size,
      stream_state->key,
      stream_id,
      TextView{stream_state->body_to_send.data(), body_size});

  return 1;
}

/* this amount of data has now been acked on this stream */
static int
cb_h3_acked_stream_data(
    nghttp3_conn *conn,
    int64_t stream_id,
    uint64_t datalen,
    void * /* conn_user_data */,
    void *stream_user_data)
{
  Errata errata;
  errata.note(S_DIAG, "HTTP/3 stream with id {} acked {} bytes", stream_id, datalen);
  auto *stream_state = reinterpret_cast<H3StreamState *>(stream_user_data);
  assert(stream_state->num_data_bytes_written >= datalen);
  stream_state->num_data_bytes_written -= datalen;
  if (stream_state->num_data_bytes_written == 0) {
    errata.note(
        S_DIAG,
        "Resuming HTTP/3 stream with id {} and key {}",
        stream_id,
        stream_state->key,
        datalen);
    auto const rv = nghttp3_conn_resume_stream(conn, stream_id);
    if (rv != 0) {
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
  }
  return 0;
}

static int
cb_h3_stream_close(
    nghttp3_conn * /* conn */,
    int64_t stream_id,
    uint64_t /* app_error_code */,
    void *conn_user_data,
    void *stream_user_data)
{
  Errata errata;
  errata.note(S_DIAG, "HTTP/3 stream is closed with id: {}", stream_id);

  auto *session = reinterpret_cast<H3Session *>(conn_user_data);
  auto iter = session->stream_map.find(stream_id);
  if (iter == session->stream_map.end()) {
    errata.note(
        S_ERROR,
        "HTTP/3 stream is closed with id {} but could not find it tracked internally",
        stream_id);
    return 0;
  }
  auto &stream_state = *reinterpret_cast<H3StreamState *>(stream_user_data);

  if (stream_state.will_receive_request()) {
    if (stream_state.specified_request->_content_rule) {
      if (!stream_state.specified_request->_content_rule
               ->test(stream_state.key, "body", swoc::TextView(stream_state.body_received)))
      {
        errata.note(S_DIAG, R"(Body content did not match expected value.)");
      }
    }
  } else {
    if (stream_state.specified_response->_content_rule) {
      if (!stream_state.specified_response->_content_rule
               ->test(stream_state.key, "body", swoc::TextView(stream_state.body_received)))
      {
        errata.note(S_DIAG, R"(Body content did not match expected value.)");
      }
    }
  }

  auto const &message_start = stream_state.stream_start;
  auto const message_end = ClockType::now();
  auto const elapsed_ms = duration_cast<milliseconds>(message_end - message_start);
  if (elapsed_ms > Transaction_Delay_Cutoff) {
    errata.note(
        S_ERROR,
        R"(HTTP/3 transaction in stream id {} with key {} took {}.)",
        stream_id,
        stream_state.key,
        elapsed_ms);
  }

  session->stream_map.erase(stream_id);

  /* make sure that ngh3_stream_recv is called again to complete the transfer
   * even if there are no more packets to be received from the server. */
  errata.note(nghttp3_receive_and_send_data(*session, Poll_Timeout));
  return 0;
}

static int
cb_h3_recv_data(
    nghttp3_conn * /* conn */,
    int64_t stream_id,
    const uint8_t *buf,
    size_t buflen,
    void * /* conn_user_data */,
    void *stream_user_data)
{
  Errata errata;
  auto *stream_state = reinterpret_cast<H3StreamState *>(stream_user_data);
  errata.note(
      S_DIAG,
      "Received an HTTP/3 body of {} bytes for transaction with key {}, "
      "stream id {}, with content:\n{}",
      buflen,
      stream_state->key,
      stream_id,
      TextView(reinterpret_cast<char const *>(buf), buflen));
  stream_state->body_received += std::string(reinterpret_cast<char const *>(buf), buflen);
  return 0;
}

static int
cb_h3_deferred_consume(
    nghttp3_conn * /* conn */,
    int64_t stream_id,
    size_t consumed,
    void *conn_user_data,
    void * /* stream_user_data */)
{
  auto *h3_session = reinterpret_cast<H3Session *>(conn_user_data);
  auto &qs = h3_session->quic_socket;

  ngtcp2_conn_extend_max_stream_offset(qs.qconn, stream_id, consumed);
  ngtcp2_conn_extend_max_offset(qs.qconn, consumed);
  return 0;
}

static int
cb_h3_recv_header(
    nghttp3_conn * /* conn */,
    int64_t /* stream_id */,
    int32_t /* token */,
    nghttp3_rcbuf *name,
    nghttp3_rcbuf *value,
    uint8_t /* flags */,
    void * /* conn_user_data */,
    void *stream_user_data)
{
  auto *stream_state = reinterpret_cast<H3StreamState *>(stream_user_data);
  stream_state->have_received_headers = true;

  TextView name_view = stream_state->register_rcbuf(name);
  TextView value_view = stream_state->register_rcbuf(value);

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
  } else { // stream_state receives a response.
    auto &response_headers = stream_state->response_from_server;
    if (name_view == ":status") {
      response_headers->_status = swoc::svtou(value_view);
      response_headers->_status_string = std::string(value_view);
    }
    response_headers->_fields_rules->add_field(name_view, value_view);
    // See if we are expecting a 100 response.
    if (stream_state->wait_for_continue) {
      if (name_view == ":status" && value_view == "100") {
        // We got our 100 Continue. No need to wait for it anymore.
        stream_state->wait_for_continue = false;
      }
    }
  }
  return 0;
}

static int
cb_h3_end_headers(
    nghttp3_conn * /* conn */,
    int64_t stream_id,
    int /* fin */,
    void *conn_user_data,
    void *stream_user_data)
{
  Errata errata;
  auto *session_data = reinterpret_cast<H3Session *>(conn_user_data);
  auto *stream_state = reinterpret_cast<H3StreamState *>(stream_user_data);
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
      size_t expected_size = swoc::svtou(spot->second);
      stream_state->body_received.reserve(expected_size);
    }
    errata.note(
        S_DIAG,
        "Received an HTTP/3 request for key {} with stream id {}:\n{}",
        stream_state->key,
        stream_id,
        request_from_client);
  } else { // stream_state receives a response
    auto &response_from_wire = *stream_state->response_from_server;
    response_from_wire.derive_key();
    if (stream_state->key.empty()) {
      // A response for which we didn't process the request, presumably. A
      // server push? Maybe? In theory we can support that but currently we
      // do not. Emit a warning for now.
      stream_state->key = response_from_wire.get_key();
      errata.note(
          S_ERROR,
          "Incoming HTTP/3 response has no key set from the request. Using key from "
          "response: {}.",
          stream_state->key);
    } else {
      // Make sure the key is set and give preference to the associated
      // request over the content of the response. There shouldn't be a
      // difference, but if there is, the user has the YAML file with the
      // request's key in front of them, and identifying that transaction
      // is more helpful than so some abberant response's key from the
      // wire. If they are looking into issues, debug logging will show
      // the fields of both the request and response.
      response_from_wire.set_key(stream_state->key);
    }
    if (auto spot{response_from_wire._fields_rules->_fields.find(HttpHeader::FIELD_CONTENT_LENGTH)};
        spot != response_from_wire._fields_rules->_fields.end())
    {
      size_t expected_size = swoc::svtou(spot->second);
      stream_state->body_received.reserve(expected_size);
    }
    errata.note(
        S_DIAG,
        "Received an HTTP/3 response for key {} with stream id {}:\n{}",
        stream_state->key,
        stream_id,
        response_from_wire);
    auto const &key = stream_state->key;
    auto const &specified_response = stream_state->specified_response;
    if (response_from_wire.verify_headers(key, *specified_response->_fields_rules)) {
      errata.note(S_ERROR, R"(HTTP/3 response headers did not match expected response headers.)");
      session_data->set_non_zero_exit_status();
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
          key);
    }
  }

  if (!stream_state->have_received_headers) {
    errata.note(S_ERROR, "Stream did not receive any headers for key: {}", stream_state->key);
  }
  return 0;
}

static int
cb_h3_end_stream(
    nghttp3_conn * /* conn */,
    int64_t stream_id,
    void *conn_user_data,
    void *stream_user_data)
{
  Errata errata;
  auto *session_data = reinterpret_cast<H3Session *>(conn_user_data);
  auto *stream_state = reinterpret_cast<H3StreamState *>(stream_user_data);
  std::string key;
  if (stream_state->will_receive_request()) {
    auto &request_from_client = *stream_state->request_from_client;
    request_from_client.derive_key();
    key = request_from_client.get_key();
  } else { // stream_state receives a response
    auto &response_from_wire = *stream_state->response_from_server;
    response_from_wire.derive_key();
    if (stream_state->key.empty()) {
      // A response for which we didn't process the request, presumably. A
      // server push? Maybe? In theory we can support that but currently we
      // do not. Emit a warning for now.
      stream_state->key = response_from_wire.get_key();
      errata.note(
          S_ERROR,
          "Incoming HTTP/3 response has no key set from the request. Using key from "
          "response: {}.",
          stream_state->key);
    } else {
      // Make sure the key is set and give preference to the associated
      // request over the content of the response. There shouldn't be a
      // difference, but if there is, the user has the YAML file with the
      // request's key in front of them, and identifying that transaction
      // is more helpful than so some abberant response's key from the
      // wire. If they are looking into issues, debug logging will show
      // the fields of both the request and response.
      response_from_wire.set_key(stream_state->key);
    }
    key = stream_state->key;
  }
  session_data->set_stream_has_ended(stream_id, key);
  return 0;
}

static int
cb_h3_send_stop_sending(
    nghttp3_conn * /* conn */,
    int64_t /* stream_id */,
    uint64_t /* app_error_code */,
    void * /* conn_user_data */,
    void * /* stream_user_data */)
{
  // The nghttp3 API is telling us to tell the QUIC stack to send a
  // STOP_SENDING frame here. That is currently not implemented.
  Errata errata;
  errata.note(
      S_ERROR,
      "Got a STOP_SENDING request from nghttp3. Proxy Verifier does not implement this.");
  return 0;
}

static nghttp3_callbacks nghttp3_client_callbacks = {
    cb_h3_acked_stream_data,
    cb_h3_stream_close,
    cb_h3_recv_data,
    cb_h3_deferred_consume,
    nullptr, /* begin_headers */
    cb_h3_recv_header,
    cb_h3_end_headers,
    nullptr, /* begin_trailers */
    cb_h3_recv_header,
    nullptr, /* end_trailers */
    cb_h3_send_stop_sending,
    cb_h3_end_stream,
    nullptr, /* reset_stream */
    nullptr, /* shutdown */
};
// --------------------------------------------
// End nghttp3 callbacks.
// --------------------------------------------

constexpr int SUCCEEDED = 0;
constexpr int FAILED = 1;

static int
initialize_nghttp3_connection(H3Session *session)
{
  Errata errata;
  auto &qs = session->quic_socket;
  int64_t ctrl_stream_id = 0;
  int64_t qpack_enc_stream_id = 0;
  int64_t qpack_dec_stream_id = 0;

  auto const max_streams = ngtcp2_conn_get_max_local_streams_uni(qs.qconn);
  if (max_streams < 3) {
    errata.note(S_ERROR, "Too few max streams: {}", max_streams);
    return 1;
  }

  nghttp3_settings_default(&qs.h3settings);

  int rc = nghttp3_conn_client_new(
      &qs.h3conn,
      &nghttp3_client_callbacks,
      &qs.h3settings,
      nghttp3_mem_default(),
      session);
  if (rc != 0) {
    errata.note(S_ERROR, "nghttp3_conn_client_new failed: {}", Ngtcp2Error{rc});
    return FAILED;
  }

  rc = ngtcp2_conn_open_uni_stream(qs.qconn, &ctrl_stream_id, nullptr);
  if (rc != 0) {
    errata.note(S_ERROR, "ngtcp2_conn_open_uni_stream failed: {}", Ngtcp2Error{rc});
    return FAILED;
  }

  rc = nghttp3_conn_bind_control_stream(qs.h3conn, ctrl_stream_id);
  if (rc != 0) {
    errata.note(S_ERROR, "nghttp3_conn_bind_control_stream failed: {}", Ngtcp2Error{rc});
    return FAILED;
  }

  rc = ngtcp2_conn_open_uni_stream(qs.qconn, &qpack_enc_stream_id, nullptr);
  if (rc != 0) {
    errata.note(S_ERROR, "ngtcp2_conn_open_uni_stream failed: {}", Ngtcp2Error{rc});
    return FAILED;
  }

  rc = ngtcp2_conn_open_uni_stream(qs.qconn, &qpack_dec_stream_id, nullptr);
  if (rc != 0) {
    errata.note(S_ERROR, "ngtcp2_conn_open_uni_stream failed: {}", Ngtcp2Error{rc});
    return FAILED;
  }

  rc = nghttp3_conn_bind_qpack_streams(qs.h3conn, qpack_enc_stream_id, qpack_dec_stream_id);
  if (rc != 0) {
    errata.note(S_ERROR, "nghttp3_conn_bind_qpack_streams failed: {}", Ngtcp2Error{rc});
    return FAILED;
  }

  return SUCCEEDED;
}

static void
configure_quic_socket_settings(QuicSocket &qs, uint64_t stream_buffer_size)
{
  ngtcp2_settings *s = &qs.settings;
  ngtcp2_transport_params *t = &qs.transport_params;
  ngtcp2_settings_default(s);
  ngtcp2_transport_params_default(t);
#ifdef DEBUG_NGTCP2
  s->log_printf = quic_printf;
#else
  s->log_printf = nullptr;
#endif
  s->initial_ts = timestamp();
  t->initial_max_stream_data_bidi_local = stream_buffer_size;
  t->initial_max_stream_data_bidi_remote = QUIC_MAX_STREAMS;
  t->initial_max_stream_data_uni = QUIC_MAX_STREAMS;
  t->initial_max_data = QUIC_MAX_DATA;
  t->initial_max_streams_bidi = 1;
  t->initial_max_streams_uni = 3;
  t->max_idle_timeout = duration_cast<milliseconds>(QUIC_IDLE_TIMEOUT).count();
  if (qs.qlogfd != -1) {
    s->qlog.write = QuicSocket::qlog_callback;
  }
}

QuicHandshake::QuicHandshake()
{
  // Reserve enough space that we feel comfortable will fit the entire QUIC
  // handshake. This buffer is potentially used across write_client_handshake
  // calls and therefore the memory has to persist for those, and std::vector
  // resizing will invalidate this.
  buf.reserve(QuicHandshake::max_handshake_size);
}

QuicSocket::QuicSocket()
{
  // Zero out all of our data so that if it gets uses uninitialized by mistake
  // at least it will fail early and consistently.
  memset(&dcid, 0, sizeof(dcid));
  memset(&scid, 0, sizeof(scid));
  memset(&settings, 0, sizeof(settings));
  memset(&transport_params, 0, sizeof(transport_params));
  memset(&h3settings, 0, sizeof(h3settings));
}

QuicSocket::~QuicSocket()
{
  if (qlogfd != -1) {
    ::close(qlogfd);
  }
  qlogfd = -1;
  if (ssl != nullptr) {
    SSL_free(ssl);
  }
  ssl = nullptr;
  ngtcp2_conn_del(qconn);
  nghttp3_conn_del(h3conn);
}

Errata
QuicSocket::open_qlog_file()
{
  Errata errata;
  qlogfd = -1;
  if (_qlog_dir.empty()) {
    return errata;
  }

  if (scid.datalen == 0) {
    errata.note(S_ERROR, "QUIC logging is configured, but scid was not set for this connection.");
    return errata;
  }
  swoc::file::path qlog_path{_qlog_dir};
  std::string qlog_filename;
  for (auto i = 0u; i < scid.datalen; ++i) {
    // Two hex digits to represent each byte followed by a NULL-terminator.
    char hex[3];
    snprintf(hex, sizeof(hex), "%02x", scid.data[i]);
    qlog_filename += std::string{hex, strlen(hex)};
  }
  qlog_filename += std::string{".qlog"};
  qlog_path /= qlog_filename;

  qlogfd = ::open(qlog_path.c_str(), O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

  if (qlogfd < 0) {
    errata.note(S_ERROR, "Failed to open QUIC log at {}: {}", qlog_path, Errno{});
    return errata;
  }
  errata.note(S_DIAG, "Writing QUIC log to: {}", qlog_path);
  return errata;
}

// static
void
QuicSocket::qlog_callback(void *user_data, uint32_t flags, const void *data, size_t datalen)
{
  Errata errata;
  H3Session *h3_session = reinterpret_cast<H3Session *>(user_data);
  QuicSocket &qs = h3_session->quic_socket;
  if (qs.qlogfd == -1) {
    // Likely a previous write has failed and the log was closed.
    return;
  }
  std::scoped_lock _{_qlog_mutex};
  ssize_t rc = ::write(qs.qlogfd, data, datalen);
  if (rc == -1) {
    errata.note(S_ERROR, "Failed to write to QUIC log file: {}", Errno{});
    ::close(qs.qlogfd);
    qs.qlogfd = -1;
  }

  if (flags & NGTCP2_QLOG_WRITE_FLAG_FIN) {
    ::close(qs.qlogfd);
    qs.qlogfd = -1;
  }
}

// static
void
QuicSocket::randomly_populate_array(uint8_t *array, size_t array_len)
{
  for (auto i = 0u; i < array_len; ++i) {
    array[i] = _uni_id(_rng);
  }
}

// static
Errata
QuicSocket::configure_qlog_dir(TextView qlog_dir)
{
  Errata errata;
  if (qlog_dir.empty()) {
    errata.note(S_DIAG, "qlog is not enabled.");
    return errata;
  }
  _qlog_dir = qlog_dir;
  std::error_code ec;
  auto stat{swoc::file::status(qlog_dir, ec)};
  if (ec.value() == ENOENT) {
    std::filesystem::create_directories(qlog_dir, ec);
    if (ec.value() != 0) {
      errata.note(S_ERROR, R"(Could not create qlog directory path "{}": {})", qlog_dir, ec);
      return errata;
    }
  } else if (ec.value() != 0) {
    errata.note(S_ERROR, R"(Invalid qlog directory path "{}": {}.)", qlog_dir, ec);
    return errata;
  }
  stat = swoc::file::status(qlog_dir, ec);
  if (!swoc::file::is_dir(stat)) {
    errata.note(S_ERROR, R"(Specified qlog path is not a directory: "{}")", qlog_dir);
    return errata;
  }
  errata.note(S_DIAG, "QUIC log files will be written to {}", qlog_dir);
  return errata;
}

// static
void
H3Session::set_non_zero_exit_status()
{
  *H3Session::process_exit_code = 1;
}

Errata
H3Session::configure_udp_socket(swoc::TextView interface, swoc::IPEndpoint const *target)
{
  Errata errata;
  int const socket_fd = ::socket(target->family(), SOCK_DGRAM, 0);
  if (0 > socket_fd) {
    errata.note(S_ERROR, R"(Failed to open a UDP socket - {})", Errno{});
    return errata;
  }
  static constexpr int ONE = 1;
  struct linger l;
  l.l_onoff = 0;
  l.l_linger = 0;
  setsockopt(socket_fd, SOL_SOCKET, SO_LINGER, (char *)&l, sizeof(l));
  if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &ONE, sizeof(int)) < 0) {
    errata.note(S_ERROR, R"(Could not set reuseaddr on socket {} - {}.)", socket_fd, Errno{});
    return errata;
  }
  errata.note(this->set_fd(socket_fd));
  if (!errata.is_ok()) {
    return errata;
  }

  if (!interface.empty()) {
    InterfaceNameToEndpoint interface_to_endpoint{interface, target->family()};
    auto &&[device_endpoint, device_errata] = interface_to_endpoint.find_ip_endpoint();
    errata.note(std::move(device_errata));
    if (!errata.is_ok()) {
      return errata;
    }
    if (::bind(socket_fd, device_endpoint, device_endpoint.size()) == -1) {
      errata.note(S_ERROR, "Failed to bind on interface {}: {}", interface, swoc::bwf::Errno{});
      return errata;
    }
  }

  if (-1 == ::connect(socket_fd, &target->sa, target->size())) {
    errata.note(S_ERROR, R"(Failed to connect socket {}: - {})", *target, Errno{});
    return errata;
  }
  if (0 != ::fcntl(socket_fd, F_SETFL, fcntl(socket_fd, F_GETFL, 0) | O_NONBLOCK)) {
    errata.note(
        S_ERROR,
        R"(Failed to make the client socket non-blocking {}: - {})",
        *target,
        Errno{});
    return errata;
  }
  this->_endpoint = target;
  return errata;
}

Errata
H3Session::do_connect(
    swoc::TextView interface,
    swoc::IPEndpoint const *target,
    ProxyProtocolUtil * /*pp_msg*/)
{
  Errata errata = configure_udp_socket(interface, target);
  if (!errata.is_ok()) {
    return errata;
  }

  // A generic UDP socket has been configured and connected. Now finish the
  // connection phase by configuring a QUIC and HTTP/3 connection over this
  // socket.
  errata.note(this->connect());
  return errata;
}

swoc::Rv<int>
H3Session::poll_for_headers(milliseconds timeout)
{
  assert(0);
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
  zret.note(nghttp3_receive_and_send_data(*this, Poll_Timeout));
  if (!zret.is_ok()) {
    zret.note(
        S_ERROR,
        "Calling nghttp3_receive_and_send_data in H3Session::poll_for_headers failed.");
    close();
    return zret;
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
H3Session::get_a_stream_has_ended() const
{
  return !_ended_streams.empty();
}

void
H3Session::record_stream_state(int64_t stream_id, std::shared_ptr<H3StreamState> stream_state)
{
  stream_map[stream_id] = stream_state;
  _last_added_stream = stream_state;
}

void
H3Session::set_stream_has_ended(int64_t stream_id, std::string_view key)
{
  _ended_streams.push_back(stream_id);
  if (!key.empty()) {
    _finished_streams.emplace(key);
  }
}

swoc::Rv<std::shared_ptr<HttpHeader>>
H3Session::read_and_parse_request(swoc::FixedBufferWriter & /* buffer */)
{
  swoc::Rv<std::shared_ptr<HttpHeader>> zret{nullptr};

  // This function should only be called after poll_for_headers() says there is
  // a finished stream.
  assert(!_ended_streams.empty());
  auto const stream_id = _ended_streams.front();
  _ended_streams.pop_front();
  auto stream_map_iter = stream_map.find(stream_id);
  if (stream_map_iter == stream_map.end()) {
    zret.note(
        S_ERROR,
        "Requested request headers for stream id {}, but none are available.",
        stream_id);
    return zret;
  }
  auto &stream_state = stream_map_iter->second;
  zret = stream_state->request_from_client;
  return zret;
}

swoc::Rv<size_t>
H3Session::drain_body(
    HttpHeader const & /* hdr */,
    size_t /* expected_content_size */,
    TextView /* initial */,
    std::shared_ptr<RuleCheck> /* rule_check */)
{
  // For HTTP/3, we process entire streams once they are ended. Therefore there
  // is never body to drain.
  return {0};
}

// Complete the TLS handshake (server-side).
Errata
H3Session::accept()
{
  swoc::Errata errata;
  //
  // TODO: This is all just stubbed out. Copied over from HTTP/2, so most of it
  // is wrong. Flesh this out when we implement server-side HTTP/3
  //

  // Check that the HTTP/3 protocol was negotiated.
  unsigned char const *alpn = nullptr;
  unsigned int alpnlen = 0;
#ifdef OPENSSL_NO_NEXTPROTONEG
  SSL_get0_next_proto_negotiated(this->_ssl, &alpn, &alpnlen);
#endif /* !OPENSSL_NO_NEXTPROTONEG */
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
  if (alpn == nullptr) {
    SSL_get0_alpn_selected(this->_ssl, &alpn, &alpnlen);
  }
#endif /* OPENSSL_VERSION_NUMBER >= 0x10002000L */

  if (alpn != nullptr && alpnlen == 2 && memcmp("h3", alpn, 2) == 0) {
    errata.note(
        S_DIAG,
        R"(Negotiated ALPN: {}, HTTP/3 is negotiated.)",
        TextView{(char *)alpn, alpnlen});
  } else {
    errata.note(
        S_ERROR,
        R"(Negotiated ALPN: {}, HTTP/3 failed to negotiate.)",
        (alpn == nullptr) ? "none" : TextView{(char *)alpn, alpnlen});
    return errata;
  }

  this->server_session_init();
  errata.note(S_DIAG, "Finished accept using H3Session");
  return errata;
}

// Complete the TLS handshake (client-side).
Errata
H3Session::connect()
{
  swoc::Errata errata;

  errata.note(this->client_session_init());
  if (!errata.is_ok()) {
    errata.note(S_ERROR, "TLS initialization failed.");
    return errata;
  }

  return errata;
}

Errata
H3Session::run_transactions(
    std::list<Txn> const &transactions,
    swoc::TextView interface,
    swoc::IPEndpoint const *target,
    double rate_multiplier)
{
  Errata errata;

  auto const first_time = ClockType::now();
  for (auto const &transaction : transactions) {
    Errata txn_errata;
    auto const key{transaction._req.get_key()};
    if (this->is_closed()) {
      txn_errata.note(this->do_connect(interface, target));
      if (!txn_errata.is_ok()) {
        txn_errata.note(S_ERROR, R"(Failed to reconnect HTTP/3 key: {}.)", key);
        // If we don't have a valid connection, there's no point in continuing.
        break;
      }
    }
    while (this->request_has_outstanding_stream_dependencies(transaction._req)) {
      txn_errata.note(nghttp3_receive_and_send_data(*this, Poll_Timeout));
      if (!txn_errata.is_ok()) {
        errata.note(S_ERROR, R"(Failed HTTP/3 transaction with key: {}.)", key);
        return errata;
      }
    }
    if (rate_multiplier != 0 || transaction._user_specified_delay_duration > 0us) {
      std::chrono::duration<double, std::micro> delay_time = 0ms;
      auto current_time = ClockType::now();
      auto next_time = current_time + delay_time;
      if (transaction._user_specified_delay_duration > 0us) {
        delay_time = transaction._user_specified_delay_duration;
        next_time = current_time + delay_time;
      } else {
        auto const start_offset = transaction._start;
        next_time = (rate_multiplier * start_offset) + first_time;
        delay_time = next_time - current_time;
      }
      while (delay_time > 0us) {
        // Make use of our delay time to read any incoming responses.
        txn_errata.note(
            nghttp3_receive_and_send_data(*this, duration_cast<milliseconds>(delay_time)));
        current_time = ClockType::now();
        delay_time = next_time - current_time;
        sleep_for(delay_time);
      }
    }
    txn_errata.note(this->run_transaction(transaction));
    if (!txn_errata.is_ok()) {
      errata.note(S_ERROR, R"(Failed HTTP/3 transaction with key: {}.)", key);
    }
  }
  errata.note(receive_responses());
  return errata;
}

bool
H3Session::request_has_outstanding_stream_dependencies(HttpHeader const &request) const
{
  for (auto const &stream_dependency : request._keys_to_await) {
    if (this->_finished_streams.find(stream_dependency) == this->_finished_streams.end()) {
      return true;
    }
  }
  return false;
}

Errata
H3Session::run_transaction(Txn const &transaction)
{
  Errata errata;
  auto &&[bytes_written, write_errata] = this->write(transaction._req);
  errata.note(std::move(write_errata));
  _last_added_stream->specified_response = &transaction._rsp;
  return errata;
}

TextView
H3StreamState::register_rcbuf(nghttp3_rcbuf *rcbuf)
{
  nghttp3_rcbuf_incref(rcbuf);
  _rcbufs_to_free.push_back(rcbuf);
  auto buf = nghttp3_rcbuf_get_buf(rcbuf);
  return TextView(reinterpret_cast<char *>(buf.base), buf.len);
}

H3StreamState::H3StreamState(bool is_client)
  : stream_start{ClockType::now()}
  , request_from_client{std::make_shared<HttpHeader>()}
  , response_from_server{std::make_shared<HttpHeader>()}
  , _will_receive_request{!is_client}
{
  request_from_client->set_is_request(HTTP_PROTOCOL_TYPE::HTTP_3);
  response_from_server->set_is_response(HTTP_PROTOCOL_TYPE::HTTP_3);
}

H3StreamState::~H3StreamState()
{
  for (auto rcbuf : _rcbufs_to_free) {
    nghttp3_rcbuf_decref(rcbuf);
  }
}

bool
H3StreamState::will_receive_request() const
{
  return _will_receive_request;
}

bool
H3StreamState::will_receive_response() const
{
  return !_will_receive_request;
}

void
H3StreamState::set_stream_id(int64_t stream_id)
{
  _stream_id = stream_id;
}

int64_t
H3StreamState::get_stream_id() const
{
  return _stream_id;
}

H3Session::H3Session() { }

H3Session::H3Session(TextView const &client_sni, int client_verify_mode)
  : _client_sni{client_sni}
  , _client_verify_mode{client_verify_mode}
{
}

H3Session::~H3Session()
{
  _last_added_stream.reset();
  char buffer[NGTCP2_MAX_UDP_PAYLOAD_SIZE] = {0};
  ngtcp2_tstamp ts = 0;
  ngtcp2_ssize rc = 0;
  ngtcp2_connection_close_error error_code;
  memset(&error_code, 0, sizeof(error_code));

  ngtcp2_connection_close_error_set_application_error(&error_code, NGHTTP3_H3_NO_ERROR, nullptr, 0);
  ts = timestamp();
  // Create the CONNECTION_CLOSE content in buffer.
  rc = ngtcp2_conn_write_connection_close(
      quic_socket.qconn,
      nullptr, /* path */
      nullptr, /* pkt_info */
      (uint8_t *)buffer,
      sizeof(buffer),
      &error_code,
      ts);
  if (rc > 0) {
    // Send the CONNECTION_CLOSE.
    while ((send(get_fd(), buffer, rc, 0) == -1) && errno == EINTR)
      ;
  }
}

swoc::Rv<ssize_t>
H3Session::read(swoc::MemSpan<char> /* span */)
{
  swoc::Rv<ssize_t> zret{0};
  zret.note(S_ERROR, "HTTP/3 read() called for the unsupported MemSpan overload.");
  return zret;
}

swoc::Rv<ssize_t>
H3Session::write(TextView /* data */)
{
  swoc::Rv<ssize_t> zret{0};
  zret.note(S_ERROR, "HTTP/3 write() called for the unsupported TextView overload.");
  return zret;
}

nghttp3_nv
H3Session::tv_to_nv(char const *name, TextView v)
{
  nghttp3_nv res;

  res.name = (unsigned char *)name;
  res.namelen = strlen(name);
  res.value = (unsigned char *)v.data();
  res.valuelen = v.length();
  res.flags = NGHTTP3_NV_FLAG_NONE;

  return res;
}

Errata
H3Session::pack_headers(HttpHeader const &hdr, nghttp3_nv *&nv_hdr, int &hdr_count)
{
  Errata errata;

  hdr_count = hdr._fields_rules->_fields.size();

  nv_hdr = reinterpret_cast<nghttp3_nv *>(malloc(sizeof(nghttp3_nv) * hdr_count));

  int offset = 0;
  if (hdr.is_response()) {
    nv_hdr[offset++] = tv_to_nv(":status", hdr._status_string);
  } else { // Is a request.
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

swoc::Rv<ssize_t>
H3Session::write(HttpHeader const &hdr)
{
  swoc::Rv<ssize_t> zret{0};

  auto const key = hdr.get_key();
  H3StreamState *stream_state = nullptr;
  std::shared_ptr<H3StreamState> new_stream_state{nullptr};
  int64_t stream_id = 0;
  if (hdr.is_response()) {
    stream_id = hdr._stream_id;
    auto stream_map_iter = stream_map.find(stream_id);
    if (stream_map_iter == stream_map.end()) {
      zret.note(S_ERROR, "Could not find registered stream for stream id: {}", stream_id);
      return zret;
    }
    stream_state = stream_map_iter->second.get();
  } else { // Is a request.
    // Only servers write responses while clients write requests.
    bool const is_client = hdr.is_request();
    new_stream_state = std::make_shared<H3StreamState>(is_client);
    stream_state = new_stream_state.get();

    auto const rc = ngtcp2_conn_open_bidi_stream(quic_socket.qconn, &stream_id, nullptr);
    if (rc != 0) {
      zret.note(
          S_ERROR,
          "Failed ngtcp2_conn_open_bidi_stream for key {}, error code: {}",
          key,
          Ngtcp2Error{rc});
      return zret;
    }
    stream_state->set_stream_id(stream_id);
    record_stream_state(stream_id, new_stream_state);
  }
  stream_state->key = key;

  int num_headers;
  nghttp3_nv *nva = nullptr;
  zret.note(pack_headers(hdr, nva, num_headers));
  if (!zret.is_ok()) {
    zret.note(S_ERROR, "Failed to pack headers for key: {}", key);
    return zret;
  }

  int submit_result = 0;
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
    nghttp3_data_reader data_reader;
    data_reader.read_data = cb_h3_readfunction;
    stream_state->body_to_send = TextView{content.data(), content.size()};
    stream_state->wait_for_continue = hdr._send_continue;
    if (hdr.is_response()) {
      submit_result = nghttp3_conn_submit_response(
          quic_socket.h3conn,
          stream_id,
          nva,
          num_headers,
          &data_reader);
    } else {
      submit_result = nghttp3_conn_submit_request(
          quic_socket.h3conn,
          stream_id,
          nva,
          num_headers,
          &data_reader,
          stream_state);
    }
  } else { // Empty body.
    if (hdr.is_response()) {
      submit_result =
          nghttp3_conn_submit_response(quic_socket.h3conn, stream_id, nva, num_headers, nullptr);
    } else {
      submit_result = nghttp3_conn_submit_request(
          quic_socket.h3conn,
          stream_id,
          nva,
          num_headers,
          nullptr,
          stream_state);
    }
  }
  if (submit_result == 0) {
    zret.note(
        S_DIAG,
        "Sent the following HTTP/3 {}{} headers for key {} with stream id {}:\n{}",
        swoc::bwf::If(hdr.is_request(), "request"),
        swoc::bwf::If(hdr.is_response(), "response"),
        hdr.get_key(),
        stream_id,
        hdr);
  } else {
    zret.note(
        S_ERROR,
        "Submitting an HTTP/3 {}{} for key {} with stream id {} failed: {}",
        swoc::bwf::If(hdr.is_request(), "request"),
        swoc::bwf::If(hdr.is_response(), "response"),
        hdr.get_key(),
        stream_id,
        submit_result);
  }
  if (zret.is_ok()) {
    // Make sure the logging of the headers are emitted before the body.
    zret.errata().sink();
  }

  if (ngtcp2_flush_egress(*this) < 0) {
    zret.note(S_ERROR, "Failure calling ngtcp2_flush_egress while writing headers.");
  }
  free(nva);
  return zret;
}

SSL_CTX *H3Session::_h3_client_context = nullptr;
SSL_CTX *H3Session::_h3_server_context = nullptr;

// static
Errata
H3Session::init(int *process_exit_code, TextView qlog_dir)
{
  Errata errata;
  H3Session::process_exit_code = process_exit_code;
  errata.note(QuicSocket::configure_qlog_dir(qlog_dir));
  errata.note(H3Session::client_ssl_ctx_init(_h3_client_context));
  errata.note(H3Session::server_ssl_ctx_init(_h3_server_context));
  errata.note(S_DIAG, "Finished H3Session::init");
  return errata;
}

// static
void
H3Session::terminate()
{
  H3Session::terminate(_h3_server_context);
  H3Session::terminate(_h3_server_context);
}

// static
void
H3Session::terminate(SSL_CTX *&context)
{
  SSL_CTX_free(context);
  context = nullptr;
}

// static
Errata
H3Session::client_ssl_ctx_init(SSL_CTX *&client_context)
{
  Errata errata;
  client_context = SSL_CTX_new(TLS_method());

  SSL_CTX_set_min_proto_version(client_context, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(client_context, TLS1_3_VERSION);

  SSL_CTX_set_default_verify_paths(client_context);

  if (SSL_CTX_set_ciphersuites(client_context, QUIC_CIPHERS) != 1) {
    errata.note(S_ERROR, "SSL_CTX_set_ciphersuites failed: {}", swoc::bwf::SSLError{});
    return errata;
  }

  if (SSL_CTX_set1_groups_list(client_context, QUIC_GROUPS) != 1) {
    errata.note(S_ERROR, "SSL_CTX_set1_groups_list failed: {}", swoc::bwf::SSLError{});
    return errata;
  }

  if (SSL_CTX_set_quic_method(client_context, &ssl_quic_method) == 0) {
    errata.note(S_ERROR, "SSL_CTX_set_quic_method failed: {}", swoc::bwf::SSLError{});
    return errata;
  }

  if (TLSSession::tls_secrets_are_being_logged()) {
    SSL_CTX_set_keylog_callback(client_context, TLSSession::keylog_callback);
  }

  return errata;
}

// static
Errata
H3Session::server_ssl_ctx_init(SSL_CTX *& /* server_context */)
{
  Errata errata;
#if 0
  // Add this in once we implement server-side HTTP/3.
  if (TLSSession::tls_secrets_are_being_logged()) {
    SSL_CTX_set_keylog_callback(client_context, TLSSession::keylog_callback);
  }
#endif

  return errata;
}

Errata
H3Session::client_ssl_session_init(SSL_CTX *client_context)
{
  Errata errata;
  const uint8_t *alpn = nullptr;
  size_t alpnlen = 0;

  assert(quic_socket.ssl == nullptr);
  quic_socket.ssl = SSL_new(client_context);

  if (SSL_set_app_data(quic_socket.ssl, this) == 0) {
    errata.note(S_ERROR, "SSL_set_app_data failed: {}", swoc::bwf::SSLError{});
  }
  SSL_set_connect_state(quic_socket.ssl);
  SSL_set_quic_use_legacy_codepoint(quic_socket.ssl, 0);

  alpn = reinterpret_cast<uint8_t const *>(H3_ALPN_H3_29_H3.data());
  alpnlen = H3_ALPN_H3_29_H3.size();
  if (alpn) {
    if (SSL_set_alpn_protos(quic_socket.ssl, alpn, (int)alpnlen) != 0) {
      errata.note(S_ERROR, "SSL_set_alpn_protos failed: {}", swoc::bwf::SSLError{});
    }
  }

  if (!_client_sni.empty()) {
    errata.note(S_DIAG, R"(Setting client-side H3 SNI to: "{}")", _client_sni);
    if (SSL_set_tlsext_host_name(quic_socket.ssl, _client_sni.c_str()) == 0) {
      errata
          .note(S_ERROR, "Failed to set client SNI to {}: {}", _client_sni, swoc::bwf::SSLError{});
    }
  }

  if (_client_verify_mode != SSL_VERIFY_NONE) {
    errata.note(
        S_DIAG,
        R"(Setting client H3 verification mode against the proxy to: {}.)",
        _client_verify_mode);
    SSL_set_verify(
        quic_socket.ssl,
        _client_verify_mode,
        nullptr /* No verify_callback is passed */);
  }

  return errata;
}

Errata
H3Session::receive_responses()
{
  Errata errata;
  while (!stream_map.empty()) {
    errata.note(nghttp3_receive_and_send_data(*this, Poll_Timeout));
    if (!errata.is_ok()) {
      errata.note(S_ERROR, "Encountered a problem while receiving responses.");
      break;
    }
  }
  return errata;
}

Errata
H3Session::client_session_init()
{
  Errata errata;
  quic_socket.version = NGTCP2_PROTO_VER_MAX;

  errata.note(client_ssl_session_init(_h3_client_context));
  if (!errata.is_ok()) {
    errata.note(S_ERROR, "Failure initializing client-side SSL object.");
    return errata;
  }

  quic_socket.dcid.datalen = NGTCP2_MAX_CIDLEN;
  QuicSocket::randomly_populate_array(quic_socket.dcid.data, quic_socket.dcid.datalen);

  quic_socket.scid.datalen = NGTCP2_MAX_CIDLEN;
  QuicSocket::randomly_populate_array(quic_socket.scid.data, quic_socket.scid.datalen);

  errata.note(quic_socket.open_qlog_file());

  configure_quic_socket_settings(quic_socket, MAX_DRAIN_BUFFER_SIZE);

  if (!quic_socket.local_addr.is_valid()) {
    struct sockaddr_storage socket_address;
    socklen_t socket_address_len = sizeof(socket_address);
    auto const rv =
        getsockname(this->get_fd(), (struct sockaddr *)&socket_address, &socket_address_len);
    if (rv == -1) {
      errata.note(S_ERROR, "getsockname failed: {}", Errno{});
      return errata;
    }
    quic_socket.local_addr.assign(reinterpret_cast<struct sockaddr *>(&socket_address));
  }

  ngtcp2_path path;
  memset(&path, 0, sizeof(path));
  ngtcp2_addr_init(&path.local, quic_socket.local_addr, quic_socket.local_addr.size());
  ngtcp2_addr_init(&path.remote, &this->_endpoint->sa, this->_endpoint->size());

  auto const rc = ngtcp2_conn_client_new(
      &quic_socket.qconn,
      &quic_socket.dcid,
      &quic_socket.scid,
      &path,
      NGTCP2_PROTO_VER_V1,
      &client_ngtcp2_callbacks,
      &quic_socket.settings,
      &quic_socket.transport_params,
      nullptr,
      this /* The user_data in the ngtcp2 callbacks. */);
  if (rc != 0) {
    errata.note(S_ERROR, "ngtcp2_conn_client_new failed.");
    return errata;
  }

  ngtcp2_conn_set_tls_native_handle(quic_socket.qconn, quic_socket.ssl);

  // Commence handshake.
  if (ngtcp2_flush_egress(*this) < 0) {
    errata.note(S_ERROR, "Error writing bytes during QUIC TLS handshake.");
    return errata;
  }

  // Now that we went our first packet, exchange packets until the handshake is
  // complete.
  bool handshake_completed = ngtcp2_conn_get_handshake_completed(quic_socket.qconn);
  while (!handshake_completed) {
    errata.note(nghttp3_receive_and_send_data(*this, Poll_Timeout));
    if (!errata.is_ok()) {
      errata.note(S_ERROR, "Encountered a problem while completing the handshake.");
      break;
    }
    handshake_completed = ngtcp2_conn_get_handshake_completed(quic_socket.qconn);
  }
  if (!handshake_completed) {
    errata.note(S_ERROR, "Could not complete the QUIC handshake.");
  }
  return errata;
}

Errata
H3Session::server_session_init()
{
  Errata errata;
  // TODO: stubbed out. Flesh this out when we implement server-side HTTP/3.
  return errata;
}
