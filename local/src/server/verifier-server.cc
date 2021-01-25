/** @file
 * Implement the Proxy Verifier server.
 *
 * Copyright 2021, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include <array>
#include <atomic>
#include <condition_variable>
#include <csignal>
#include <cstring>
#include <deque>
#include <libgen.h>
#include <mutex>
#include <thread>
#include <unordered_map>

#include <dirent.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/ArgParser.h"
#include "core/YamlParser.h"
#include "core/ProxyVerifier.h"
#include "swoc/BufferWriter.h"
#include "swoc/Errata.h"
#include "swoc/MemArena.h"
#include "swoc/TextView.h"
#include "swoc/bwf_base.h"
#include "swoc/bwf_ex.h"
#include "swoc/bwf_ip.h"
#include "swoc/bwf_std.h"
#include "swoc/swoc_file.h"
#include "swoc/swoc_ip.h"
#include "yaml-cpp/yaml.h"

using swoc::BufferWriter;
using swoc::Errata;
using swoc::TextView;

using std::this_thread::sleep_for;
namespace chrono = std::chrono;
using namespace std::literals;
constexpr auto const Thread_Sleep_Interval = 100ms;

void TF_Serve_Connection(std::thread *t);

/** Whether to verify each request against the corresponding proxy-request
 * in the yaml file.
 */
bool Use_Strict_Checking = false;

/// This must be a list so that iterators / pointers to elements do not go stale.
std::list<std::unique_ptr<std::thread>> Accept_Threads;

/** Set this to true when it's time for the threads to stop. */
bool Shutdown_Flag = false;

class ServerThreadInfo : public ThreadInfo
{
public:
  Session *_session = nullptr;
  bool
  data_ready() override
  {
    return Shutdown_Flag || this->_session;
  }
};

class ServerThreadPool : public ThreadPool
{
public:
  std::thread make_thread(std::thread *t) override;
};

ServerThreadPool Server_Thread_Pool;

HttpHeader
get_continue_response(int32_t stream_id = -1)
{
  HttpHeader response;
  response._is_response = true;
  response._status = 100;
  response._status_string = "100";
  response._http_version = "1.1";
  response._reason = "continue";
  if (stream_id >= 0) {
    response._is_http2 = true;
    // _http_version and _reason are not used in HTTP/2, so don't worry about
    // them because they won't be used.
    response._stream_id = stream_id;
  }
  return response;
}

HttpHeader
get_not_found_response(int32_t stream_id = -1)
{
  HttpHeader response;
  response._is_response = true;
  response._status = 404;
  response._status_string = "404";
  if (stream_id >= 0) {
    response._is_http2 = true;
    // _http_version and _reason are not used in HTTP/2, so don't worry about
    // them because they won't be used.
    response._stream_id = stream_id;
  } else {
    response._http_version = "1.1";
    response._reason = "Not Found";
  }
  static const std::string field_name = "Content-Length";
  static const std::string field_value = "0";
  response._fields_rules->add_field(field_name, field_value);
  return response;
}

std::thread
ServerThreadPool::make_thread(std::thread *t)
{
  return std::thread(
      TF_Serve_Connection,
      t); // move the temporary into the list element for permanence.
}

/** Command execution.
 *
 * This handles parsing and acting on the command line arguments.
 */
struct Engine
{
  ts::ArgParser parser;    ///< Command line argument parser.
  ts::Arguments arguments; ///< Results from argument parsing.

  void command_run();

  /// The process return code with which to exit.
  static int process_exit_code;
};

int Engine::process_exit_code = 0;

/** Handle SIGINT, exiting with an appropriate exit code.
 *
 * The Proxy Verifier server is long-lived and will likely be stopped by the
 * user via a SIGINT. Handle this signal and exit with a non-zero status if
 * some error has happened over the lifetime of the server.
 *
 * @param[in] signal The signal number of the signal being handled. This will
 * always be SIGINT since that is all that is registered with this handler.
 */
void
sigint_handler(int /* signal */)
{
  Errata errata;
  if (Engine::process_exit_code == 0) {
    errata.diag("Handling SIGINT: shutting down and "
                "exiting with a 0 response code because no errors have been seen.");
  } else {
    errata.diag(
        "Handling SIGINT: shutting down and "
        "exiting with response code {} because errors have been seen.",
        Engine::process_exit_code);
  }
  Shutdown_Flag = true;
}

std::mutex LoadMutex;

/** Parse the "tls" node for whether the proxy provided a certificate.
 *
 * This looks for the presence of "proxy-provided-certificate":true.
 *
 * @param[in] tls_node The "tls" node to parse.
 *
 * @return -1 if the proxy-provided-certificate element did not exist, 0 if it existed
 * and was false, 1 if it existed and was true.
 */
static swoc::Rv<int>
parse_proxy_provided_certificate(YAML::Node const &tls_node)
{
  swoc::Rv<int> proxy_provided_certificate{-1};
  if (auto proxy_provided_certificate_node{tls_node[YAML_SSN_TLS_PROXY_PROVIDED_CERTIFICATE_KEY]};
      proxy_provided_certificate_node)
  {
    if (proxy_provided_certificate_node.IsScalar()) {
      proxy_provided_certificate = proxy_provided_certificate_node.Scalar() == "true" ? 1 : 0;
    } else {
      proxy_provided_certificate.error(
          R"(Session has a value for key "{}" that is not a scalar as required.)",
          YAML_SSN_TLS_REQUEST_CERTIFICATE_KEY);
    }
  }
  return proxy_provided_certificate;
}

/** Parse the "tls" node for whether the server is directed to request a
 * certificate from the proxy.
 *
 * This looks for the presence of "request-certificate":true.
 *
 * @param[in] tls_node The "tls" node to parse.
 *
 * @return -1 if the request-certificate element did not exist, 0 if it existed
 * and was false, 1 if it existed and was true.
 */
static swoc::Rv<int>
parse_request_certificate(YAML::Node const &tls_node)
{
  swoc::Rv<int> should_request_certificate{-1};
  if (auto request_certificate_node{tls_node[YAML_SSN_TLS_REQUEST_CERTIFICATE_KEY]};
      request_certificate_node)
  {
    if (request_certificate_node.IsScalar()) {
      should_request_certificate = request_certificate_node.Scalar() == "true" ? 1 : 0;
    } else {
      should_request_certificate.error(
          R"(Session has a value for key "{}" that is not a scalar as required.)",
          YAML_SSN_TLS_REQUEST_CERTIFICATE_KEY);
    }
  }
  return should_request_certificate;
}

std::unordered_map<std::string, Txn, std::hash<std::string_view>> Transactions;

class ServerReplayFileHandler : public ReplayFileHandler
{
public:
  ServerReplayFileHandler();

  swoc::Errata ssn_open(YAML::Node const &node) override;
  swoc::Errata txn_open(YAML::Node const &node) override;
  swoc::Errata client_request(YAML::Node const &node) override;
  swoc::Errata proxy_request(YAML::Node const &node) override;
  swoc::Errata server_response(YAML::Node const &node) override;
  swoc::Errata apply_to_all_messages(HttpFields const &all_headers) override;
  swoc::Errata txn_close() override;
  swoc::Errata ssn_close() override;

  void txn_reset();
  void ssn_reset();

private:
  swoc::Errata handle_protocol_node(YAML::Node const &proxy_request_node);
  swoc::Errata handle_tls_node_directives(YAML::Node const &tls_node, std::string_view sni);

private:
  YAML::Node const *_ssn_node = nullptr;
  YAML::Node const *_txn_node = nullptr;
  /** The key for this transaction.
   *
   * This can be derived in a variety of ways:
   *   * From the client-request node.
   *   * From the proxy-request node.
   *   * From the all:{headers:{fields:}} node.
   *
   * This value tracks the derived key across these methods.
   */
  std::string _key;
  Txn _txn;
};

ServerReplayFileHandler::ServerReplayFileHandler() : _txn{Use_Strict_Checking} { }

void
ServerReplayFileHandler::txn_reset()
{
  _txn_node = nullptr;
  _key.clear();
  _txn.~Txn();
  new (&_txn) Txn{Use_Strict_Checking};
}

void
ServerReplayFileHandler::ssn_reset()
{
  _ssn_node = nullptr;
}

swoc::Errata
ServerReplayFileHandler::ssn_open(YAML::Node const &node)
{
  _ssn_node = &node;
  return {};
}

swoc::Errata
ServerReplayFileHandler::txn_open(YAML::Node const &node)
{
  LoadMutex.lock();
  _txn._req._is_request = true;
  _txn._rsp._is_response = true;
  Errata errata;
  if (!node[YAML_SERVER_RSP_KEY]) {
    errata.error(
        R"(Transaction node at "{}":{} does not have a server response [{}].)",
        _path,
        node.Mark().line,
        YAML_SERVER_RSP_KEY);
  }
  if (!errata.is_ok()) {
    return errata;
  }
  _txn_node = &node;
  return {};
}

swoc::Errata
ServerReplayFileHandler::handle_tls_node_directives(
    YAML::Node const &tls_node,
    std::string_view sni)
{
  swoc::Errata errata;
  auto should_request_certificate = parse_request_certificate(tls_node);
  if (!should_request_certificate.is_ok()) {
    errata.note(std::move(should_request_certificate.errata()));
    return errata;
  }

  auto proxy_provided_certificate = parse_proxy_provided_certificate(tls_node);
  if (!proxy_provided_certificate.is_ok()) {
    errata.note(std::move(proxy_provided_certificate.errata()));
    return errata;
  }

  auto const verify_mode_node_value = parse_verify_mode(tls_node);
  if (!verify_mode_node_value.is_ok()) {
    errata.note(std::move(verify_mode_node_value.errata()));
    return errata;
  }

  /* And all of these can exist concurrently but they must all agree. */
  if ((proxy_provided_certificate == 1 && should_request_certificate == 0) ||
      (proxy_provided_certificate == 0 && should_request_certificate == 1) ||

      (proxy_provided_certificate == 1 && verify_mode_node_value == 0) ||
      (proxy_provided_certificate == 0 && verify_mode_node_value > 0) ||

      (should_request_certificate == 1 && verify_mode_node_value == 0) ||
      (should_request_certificate == 0 && verify_mode_node_value > 0))
  {
    errata.error(
        R"(The "tls" node at "{}":{} has conflicting {}, {}, and {} values.)",
        _path,
        tls_node.Mark().line,
        YAML_SSN_TLS_PROXY_PROVIDED_CERTIFICATE_KEY,
        YAML_SSN_TLS_REQUEST_CERTIFICATE_KEY,
        YAML_SSN_TLS_VERIFY_MODE_KEY);
    return errata;
  }

  TLSHandshakeBehavior handshake_behavior;
  if (verify_mode_node_value > 0) {
    handshake_behavior.set_verify_mode(verify_mode_node_value);
    errata.diag(
        R"(Registered an SNI for client certification "{}":{}. SNI: {}, verify_mode: {}.)",
        _path,
        tls_node.Mark().line,
        sni,
        verify_mode_node_value.result());
  } else if (should_request_certificate == 1 || proxy_provided_certificate == 1) {
    handshake_behavior.set_verify_mode(SSL_VERIFY_PEER);
    errata.diag(
        R"(Registered an SNI for client certification "{}":{}. SNI: {}.)",
        _path,
        tls_node.Mark().line,
        sni);
  }

  auto const alpn_protocols = parse_alpn_protocols_node(tls_node);
  if (!alpn_protocols.result().empty()) {
    handshake_behavior.set_alpn_protocols_string(alpn_protocols.result());
    auto const printable_alpn = get_printable_alpn_string(alpn_protocols.result());
    errata.diag(R"(Using ALPN protocol string "{}" for SNI "{}")", printable_alpn, sni);
  }

  TLSSession::register_tls_handshake_behavior(sni, std::move(handshake_behavior));
  return errata;
}

swoc::Errata
ServerReplayFileHandler::client_request(YAML::Node const &node)
{
  HttpHeader client_request;
  Errata errata = YamlParser::populate_http_message(node, client_request);
  auto const key = client_request.get_key();
  if (key != HttpHeader::TRANSACTION_KEY_NOT_SET) {
    _key = key;
  }
  return errata;
}

swoc::Errata
ServerReplayFileHandler::handle_protocol_node(YAML::Node const &proxy_request_node)
{
  swoc::Errata errata;
  // A protocol sequence description on the server side is optional. If not
  // provided in the proxy-request, use the one in the session if it exists.
  YAML::Node protocol_sequence_node;
  if (proxy_request_node[YAML_SSN_PROTOCOL_KEY]) {
    protocol_sequence_node = proxy_request_node[YAML_SSN_PROTOCOL_KEY];
  } else if ((*_ssn_node)[YAML_SSN_PROTOCOL_KEY]) {
    protocol_sequence_node = (*_ssn_node)[YAML_SSN_PROTOCOL_KEY];
  } else {
    // There is no session-level nor transaction level protocol node to
    // process.
    return errata;
  }

  auto const http_node =
      parse_for_protocol_node(protocol_sequence_node, YAML_SSN_PROTOCOL_HTTP_NAME);
  if (!http_node.is_ok()) {
    errata.note(std::move(http_node.errata()));
    return errata;
  }
  if (http_node.result().IsDefined() &&
      http_node.result()[YAML_SSN_PROTOCOL_VERSION].Scalar() == "2") {
    _txn._req._is_http2 = true;
    _txn._rsp._is_http2 = true;
  }

  auto const tls_node = parse_for_protocol_node(protocol_sequence_node, YAML_SSN_PROTOCOL_TLS_NAME);
  if (!tls_node.is_ok()) {
    errata.note(std::move(tls_node.errata()));
    return errata;
  }
  if (!tls_node.result()) {
    return errata;
  }
  auto const &sni_rv = parse_sni(tls_node);
  if (!sni_rv.is_ok()) {
    errata.note(std::move(sni_rv.errata()));
    return errata;
  }
  auto const sni = sni_rv.result();
  if (sni.empty()) {
    return errata;
  }

  auto handle_errata = handle_tls_node_directives(tls_node, sni);
  if (!handle_errata.is_ok()) {
    errata.note(std::move(handle_errata));
    return errata;
  }
  return errata;
}

swoc::Errata
ServerReplayFileHandler::proxy_request(YAML::Node const &node)
{
  swoc::Errata errata;

  // Process the protocol stack because that adjusts expectations for how to
  // load the fields (such as whether this is HTTP/2).
  errata.note(handle_protocol_node(node));
  if (!errata.is_ok()) {
    return errata;
  }

  _txn._req._fields_rules = std::make_shared<HttpFields>(*global_config.txn_rules);
  errata.note(YamlParser::populate_http_message(node, _txn._req));
  if (!errata.is_ok()) {
    return errata;
  }
  auto const key = _txn._req.get_key();
  if (key != HttpHeader::TRANSACTION_KEY_NOT_SET) {
    _key = key;
  }
  return errata;
}

swoc::Errata
ServerReplayFileHandler::server_response(YAML::Node const &node)
{
  swoc::Errata errata;
  errata.note(YamlParser::populate_http_message(node, _txn._rsp));
  if (_txn._rsp._status == 0) {
    errata.error(R"(server-response without a status at "{}":{}.)", _path, node.Mark().line);
  }
  return errata;
}

swoc::Errata
ServerReplayFileHandler::apply_to_all_messages(HttpFields const &all_headers)
{
  _txn._req.merge(all_headers);
  _txn._rsp.merge(all_headers);
  auto const key = _txn._req.get_key();
  if (key != HttpHeader::TRANSACTION_KEY_NOT_SET) {
    _key = key;
  }
  return {};
}

swoc::Errata
ServerReplayFileHandler::txn_close()
{
  swoc::Errata errata;
  if (_key.empty()) {
    errata.error(
        R"(Could not find a key of format "{}" for transaction at "{}":{}.)",
        HttpHeader::_key_format,
        _path,
        _txn_node->Mark().line);
  } else {
    // For convenience, we do not require the user to set the key in
    // server-response nodes. Proxy Verifier functions fine in every way for
    // this, except for some debug logging which will show TRANSACTION_KEY_NOT_SET
    // in some places. For this reason make sure the response is aware of the
    // key.
    _txn._rsp.set_key(_key);
    Transactions.emplace(_key, std::move(_txn));
  }
  this->txn_reset();
  LoadMutex.unlock();
  return errata;
}

swoc::Errata
ServerReplayFileHandler::ssn_close()
{
  this->ssn_reset();
  return {};
}

void
delete_thread_info_session(ServerThreadInfo &thread_info)
{
  if (thread_info._session == nullptr) {
    return;
  }
  std::unique_lock<std::mutex> lock(thread_info._mutex);
  delete thread_info._session;
  thread_info._session = nullptr;
}

void
TF_Serve_Connection(std::thread *t)
{
  ServerThreadInfo thread_info;
  thread_info._thread = t;
  while (!Shutdown_Flag) {
    swoc::Errata errata;

    Server_Thread_Pool.wait_for_work(&thread_info);
    if (Shutdown_Flag) {
      // Calling Shutdown is a condition that releases wait_for_work.
      delete_thread_info_session(thread_info);
      break;
    }

    errata = thread_info._session->accept();
    while (!Shutdown_Flag && !thread_info._session->is_closed() && errata.is_ok()) {
      swoc::Errata thread_errata;

      // Poll so we can timeout and check for shutdown.
      auto &&[poll_return, poll_errata] =
          thread_info._session->poll_for_headers(Thread_Sleep_Interval);
      thread_errata.note(poll_errata);
      if (poll_return == 0) {
        // Poll timed out. Loop back around.
        continue;
      } else if (!poll_errata.is_ok()) {
        thread_errata.error("Poll failed: {}", swoc::bwf::Errno{});
        break;
      } else if (poll_return == -1) {
        // Socket closed.
        thread_info._session->close();
        break;
      }

      swoc::LocalBufferWriter<MAX_HDR_SIZE> w;
      auto &&[req_hdr, read_header_errata] = thread_info._session->read_and_parse_request(w);
      thread_errata.note(std::move(read_header_errata));
      if (!thread_errata.is_ok()) {
        thread_errata.error("Could not read the header.");
        Engine::process_exit_code = 1;
        break;
      }
      if (!req_hdr) {
        // There were no headers to retrieve. This would happen if the client
        // closed the connection and is not an error.
        break;
      }
      auto const stream_id = req_hdr->_stream_id;
      auto const is_http2 = (stream_id >= 0);
      auto key{req_hdr->get_key()};
      auto specified_transaction_it{Transactions.find(key)};

      if (specified_transaction_it == Transactions.end()) {
        thread_errata.error(R"(Proxy request with key "{}" not found, sending a 404.)", key);
        Engine::process_exit_code = 1;
        HttpHeader not_found_response = get_not_found_response(stream_id);
        not_found_response.update_content_length(req_hdr->_method);
        thread_info._session->write(not_found_response);
        // This will end the loop and eventually drop the connection.
        break;
      }

      [[maybe_unused]] auto &[unused_key, specified_transaction] = *specified_transaction_it;

      thread_errata.note(req_hdr->update_content_length(req_hdr->_method));
      thread_errata.note(req_hdr->update_transfer_encoding());

      // If there is an Expect header with the value of 100-continue, send the
      // 100-continue response before Reading request body.
      if (req_hdr->_send_continue) {
        HttpHeader continue_response = get_continue_response(stream_id);
        thread_info._session->write(continue_response);
      }

      // HTTP/2 transactions are processed on a stream basis, and the body is never needed
      // to be independantly drained.
      if (!is_http2 &&
          (req_hdr->_content_size || req_hdr->_content_length_p || req_hdr->_chunked_p)) {
        if (req_hdr->_chunked_p) {
          req_hdr->_content_size = specified_transaction._req._content_size;
        }
        auto &&[bytes_drained, drain_errata] =
            thread_info._session->drain_body(*req_hdr, req_hdr->_content_size, w.view());
        thread_errata.note(std::move(drain_errata));

        if (!thread_errata.is_ok()) {
          thread_errata.error("Failed to drain the request body for key: {}.", key);
          break;
        }
      }
      if (req_hdr->verify_headers(key, *specified_transaction._req._fields_rules)) {
        thread_errata.error(R"(Request headers did not match expected request headers.)");
        Engine::process_exit_code = 1;
      } else {
        thread_errata.diag(R"(Request with key {} passed validation.)", key);
      }
      // Responses to HEAD requests may have a non-zero Content-Length
      // but will never have a body. update_content_length adjusts
      // expectations so the body is not written for responses to such
      // requests.
      specified_transaction._rsp.update_content_length(req_hdr->_method);
      if (is_http2) {
        specified_transaction._rsp._is_http2 = true;
        specified_transaction._rsp._stream_id = stream_id;
      }
      auto &&[bytes_written, write_errata] =
          thread_info._session->write(specified_transaction._rsp);
      thread_errata.note(std::move(write_errata));
      thread_errata.diag(
          "Wrote {} bytes in an {}{} response to request with key {} "
          "with response status {}:\n{}",
          bytes_written,
          swoc::bwf::If(is_http2, "HTTP/2"),
          swoc::bwf::If(!is_http2, "HTTP/1"),
          key,
          specified_transaction._rsp._status,
          specified_transaction._rsp);
    }

    // cleanup and get ready for another session.
    delete_thread_info_session(thread_info);
  }
}

void
TF_Accept(int socket_fd, bool do_tls)
{
  std::unique_ptr<Session> session;
  struct pollfd pfd = {.fd = socket_fd, .events = POLLIN, .revents = 0};

  while (!Shutdown_Flag) {
    swoc::Errata errata;
    // Poll so that we can set a timeout and check whether the user requested a shutdown.
    auto const poll_return = ::poll(&pfd, 1, Thread_Sleep_Interval.count());
    if (poll_return == 0) {
      // poll timed out.
      continue;
    } else if (poll_return < 0) {
      errata.error("poll failed: {}", swoc::bwf::Errno{});
      continue;
    }
    swoc::IPEndpoint remote_addr;
    socklen_t remote_addr_size = sizeof(remote_addr);

    int fd = accept(socket_fd, &remote_addr.sa, &remote_addr_size);
    if (fd < 0) {
      errata.error("Failed to create a socket via accept: {}", swoc::bwf::Errno{});
      continue;
    }
    static const int ONE = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &ONE, sizeof(ONE));
    if (0 != ::fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK)) {
      errata.error("Failed to make the server socket non-blocking: {}", swoc::bwf::Errno{});
    }
    if (do_tls) {
      // H2Session will figure out the HTTP protocol during the TLS handshake
      // and handle HTTP/1.x or HTTP/2 accordingly.
      session = std::make_unique<H2Session>();
    } else {
      session = std::make_unique<Session>();
    }
    errata = session->set_fd(fd);
    if (!errata.is_ok()) {
      continue;
    }
    ServerThreadInfo *thread_info =
        dynamic_cast<ServerThreadInfo *>(Server_Thread_Pool.get_worker());
    if (nullptr == thread_info) {
      errata.error("Failed to get worker thread");
    } else {
      std::unique_lock<std::mutex> lock(thread_info->_mutex);
      thread_info->_session = session.release();
      thread_info->_cvar.notify_one();
    }
  }
}

swoc::Errata
do_listen(swoc::IPEndpoint &server_addr, bool do_tls)
{
  swoc::Errata errata;
  int socket_fd = socket(server_addr.family(), SOCK_STREAM, 0);
  if (socket_fd >= 0) {
    // Be agressive in reusing the port
    static constexpr int ONE = 1;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &ONE, sizeof(int)) < 0) {
      errata.error(R"(Could not set reuseaddr on socket {}: {}.)", socket_fd, swoc::bwf::Errno{});
    } else {
      if (0 == ::fcntl(socket_fd, F_SETFL, fcntl(socket_fd, F_GETFL, 0) | O_NONBLOCK)) {
        int bind_result = bind(socket_fd, &server_addr.sa, server_addr.size());
        if (bind_result == 0) {
          int listen_result = listen(socket_fd, 16384);
          if (listen_result == 0) {
            errata.info(R"(Listening at {})", server_addr);
            auto runner = std::make_unique<std::thread>(TF_Accept, socket_fd, do_tls);
            Accept_Threads.push_back(std::move(runner));
          } else {
            errata.error(R"(Could not isten to {}: {}.)", server_addr, swoc::bwf::Errno{});
          }
        } else {
          errata.error(R"(Could not bind to {}: {}.)", server_addr, swoc::bwf::Errno{});
        }
      } else {
        errata.error(
            R"(Could not make socket non-blocking {}: {}.)",
            server_addr,
            swoc::bwf::Errno{});
      }
    }
  } else {
    errata.error(R"(Could not create socket: {}.)", swoc::bwf::Errno{});
  }
  if (!errata.is_ok() && socket_fd >= 0) {
    close(socket_fd);
  }
  return errata;
}

void
Engine::command_run()
{
  { // Scope errata before the long-lived server loop.
    Errata errata;
    auto args{arguments.get("run")};
    std::deque<swoc::IPEndpoint> server_addrs, server_addrs_https;
    auto server_addr_arg{arguments.get("listen")};
    auto server_addr_https_arg{arguments.get("listen-https")};

    swoc::LocalBufferWriter<1024> w;

    if (args.size() < 1) {
      errata.error(R"("run" command requires a directory path as an argument.)");
      process_exit_code = 1;
      return;
    }

    auto thread_limit_arg{arguments.get("thread-limit")};
    if (thread_limit_arg.size() == 1) {
      auto const thread_limit_int = atoi(thread_limit_arg[0].c_str());
      Server_Thread_Pool.set_max_threads(thread_limit_int);
    }

    if (arguments.get("strict")) {
      Use_Strict_Checking = true;
    }

    auto key_format_arg{arguments.get("format")};
    if (key_format_arg) {
      HttpHeader::_key_format = key_format_arg[0];
    }

    if (server_addr_arg) {
      if (server_addr_arg.size() == 1) {
        errata = parse_ips(server_addr_arg[0], server_addrs);
      } else {
        errata.error(R"(--listen option must have a single value, the listen address and port.)");
        process_exit_code = 1;
        return;
      }
    }

    if (server_addr_https_arg) {
      if (server_addr_https_arg.size() == 1) {
        errata = parse_ips(server_addr_https_arg[0], server_addrs_https);
        if (!errata.is_ok()) {
          process_exit_code = 1;
          return;
        }
        std::error_code ec;

        auto cert_arg{arguments.get("server-cert")};
        if (cert_arg.size() >= 1) {
          errata.note(TLSSession::configure_server_cert(cert_arg[0]));
          if (!errata.is_ok()) {
            errata.error(R"(Invalid server-cert path "{}")", cert_arg[0]);
            process_exit_code = 1;
            return;
          }
        }
        auto ca_certs_arg{arguments.get("ca-certs")};
        if (ca_certs_arg.size() >= 1) {
          errata.note(TLSSession::configure_ca_cert(ca_certs_arg[0]));
          if (!errata.is_ok()) {
            errata.error(R"(Invalid ca-certs path "{}")", ca_certs_arg[0]);
            process_exit_code = 1;
            return;
          }
        }
        if (errata.is_ok()) {
          errata.note(TLSSession::init());
          errata.note(H2Session::init(&process_exit_code));
        }
      } else {
        errata.error(
            R"(--listen-https option must have a single value, the listen address and port.)");
        process_exit_code = 1;
        return;
      }
    }

    errata.note(YamlParser::load_replay_files(
        swoc::file::path{args[0]},
        [](swoc::file::path const &file) -> swoc::Errata {
          ServerReplayFileHandler handler;
          return YamlParser::load_replay_file(file, handler);
        },
        10));

    if (!errata.is_ok()) {
      process_exit_code = 1;
      return;
    }
    Session::init(Transactions.size());

    size_t max_content_length = 0;
    for (auto const &[key, txn] : Transactions) {
      if (txn._rsp._content_data == nullptr) { // don't check responses with literal content.
        max_content_length = std::max<size_t>(max_content_length, txn._rsp._content_size);
      }
    }
    HttpHeader::set_max_content_length(max_content_length);
    for (auto &[key, txn] : Transactions) {
      if (txn._rsp._content_data == nullptr) { // fill in from static content.
        txn._rsp._content_data = txn._rsp._content.data();
      }
    }

    errata.info("Ready with {} transactions.", Transactions.size());

    for (auto &server_addr : server_addrs) {
      // Set up listen port.
      if (server_addr.is_valid()) {
        errata.note(do_listen(server_addr, false));
      }
      if (!errata.is_ok()) {
        process_exit_code = 1;
        return;
      }
    }
    for (auto &server_addr_https : server_addrs_https) {
      if (server_addr_https.is_valid()) {
        errata.note(do_listen(server_addr_https, true));
      }
    }
  } // End of scope for errata so it gets logged.

  // Wait for the listening threads to start up.
  while (!Shutdown_Flag) {
    sleep_for(Thread_Sleep_Interval);
  }
  for_each(
      Accept_Threads.begin(),
      Accept_Threads.end(),
      [](std::unique_ptr<std::thread> const &thread) { thread->join(); });
  Accept_Threads.clear();
  Server_Thread_Pool.join_threads();

  TLSSession::terminate();
  H2Session::terminate();
  exit(Engine::process_exit_code);
}

int
main(int /* argc */, char const *argv[])
{
  swoc::Errata errata;
  if (block_sigpipe()) {
    errata.warn("Could not block SIGPIPE. Continuing anyway, but be aware that "
                "SSL_read "
                "and SSL_write issues may trigger SIGPIPE which will abruptly "
                "terminate execution.");
  }

  struct sigaction sigIntHandler;
  sigIntHandler.sa_handler = sigint_handler;
  sigemptyset(&sigIntHandler.sa_mask);
  sigIntHandler.sa_flags = 0;
  sigaction(SIGINT, &sigIntHandler, nullptr);

  Engine engine;

  engine.parser
      .add_option(
          "--verbose",
          "",
          "Enable verbose output:"
          "\n\terror: Only print errors."
          "\n\twarn: Print warnings and errors."
          "\n\tinfo: Print info messages in addition to warnings and "
          "errors. This is the default verbosity level."
          "\n\tdiag: Print debug messages in addition to info, "
          "warnings, and errors,",
          "",
          1,
          "info")
      .add_option("--version", "-V", "Print version string")
      .add_option("--help", "-h", "Print usage information");

  static std::string const thread_limit_description =
      std::string("Specify the maximum number of threads to use for handling "
                  "concurrent connections. Default: ") +
      std::to_string(ThreadPool::default_max_threads);
  engine.parser
      .add_command(
          "run",
          "run <dir>: the replay server using data in <dir>",
          "",
          1,
          [&]() -> void { engine.command_run(); })
      .add_option("--thread-limit", "", thread_limit_description.c_str(), "", 1, "")
      .add_option(
          "--listen",
          "",
          "Listen address and port. Can be a comma separated list.",
          "",
          1,
          "")
      .add_option(
          "--listen-https",
          "",
          "Listen TLS address and port. Can be a comma separated list.",
          "",
          1,
          "")
      .add_option("--format", "-f", "Transaction key format", "", 1, "")
      .add_option(
          "--server-cert",
          "",
          "Specify a TLS server certificate file containing both the public and "
          "private keys. Alternatively a directory containing server.pem and "
          "server.key files can be provided.",
          "",
          1,
          "")
      .add_option(
          "--ca-certs",
          "",
          "Specify TLS CA certificate file containing one or more certificates. "
          "Alternatively, a directory containing separate certificate files can "
          "be provided.",
          "",
          1,
          "")
      .add_option(
          "--strict",
          "-s",
          "Verify all proxy requests against the proxy-request fields as if "
          "they had equality verification rules in them if no other "
          "verification "
          "rule is provided.");

  // parse the arguments
  engine.arguments = engine.parser.parse(argv);
  std::string verbosity = "info";
  if (auto const verbose_argument{engine.arguments.get("verbose")}; verbose_argument) {
    verbosity = verbose_argument.value();
  }
  if (!configure_logging(verbosity)) {
    std::cerr << "Unrecognized verbosity option: " << verbosity << std::endl;
    return 1;
  }

  engine.arguments.invoke();
  return engine.process_exit_code;
}
