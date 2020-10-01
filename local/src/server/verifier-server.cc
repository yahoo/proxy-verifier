/** @file
 * Implement the Proxy Verifier server.
 *
 * Copyright 2020, Verizon Media
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

namespace chrono = std::chrono;
using namespace std::literals;
constexpr auto const Thread_Sleep_Interval_MS = 100ms;

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

HttpHeader Continue_resp;

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

  /// Status code to return to the operating system.
  static int status_code;
};

int Engine::status_code = 0;

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
  if (Engine::status_code == 0) {
    errata.diag("Handling SIGINT: shutting down and "
                "exiting with a 0 response code because no errors have been seen.");
  } else {
    errata.diag(
        "Handling SIGINT: shutting down and "
        "exiting with response code {} because errors have been seen.",
        Engine::status_code);
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
      proxy_provided_certificate.errata().error(
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
      should_request_certificate.errata().error(
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
  swoc::Errata proxy_request(YAML::Node const &node) override;
  swoc::Errata server_response(YAML::Node const &node) override;
  swoc::Errata apply_to_all_messages(HttpFields const &all_headers) override;
  swoc::Errata txn_close() override;

  void reset();

private:
  swoc::Rv<int> handle_verify_mode(YAML::Node const &tls_node, std::string_view sni);

private:
  std::string _key;
  Txn _txn;
};

ServerReplayFileHandler::ServerReplayFileHandler() : _txn{Use_Strict_Checking} { }

void
ServerReplayFileHandler::reset()
{
  _txn.~Txn();
  new (&_txn) Txn{Use_Strict_Checking};
}

swoc::Errata
ServerReplayFileHandler::ssn_open(YAML::Node const & /* node */)
{
  return {};
}

swoc::Errata
ServerReplayFileHandler::txn_open(YAML::Node const &node)
{
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
  LoadMutex.lock();
  return {};
}

swoc::Rv<int>
ServerReplayFileHandler::handle_verify_mode(YAML::Node const &tls_node, std::string_view sni)
{
  swoc::Rv<int> verify_mode{-1};
  auto should_request_certificate = parse_request_certificate(tls_node);
  if (!should_request_certificate.is_ok()) {
    verify_mode.errata().note(std::move(should_request_certificate.errata()));
    return verify_mode;
  }

  auto proxy_provided_certificate = parse_proxy_provided_certificate(tls_node);
  if (!proxy_provided_certificate.is_ok()) {
    verify_mode.errata().note(std::move(proxy_provided_certificate.errata()));
    return verify_mode;
  }

  auto const verify_mode_node_value = parse_verify_mode(tls_node);
  if (!verify_mode_node_value.is_ok()) {
    verify_mode.errata().note(std::move(verify_mode_node_value.errata()));
    return verify_mode;
  }

  /* And all of these can exist concurrently but they must all agree. */
  if ((proxy_provided_certificate == 1 && should_request_certificate == 0) ||
      (proxy_provided_certificate == 0 && should_request_certificate == 1) ||

      (proxy_provided_certificate == 1 && verify_mode_node_value == 0) ||
      (proxy_provided_certificate == 0 && verify_mode_node_value > 0) ||

      (should_request_certificate == 1 && verify_mode_node_value == 0) ||
      (should_request_certificate == 0 && verify_mode_node_value > 0))
  {
    verify_mode.errata().error(
        R"(The "tls" node at "{}":{} has conflicting {}, {}, and {} values.)",
        _path,
        tls_node.Mark().line,
        YAML_SSN_TLS_PROXY_PROVIDED_CERTIFICATE_KEY,
        YAML_SSN_TLS_REQUEST_CERTIFICATE_KEY,
        YAML_SSN_TLS_VERIFY_MODE_KEY);
    return verify_mode;
  }

  if (verify_mode_node_value > 0) {
    TLSSession::register_sni_for_client_verification(sni, verify_mode_node_value);
    verify_mode.errata().diag(
        R"(Registered an SNI for client certification "{}":{}. SNI: {}, verify_mode: {}.)",
        _path,
        tls_node.Mark().line,
        sni,
        verify_mode_node_value.result());
  } else if (should_request_certificate == 1 || proxy_provided_certificate == 1) {
    TLSSession::register_sni_for_client_verification(sni, SSL_VERIFY_PEER);
    verify_mode.errata().diag(
        R"(Registered an SNI for client certification "{}":{}. SNI: {}.)",
        _path,
        tls_node.Mark().line,
        sni);
  }
  return verify_mode;
}

swoc::Errata
ServerReplayFileHandler::proxy_request(YAML::Node const &node)
{
  _txn._req._fields_rules = std::make_shared<HttpFields>(*global_config.txn_rules);
  swoc::Errata errata = _txn._req.load(node);
  if (!errata.is_ok()) {
    return errata;
  }
  if (!node[YAML_SSN_PROTOCOL_KEY]) {
    return errata;
  }
  auto const protocol_sequence_node{node[YAML_SSN_PROTOCOL_KEY]};
  if (!protocol_sequence_node) {
    // A protocol sequence description on the server side is optional.
    return errata;
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

  auto const verify_mode = handle_verify_mode(tls_node, sni);
  if (!verify_mode.is_ok()) {
    errata.note(std::move(verify_mode.errata()));
    return errata;
  }
  return errata;
}

swoc::Errata
ServerReplayFileHandler::server_response(YAML::Node const &node)
{
  return _txn._rsp.load(node);
}

swoc::Errata
ServerReplayFileHandler::apply_to_all_messages(HttpFields const &all_headers)
{
  _txn._req._fields_rules->merge(all_headers);
  _txn._rsp._fields_rules->merge(all_headers);
  return {};
}

swoc::Errata
ServerReplayFileHandler::txn_close()
{
  _key = _txn._req.make_key();
  Transactions.emplace(_key, std::move(_txn));
  LoadMutex.unlock();
  this->reset();
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
      HttpHeader req_hdr;
      swoc::Errata thread_errata;
      swoc::LocalBufferWriter<MAX_HDR_SIZE> w;
      auto &&[poll_return, poll_errata] = thread_info._session->poll(Thread_Sleep_Interval_MS);
      thread_errata.note(poll_errata);
      if (poll_return == 0) {
        // Poll timed out. Loop back around.
        continue;
      } else if (!poll_errata.is_ok()) {
        thread_errata.error("Poll failed: {}", swoc::bwf::Errno{});
        break;
      }
      auto &&[header_bytes_read, read_header_errata] = thread_info._session->read_header(w);
      thread_errata.note(read_header_errata);
      if (!read_header_errata.is_ok()) {
        thread_errata.error("Could not read the header.");
        Engine::status_code = 1;
        break;
      }

      ssize_t body_offset = header_bytes_read;
      if (body_offset == 0) {
        break; // client closed between transactions, that's not an error.
      }

      auto received_data = swoc::TextView(w.data(), body_offset);
      auto &&[parse_result, parse_errata] = req_hdr.parse_request(received_data);
      thread_errata.note(parse_errata);

      if (parse_result != HttpHeader::PARSE_OK || !thread_errata.is_ok()) {
        thread_errata.error(R"(The received request was malformed.)");
        thread_errata.diag(R"(Received data: {}.)", received_data);
        Engine::status_code = 1;
        break;
      }
      thread_errata.diag("Handling request with url: {}", req_hdr._url);
      thread_errata.diag("{}", req_hdr);
      auto key{req_hdr.make_key()};
      auto specified_response{Transactions.find(key)};

      if (specified_response == Transactions.end()) {
        thread_errata.error(R"(Proxy request with key "{}" not found.)", key);
        Engine::status_code = 1;
        break;
      }

      [[maybe_unused]] auto &[unused_key, txn] = *specified_response;

      thread_errata.note(req_hdr.update_content_length(req_hdr._method));
      thread_errata.note(req_hdr.update_transfer_encoding());

      // If there is an Expect header with the value of 100-continue, send the
      // 100-continue response before Reading request body.
      if (req_hdr._send_continue) {
        thread_info._session->write(Continue_resp);
      }

      if (req_hdr._content_length_p || req_hdr._chunked_p) {
        thread_errata.diag("Draining request body.");
        auto &&[bytes_drained, drain_errata] = thread_info._session->drain_body(
            req_hdr,
            req_hdr._content_size,
            w.view().substr(body_offset));
        thread_errata.note(drain_errata);

        if (!thread_errata.is_ok()) {
          thread_errata.error("Failed to drain the request body.");
          break;
        }
      }
      thread_errata.diag("Validating request with url: {}", req_hdr._url);
      if (req_hdr.verify_headers(key, *txn._req._fields_rules)) {
        thread_errata.error(R"(Request headers did not match expected request headers.)");
        Engine::status_code = 1;
      }
      // Responses to HEAD requests may have a non-zero Content-Length
      // but will never have a body. update_content_length adjusts
      // expectations so the body is not written for responses to such
      // requests.
      txn._rsp.update_content_length(req_hdr._method);
      thread_errata.diag(
          "Responding to request {} with status {}.",
          req_hdr._url,
          txn._rsp._status);
      auto &&[bytes_written, write_errata] = thread_info._session->write(txn._rsp);
      thread_errata.note(write_errata);
      thread_errata.diag(
          "Wrote {} bytes in response to request with url {} "
          "with response status {}",
          bytes_written,
          req_hdr._url,
          txn._rsp._status);
    }

    // cleanup and get ready for another session.
    delete_thread_info_session(thread_info);
  }
}

void
TF_Accept(int socket_fd, bool do_tls)
{
  std::unique_ptr<Session> session;
  struct pollfd poll_set[1];
  int numfds = 1;
  poll_set[0].fd = socket_fd;
  poll_set[0].events = POLLIN;

  while (!Shutdown_Flag) {
    swoc::Errata errata;
    // Poll so that we can set a timeout and check whether the user requested a shutdown.
    auto const poll_return = ::poll(poll_set, numfds, Thread_Sleep_Interval_MS.count());
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
    if (do_tls) {
      session = std::make_unique<TLSSession>();
    } else {
      session = std::make_unique<Session>();
    }
    errata = session->set_fd(fd);
    if (!errata.is_ok()) {
      continue;
    }
    static const int ONE = 1;
    setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, &ONE, sizeof(ONE));

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
      status_code = 1;
      return;
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
        status_code = 1;
        return;
      }
    }

    if (server_addr_https_arg) {
      if (server_addr_https_arg.size() == 1) {
        errata = parse_ips(server_addr_https_arg[0], server_addrs_https);
        if (!errata.is_ok()) {
          status_code = 1;
          return;
        }
        std::error_code ec;

        auto cert_arg{arguments.get("server-cert")};
        if (cert_arg.size() >= 1) {
          errata.note(TLSSession::configure_server_cert(cert_arg[0]));
          if (!errata.is_ok()) {
            errata.error(R"(Invalid server-cert path "{}")", cert_arg[0]);
            status_code = 1;
            return;
          }
        }
        auto ca_certs_arg{arguments.get("ca-certs")};
        if (ca_certs_arg.size() >= 1) {
          errata.note(TLSSession::configure_ca_cert(ca_certs_arg[0]));
          if (!errata.is_ok()) {
            errata.error(R"(Invalid ca-certs path "{}")", cert_arg[0]);
            status_code = 1;
            return;
          }
        }
        if (errata.is_ok()) {
          errata = TLSSession::init();
        }
      } else {
        errata.error(
            R"(--listen-https option must have a single value, the listen address and port.)");
        status_code = 1;
        return;
      }
    }

    errata = Load_Replay_Directory(
        swoc::file::path{args[0]},
        [](swoc::file::path const &file) -> swoc::Errata {
          ServerReplayFileHandler handler;
          return Load_Replay_File(file, handler);
        },
        10);

    if (!errata.is_ok()) {
      status_code = 1;
      return;
    }
    Session::init(Transactions.size());

    // After this, any string expected to be localized that isn't is an error,
    // so lock down the local string storage to avoid runtime locking and report
    // an error instead if not found.
    HttpHeader::_frozen = true;
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
        status_code = 1;
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
    usleep(chrono::microseconds{Thread_Sleep_Interval_MS}.count());
  }
  for_each(
      Accept_Threads.begin(),
      Accept_Threads.end(),
      [](std::unique_ptr<std::thread> const &thread) { thread->join(); });
  Accept_Threads.clear();
  Server_Thread_Pool.join_threads();

  exit(Engine::status_code);
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

  engine.parser
      .add_command(
          "run",
          "run <dir>: the replay server using data in <dir>",
          "",
          1,
          [&]() -> void { engine.command_run(); })
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

  Continue_resp._status = 100;
  Continue_resp._http_version = "1.1";
  Continue_resp._reason = "continue";

  engine.arguments.invoke();
  return engine.status_code;
}
