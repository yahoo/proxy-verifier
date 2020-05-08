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

#include <bits/signum.h>
#include <dirent.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
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

void TF_Serve(std::thread *t);

/** Whether to verify each request against the corresponding proxy-request
 * in the yaml file.
 */
bool Use_Strict_Checking = false;

// Path to the parent directory of the executable, used for relative paths.
swoc::file::path ROOT_PATH;

// This must be a list so that iterators / pointers to elements do not go stale.
std::list<std::thread *> Listen_threads;

class ServerThreadInfo : public ThreadInfo {
public:
  Session *_session = nullptr;
  bool data_ready() override { return this->_session; }
};

class ServerThreadPool : public ThreadPool {
public:
  std::thread make_thread(std::thread *t) override;
};

ServerThreadPool Server_Thread_Pool;

HttpHeader Continue_resp;

std::thread ServerThreadPool::make_thread(std::thread *t) {
  return std::thread(
      TF_Serve, t); // move the temporary into the list element for permanence.
}

/** Command execution.
 *
 * This handles parsing and acting on the command line arguments.
 */
struct Engine {
  ts::ArgParser parser;    ///< Command line argument parser.
  ts::Arguments arguments; ///< Results from argument parsing.

  void command_run();

  /// Status code to return to the operating system.
  int status_code = 0;
};

bool Shutdown_Flag = false;

std::mutex LoadMutex;

std::unordered_map<std::string, Txn, std::hash<std::string_view>> Transactions;

class ServerReplayFileHandler : public ReplayFileHandler {
public:
  ServerReplayFileHandler();

  swoc::Errata txn_open(YAML::Node const &node) override;
  swoc::Errata proxy_request(YAML::Node const &node) override;
  swoc::Errata server_response(YAML::Node const &node) override;
  swoc::Errata apply_to_all_messages(HttpFields const &all_headers) override;
  swoc::Errata txn_close() override;

  void reset();

private:
  std::string _key;
  Txn _txn;
};

ServerReplayFileHandler::ServerReplayFileHandler()
    : _txn{Use_Strict_Checking} {}

void ServerReplayFileHandler::reset() {
  _txn.~Txn();
  new (&_txn) Txn{Use_Strict_Checking};
}

swoc::Errata ServerReplayFileHandler::txn_open(YAML::Node const &node) {
  Errata errata;
  if (!node[YAML_PROXY_REQ_KEY]) {
    errata.error(
        R"(Transaction node at "{}":{} does not have a proxy request [{}].)",
        _path, node.Mark().line, YAML_PROXY_REQ_KEY);
  }
  if (!node[YAML_SERVER_RSP_KEY]) {
    errata.error(
        R"(Transaction node at "{}":{} does not have a server response [{}].)",
        _path, node.Mark().line, YAML_SERVER_RSP_KEY);
  }
  if (!errata.is_ok()) {
    return std::move(errata);
  }
  LoadMutex.lock();
  return {};
}

swoc::Errata ServerReplayFileHandler::proxy_request(YAML::Node const &node) {
  _txn._req._fields_rules =
      std::make_shared<HttpFields>(*global_config.txn_rules);
  swoc::Errata errata = _txn._req.load(node);
  return std::move(errata);
}

swoc::Errata ServerReplayFileHandler::server_response(YAML::Node const &node) {
  return _txn._rsp.load(node);
}

swoc::Errata
ServerReplayFileHandler::apply_to_all_messages(HttpFields const &all_headers) {
  _txn._req._fields_rules->merge(all_headers);
  _txn._rsp._fields_rules->merge(all_headers);
  return {};
}

swoc::Errata ServerReplayFileHandler::txn_close() {
  _key = _txn._req.make_key();
  Transactions.emplace(_key, std::move(_txn));
  LoadMutex.unlock();
  this->reset();
  return {};
}

void TF_Serve(std::thread *t) {
  ServerThreadInfo thread_info;
  thread_info._thread = t;
  while (!Shutdown_Flag) {
    swoc::Errata errata;

    Server_Thread_Pool.wait_for_work(&thread_info);

    errata = thread_info._session->accept();
    while (!thread_info._session->is_closed() && errata.is_ok()) {
      HttpHeader req_hdr;
      swoc::Errata thread_errata;
      swoc::LocalBufferWriter<MAX_HDR_SIZE> w;
      auto &&[header_bytes_read, read_header_errata] =
          thread_info._session->read_header(w);
      thread_errata.note(read_header_errata);
      if (!read_header_errata.is_ok()) {
        thread_errata.error("Could not read the header.");
        break;
      }

      ssize_t body_offset = header_bytes_read;
      if (body_offset == 0) {
        break; // client closed between transactions, that's not an error.
      }

      const auto received_data = swoc::TextView(w.data(), body_offset);
      auto &&[parse_result, parse_errata] =
          req_hdr.parse_request(received_data);
      thread_errata.note(parse_errata);

      if (parse_result != HttpHeader::PARSE_OK || !thread_errata.is_ok()) {
        thread_errata.error(R"(The received request was malformed.)");
        thread_errata.diag(R"(Received data: {}.)", received_data);
        break;
      }
      thread_errata.diag("Handling request with url: {}", req_hdr._url);
      thread_errata.diag("{}", req_hdr);
      auto key{req_hdr.make_key()};
      auto specified_response{Transactions.find(key)};

      if (specified_response == Transactions.end()) {
        thread_errata.error(R"(Proxy request with key "{}" not found.)", key);
        break;
      }

      [[maybe_unused]] auto &[unused_key, txn] = *specified_response;

      thread_errata.note(req_hdr.update_content_length(req_hdr._method));
      thread_errata.note(req_hdr.update_transfer_encoding());

      // If there is an Expect header with the value of 100-continue, send the
      // 100-continue response before Reading request body.
      if (req_hdr._send_continue) {
        auto &&[bytes_written, write_errata] =
            thread_info._session->write(Continue_resp);
      }

      if (req_hdr._content_length_p || req_hdr._chunked_p) {
        thread_errata.diag("Draining request body.");
        auto &&[bytes_drained, drain_errata] = thread_info._session->drain_body(
            req_hdr, req_hdr._content_size, w.view().substr(body_offset));
        thread_errata.note(drain_errata);

        if (!thread_errata.is_ok()) {
          thread_errata.error("Failed to drain the request body.");
          break;
        }
      }
      thread_errata.diag("Validating request with url: {}", req_hdr._url);
      if (req_hdr.verify_headers(key, *txn._req._fields_rules)) {
        thread_errata.error(
            R"(Request headers did not match expected request headers.)");
      }
      // Responses to HEAD requests may have a non-zero Content-Length
      // but will never have a body. update_content_length adjusts
      // expectations so the body is not written for responses to such
      // requests.
      txn._rsp.update_content_length(req_hdr._method);
      thread_errata.diag("Responding to request {} with status {}.",
                         req_hdr._url, txn._rsp._status);
      auto &&[bytes_written, write_errata] =
          thread_info._session->write(txn._rsp);
      thread_errata.note(write_errata);
      thread_errata.diag("Wrote {} bytes in response to request with url {} "
                         "with response status {}",
                         bytes_written, req_hdr._url, txn._rsp._status);
    }

    // cleanup and get ready for another session.
    {
      std::unique_lock<std::mutex> lock(thread_info._mutex);
      delete thread_info._session;
      thread_info._session = nullptr;
    }
  }
}

void TF_Accept(int socket_fd, bool do_tls) {
  std::unique_ptr<Session> session;
  while (!Shutdown_Flag) {
    swoc::Errata errata;
    swoc::IPEndpoint remote_addr;
    socklen_t remote_addr_size = sizeof(remote_addr);
    int fd = accept4(socket_fd, &remote_addr.sa, &remote_addr_size, 0);
    if (fd < 0) {
      errata.error("Failed to create a socket via accept4: {}",
                   swoc::bwf::Errno{});
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
      // Only pointer to worker thread info.
      {
        std::unique_lock<std::mutex> lock(thread_info->_mutex);
        thread_info->_session = session.release();
        thread_info->_cvar.notify_one();
      }
    }
  }
}

swoc::Errata do_listen(swoc::IPEndpoint &server_addr, bool do_tls) {
  swoc::Errata errata;
  int socket_fd = socket(server_addr.family(), SOCK_STREAM, 0);
  if (socket_fd >= 0) {
    // Be agressive in reusing the port
    static constexpr int ONE = 1;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &ONE, sizeof(int)) <
        0) {
      errata.error(R"(Could not set reuseaddr on socket {}: {}.)", socket_fd,
                   swoc::bwf::Errno{});
    } else {
      int bind_result = bind(socket_fd, &server_addr.sa, server_addr.size());
      if (bind_result == 0) {
        int listen_result = listen(socket_fd, 16384);
        if (listen_result == 0) {
          errata.info(R"(Listening at {})", server_addr);
          std::thread *runner = new std::thread{TF_Accept, socket_fd, do_tls};
          Listen_threads.push_back(runner);
        } else {
          errata.error(R"(Could not isten to {}: {}.)", server_addr,
                       swoc::bwf::Errno{});
        }
      } else {
        errata.error(R"(Could not bind to {}: {}.)", server_addr,
                     swoc::bwf::Errno{});
      }
    }
  } else {
    errata.error(R"(Could not create socket: {}.)", swoc::bwf::Errno{});
  }
  if (!errata.is_ok() && socket_fd >= 0) {
    close(socket_fd);
  }
  return std::move(errata);
}

void Engine::command_run() {
  { // Scope errata before the long-lived server loop.
    Errata errata;
    auto args{arguments.get("run")};
    std::deque<swoc::IPEndpoint> server_addrs, server_addrs_https;
    auto server_addr_arg{arguments.get("listen")};
    auto server_addr_https_arg{arguments.get("listen-https")};
    auto cert_arg{arguments.get("cert")};
    auto key_format_arg{arguments.get("format")};

    swoc::LocalBufferWriter<1024> w;

    if (args.size() < 1) {
      errata.error(
          R"("run" command requires a directory path as an argument.)");
      status_code = 1;
      return;
    }

    if (arguments.get("strict")) {
      Use_Strict_Checking = true;
    }

    if (key_format_arg) {
      HttpHeader::_key_format = key_format_arg[0];
    }

    if (server_addr_arg) {
      if (server_addr_arg.size() == 1) {
        errata = parse_ips(server_addr_arg[0], server_addrs);
      } else {
        errata.error(
            R"(--listen option must have a single value, the listen address and port.)");
        status_code = 1;
        return;
      }
    }

    Session::init();

    if (server_addr_https_arg) {
      if (server_addr_https_arg.size() == 1) {
        errata = parse_ips(server_addr_https_arg[0], server_addrs_https);
        if (!errata.is_ok()) {
          status_code = 1;
          return;
        }
        std::error_code ec;

        if (cert_arg.size() >= 1) {
          swoc::file::path cert_path{cert_arg[0]};
          if (!cert_path.is_absolute()) {
            cert_path = ROOT_PATH / cert_path;
          }
          auto stat{swoc::file::status(cert_path, ec)};
          if (ec.value() == 0) {
            if (is_dir(stat)) {
              TLSSession::certificate_file = cert_path / "server.pem";
              TLSSession::privatekey_file = cert_path / "server.key";
            } else {
              TLSSession::certificate_file = cert_path;
            }
          } else {
            errata.error(R"(Invalid certificate path "{}": {}.)", cert_arg[0],
                         ec);
            status_code = 1;
            return;
          }
        } else {
          TLSSession::certificate_file = ROOT_PATH / "server.pem";
          TLSSession::privatekey_file = ROOT_PATH / "server.key";
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

    errata =
        Load_Replay_Directory(swoc::file::path{args[0]},
                              [](swoc::file::path const &file) -> swoc::Errata {
                                ServerReplayFileHandler handler;
                                return Load_Replay_File(file, handler);
                              },
                              10);

    if (!errata.is_ok() && errata.severity() != swoc::Severity::ERROR) {
      status_code = 1;
      return;
    }

    // After this, any string expected to be localized that isn't is an error,
    // so lock down the local string storage to avoid runtime locking and report
    // an error instead if not found.
    HttpHeader::_frozen = true;
    size_t max_content_length = 0;
    for (auto const &[key, txn] : Transactions) {
      if (txn._rsp._content_data ==
          nullptr) { // don't check responses with literal content.
        max_content_length =
            std::max<size_t>(max_content_length, txn._rsp._content_size);
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

  // Don't exit until all the listen threads go away
  while (true) {
    sleep(10);
  }
}

int main(int /* argc */, char const *argv[]) {
  swoc::Errata errata;
  if (block_sigpipe()) {
    errata.warn("Could not block SIGPIPE. Continuing anyway, but be aware that "
                "SSL_read "
                "and SSL_write issues may trigger SIGPIPE which will abruptly "
                "terminate execution.");
  }

  Engine engine;

  engine.parser
      .add_option("--verbose", "",
                  "Enable verbose output:"
                  "\n\terror: Only print errors."
                  "\n\twarn: Print warnings and errors."
                  "\n\tinfo: Print info messages in addition to warnings and "
                  "errors. This is the default verbosity level."
                  "\n\tdiag: Print debug messages in addition to info, "
                  "warnings, and errors,",
                  "", 1, "info")
      .add_option("--version", "-V", "Print version string")
      .add_option("--help", "-h", "Print usage information");

  engine.parser
      .add_command("run", "run <dir>: the replay server using data in <dir>",
                   "", 1, [&]() -> void { engine.command_run(); })
      .add_option("--listen", "",
                  "Listen address and port. Can be a comma separated list.", "",
                  1, "")
      .add_option("--listen-https", "",
                  "Listen TLS address and port. Can be a comma separated list.",
                  "", 1, "")
      .add_option("--format", "-f", "Transaction key format", "", 1, "")
      .add_option("--cert", "", "Specify TLS certificate file", "", 1, "")
      .add_option(
          "--strict", "-s",
          "Verify all proxy requests against the proxy-request fields as if "
          "they had equality verification rules in them if no other "
          "verification "
          "rule is provided.");

  // parse the arguments
  engine.arguments = engine.parser.parse(argv);
  std::string verbosity = "info";
  if (const auto verbose_argument{engine.arguments.get("verbose")};
      verbose_argument) {
    verbosity = verbose_argument.value();
  }
  if (!configure_logging(verbosity)) {
    std::cerr << "Unrecognized verbosity option: " << verbosity << std::endl;
    return 1;
  }

  ROOT_PATH = argv[0];
  ROOT_PATH = ROOT_PATH.parent_path().parent_path();

  Continue_resp._status = 100;
  Continue_resp._http_version = "1.1";
  Continue_resp._reason = "continue";

  engine.arguments.invoke();
  return engine.status_code;
}
