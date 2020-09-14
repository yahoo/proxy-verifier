/** @file
 * Implement the Proxy Verifier client.
 *
 * Copyright 2020, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "core/ArgParser.h"
#include "core/ProxyVerifier.h"
#include "swoc/bwf_ex.h"
#include "swoc/bwf_ip.h"
#include "swoc/bwf_std.h"
#include "swoc/swoc_file.h"

#include <assert.h>
#include <chrono>
#include <list>
#include <mutex>
#include <string>
#include <sys/time.h>
#include <thread>
#include <unistd.h>
#include <unordered_set>

#include <dirent.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

namespace swoc
{
inline BufferWriter &
bwformat(BufferWriter &w, bwf::Spec const &spec, std::chrono::milliseconds ms)
{
  return bwformat(w, spec, ms.count()).write("ms");
}
} // namespace swoc

using swoc::TextView;

/** Whether to verify each response against the corresponding proxy-response
 * in the yaml file.
 */
bool Use_Strict_Checking = false;

/// Path to the parent directory of the executable, used for relative paths.
swoc::file::path ROOT_PATH;

std::unordered_set<std::string> Keys_Whitelist;

std::mutex LoadMutex;

std::list<std::shared_ptr<Ssn>> Session_List;

std::deque<swoc::IPEndpoint> Target, Target_Https;

/** Whether the replay-client behaves according to client-request or
 * proxy-request directives.
 *
 * This flag is toggled via the existence or non-existence of the --no-proxy
 * argument. By default, replay-client will follow the client-request
 * directives and assume that there is a proxy in place. But if there is
 * --no-proxy, then because the server will expect requests and responses that
 *  came from the proxy, the replay-client will oblige by using the
 *  proxy-request directives.
 */
bool Use_Proxy_Request_Directives = false;

class ClientReplayFileHandler : public ReplayFileHandler
{
public:
  ClientReplayFileHandler();
  ~ClientReplayFileHandler() = default;

  swoc::Errata ssn_open(YAML::Node const &node) override;
  swoc::Errata txn_open(YAML::Node const &node) override;
  swoc::Errata client_request(YAML::Node const &node) override;
  swoc::Errata proxy_request(YAML::Node const &node) override;
  swoc::Errata server_response(YAML::Node const &node) override;
  swoc::Errata proxy_response(YAML::Node const &node) override;
  swoc::Errata apply_to_all_messages(HttpFields const &all_headers) override;
  swoc::Errata txn_close() override;
  swoc::Errata ssn_close() override;

  void txn_reset();
  void ssn_reset();

private:
  std::shared_ptr<Ssn> _ssn;
  Txn _txn;
};

bool Shutdown_Flag = false;

class ClientThreadInfo : public ThreadInfo
{
public:
  Ssn *_ssn = nullptr;
  bool
  data_ready() override
  {
    return Shutdown_Flag || this->_ssn != nullptr;
  }
};

class ClientThreadPool : public ThreadPool
{
public:
  std::thread make_thread(std::thread *t) override;
};

ClientThreadPool Client_Thread_Pool;

void TF_Client(std::thread *t);

std::thread
ClientThreadPool::make_thread(std::thread *t)
{
  return std::thread(TF_Client, t); // move the temporary into the list element for permanence.
}

ClientReplayFileHandler::ClientReplayFileHandler() : _txn{Use_Strict_Checking} { }

void
ClientReplayFileHandler::ssn_reset()
{
  _ssn.reset();
}

void
ClientReplayFileHandler::txn_reset()
{
  _txn.~Txn();
  new (&_txn) Txn{Use_Strict_Checking};
}

swoc::Errata
ClientReplayFileHandler::ssn_open(YAML::Node const &node)
{
  swoc::Errata errata;
  _ssn = std::make_shared<Ssn>();
  _ssn->_path = _path;
  _ssn->_line_no = node.Mark().line;

  if (auto protocol_sequence_node{node[YAML_SSN_PROTOCOL_KEY]}; protocol_sequence_node) {
    auto const tls_node =
        parse_for_protocol_node(protocol_sequence_node, YAML_SSN_PROTOCOL_TLS_NAME);
    if (!tls_node.is_ok()) {
      errata.note(std::move(tls_node.errata()));
      return errata;
    }
    if (tls_node.result().IsDefined()) {
      _ssn->is_tls = true;
      auto const sni = parse_sni(tls_node);
      if (!sni.is_ok()) {
        errata.note(std::move(sni.errata()));
        return errata;
      }
      if (!sni.result().empty()) {
        _ssn->_client_sni = sni.result();
      }
      auto const verify_mode = parse_verify_mode(tls_node);
      if (!verify_mode.is_ok()) {
        errata.note(std::move(verify_mode.errata()));
        return errata;
      }
      if (verify_mode > 0) {
        _ssn->_client_verify_mode = verify_mode;
      }
    }

    auto const http_node =
        parse_for_protocol_node(protocol_sequence_node, YAML_SSN_PROTOCOL_HTTP_NAME);
    if (!http_node.is_ok()) {
      errata.note(std::move(http_node.errata()));
      return errata;
    }
    if (http_node.result().IsDefined() &&
        http_node.result()[YAML_SSN_PROTOCOL_VERSION].Scalar() == "2") {
      _ssn->is_h2 = true;
    }
  }

  if (node[YAML_SSN_START_KEY]) {
    auto start_node{node[YAML_SSN_START_KEY]};
    if (start_node.IsScalar()) {
      auto t = swoc::svtou(start_node.Scalar());
      if (t != 0) {
        _ssn->_start = t / 1000; // Convert to usec from nsec
      } else {
        errata.error(
            R"(Session at "{}":{} has a "{}" value "{}" that is not a positive integer.)",
            _path,
            _ssn->_line_no,
            YAML_SSN_START_KEY,
            start_node.Scalar());
      }
    } else {
      errata.error(
          R"(Session at "{}":{} has a "{}" key that is not a scalar.)",
          _path,
          _ssn->_line_no,
          YAML_SSN_START_KEY);
    }
  }

  return errata;
}

swoc::Errata
ClientReplayFileHandler::txn_open(YAML::Node const &node)
{
  swoc::Errata errata;
  if (!node[YAML_CLIENT_REQ_KEY]) {
    errata.error(
        R"(Transaction node at "{}":{} does not have a client request [{}].)",
        _path,
        node.Mark().line,
        YAML_CLIENT_REQ_KEY);
  }
  if (!node[YAML_PROXY_RSP_KEY]) {
    errata.error(
        R"(Transaction node at "{}":{} does not have a proxy response [{}].)",
        _path,
        node.Mark().line,
        YAML_PROXY_RSP_KEY);
  }
  if (!errata.is_ok()) {
    return errata;
  }
  LoadMutex.lock();
  return {};
}

swoc::Errata
ClientReplayFileHandler::client_request(YAML::Node const &node)
{
  if (!Use_Proxy_Request_Directives) {
    return _txn._req.load(node);
  }
  return {};
}

swoc::Errata
ClientReplayFileHandler::proxy_request(YAML::Node const &node)
{
  if (Use_Proxy_Request_Directives) {
    return _txn._req.load(node);
  }
  return {};
}

swoc::Errata
ClientReplayFileHandler::proxy_response(YAML::Node const &node)
{
  if (!Use_Proxy_Request_Directives) {
    // We only expect proxy responses when we are behaving according to the
    // client-request directives and there is a proxy.
    _txn._rsp._fields_rules = std::make_shared<HttpFields>(*global_config.txn_rules);
    return _txn._rsp.load(node);
  }
  return {};
}

swoc::Errata
ClientReplayFileHandler::server_response(YAML::Node const &node)
{
  if (Use_Proxy_Request_Directives) {
    // If we are behaving like the proxy, then replay-client is talking directly
    // with the server and should expect the server's responses.
    _txn._rsp._fields_rules = std::make_shared<HttpFields>(*global_config.txn_rules);
    return _txn._rsp.load(node);
  }
  return {};
}

swoc::Errata
ClientReplayFileHandler::apply_to_all_messages(HttpFields const &all_headers)
{
  _txn._req._fields_rules->merge(all_headers);
  _txn._rsp._fields_rules->merge(all_headers);
  return {};
}

swoc::Errata
ClientReplayFileHandler::txn_close()
{
  const auto &key{_txn._req.make_key()};
  if (Keys_Whitelist.empty() || Keys_Whitelist.count(key) > 0) {
    _ssn->_transactions.emplace_back(std::move(_txn));
  }
  this->txn_reset();
  LoadMutex.unlock();
  return {};
}

swoc::Errata
ClientReplayFileHandler::ssn_close()
{
  {
    std::lock_guard<std::mutex> lock(LoadMutex);
    if (!_ssn->_transactions.empty()) {
      Session_List.push_back(_ssn);
    }
  }
  this->ssn_reset();
  return {};
}

void
Run_Session(Ssn const &ssn, swoc::IPEndpoint const &target, swoc::IPEndpoint const &target_https)
{
  swoc::Errata errata;
  std::unique_ptr<Session> session;
  swoc::IPEndpoint const *real_target = nullptr;

  errata.diag(
      R"(Starting session "{}":{} protocol={}.)",
      ssn._path,
      ssn._line_no,
      ssn.is_h2 ? "h2" : (ssn.is_tls ? "https" : "http"));

  if (ssn.is_h2) {
    if (Use_Proxy_Request_Directives) {
      // replay-server does not support HTTP/2 yet. We currently rely upon
      // TrafficServer to handle HTTP/2 on the client-side and talk HTTP/1 on
      // the server side. If there is no TrafficServer proxy, ignore the HTTP/2
      // traffic therefore.
      errata.diag(R"(Ignoring HTTP/2 traffic in proxy mode, "{}":{})", ssn._path, ssn._line_no);
      return;
    }
    session = std::make_unique<H2Session>();
    real_target = &target_https;
  } else if (ssn.is_tls) {
    session = std::make_unique<TLSSession>(ssn._client_sni, ssn._client_verify_mode);
    real_target = &target_https;
    errata.diag("Connecting via TLS.");
  } else {
    session = std::make_unique<Session>();
    real_target = &target;
    errata.diag("Connecting via HTTP.");
  }

  errata.note(session->do_connect(real_target));
  if (errata.is_ok()) {
    errata.note(session->run_transactions(ssn._transactions, real_target));
  }
  return;
}

void
TF_Client(std::thread *t)
{
  ClientThreadInfo thread_info;
  thread_info._thread = t;
  size_t target_index = 0;
  size_t target_https_index = 0;

  while (!Shutdown_Flag) {
    thread_info._ssn = nullptr;
    Client_Thread_Pool.wait_for_work(&thread_info);

    if (thread_info._ssn != nullptr) {
      Run_Session(*thread_info._ssn, Target[target_index], Target_Https[target_https_index]);
      if (++target_index >= Target.size())
        target_index = 0;
      if (++target_https_index >= Target_Https.size())
        target_https_index = 0;
    }
  }
}

bool
session_start_compare(const std::shared_ptr<Ssn> ssn1, const std::shared_ptr<Ssn> ssn2)
{
  return ssn1->_start < ssn2->_start;
}

/** Command execution.
 *
 * This handles parsing and acting on the command line arguments.
 */
struct Engine
{
  ts::ArgParser parser;    ///< Command line argument parser.
  ts::Arguments arguments; ///< Results from argument parsing.

  static constexpr swoc::TextView COMMAND_RUN{"run"};
  static constexpr swoc::TextView COMMAND_RUN_ARGS{
      "Arguments:\n"
      "\t<dir>: Directory containing replay files.\n"
      "\t<upstream http>: hostname and port for http requests. Can be a comma "
      "seprated list\n"
      "\t<upstream https>: hostname and port for https requests. Can be a "
      "comma separated list "};
  void command_run();

  /// Status code to return to the operating system.
  int status_code = 0;
};

uint64_t
GetUTimestamp()
{
  auto retval = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::system_clock::now().time_since_epoch());
  return retval.count();
}

void
Engine::command_run()
{
  auto args{arguments.get("run")};
  swoc::Errata errata;

  if (args.size() < 3) {
    errata.error(R"(Not enough arguments for "{}" command.\n{})", COMMAND_RUN, COMMAND_RUN_ARGS);
    status_code = 1;
    return;
  }

  if (arguments.get("no-proxy")) {
    // If there is no proxy, then replay-client will take direction from
    // proxy-request directives for its behavior. See the doxygen description
    // of this variable for the reasons for this.
    Use_Proxy_Request_Directives = true;
  }

  if (arguments.get("strict")) {
    Use_Strict_Checking = true;
  }

  errata.note(resolve_ips(args[1], Target));
  if (!errata.is_ok()) {
    status_code = 1;
    return;
  }
  errata.note(resolve_ips(args[2], Target_Https));
  if (!errata.is_ok()) {
    status_code = 1;
    return;
  }

  auto key_format_arg{arguments.get("format")};
  if (key_format_arg) {
    HttpHeader::_key_format = key_format_arg[0];
  }

  auto cert_arg{arguments.get("client-cert")};
  if (cert_arg.size() >= 1) {
    swoc::file::path cert_path{cert_arg[0]};
    if (!cert_path.is_absolute()) {
      cert_path = ROOT_PATH / cert_path;
    }
    std::error_code ec;
    auto stat{swoc::file::status(cert_path, ec)};
    if (ec.value() == 0) {
      if (is_dir(stat)) {
        TLSSession::certificate_file = cert_path / "client.pem";
        TLSSession::privatekey_file = cert_path / "client.key";
      } else {
        TLSSession::certificate_file = cert_path;
      }
    } else {
      errata.error(R"(Invalid certificate path "{}": {}.)", cert_arg[0], ec);
      status_code = 1;
      return;
    }
  } else {
    TLSSession::certificate_file = ROOT_PATH / "client.pem";
    TLSSession::privatekey_file = ROOT_PATH / "client.key";
  }

  auto ca_certs_arg{arguments.get("ca-certs")};
  if (ca_certs_arg.size() >= 1) {
    swoc::file::path cert_path{ca_certs_arg[0]};
    if (!cert_path.is_absolute()) {
      cert_path = ROOT_PATH / cert_path;
    }
    std::error_code ec;
    auto stat{swoc::file::status(cert_path, ec)};
    if (ec.value() == 0) {
      if (is_dir(stat)) {
        TLSSession::ca_certificate_dir = cert_path;
      } else {
        TLSSession::ca_certificate_file = cert_path;
      }
    } else {
      errata.error(R"(Invalid ca certificate path "{}": {}.)", ca_certs_arg[0], ec);
      status_code = 1;
      return;
    }
  }

  auto keys_arg{arguments.get("keys")};
  if (!keys_arg.empty()) {
    for (auto const &key : keys_arg) {
      Keys_Whitelist.insert(key);
    }
  }

  errata.info(R"(Loading directory "{}".)", args[0]);
  errata.note(Load_Replay_Directory(
      swoc::file::path{args[0]},
      [](swoc::file::path const &file) -> swoc::Errata {
        ClientReplayFileHandler handler;
        return Load_Replay_File(file, handler);
      },
      10));
  if (!errata.is_ok()) {
    status_code = 1;
    return;
  }

  Session::init();
  errata.diag(R"(Initializing TLS)");
  TLSSession::init();
  errata.diag(R"(Initialize H2)");
  H2Session::init();

  // Sort the Session_List and adjust the time offsets
  Session_List.sort(session_start_compare);

  // After this, any string expected to be localized that isn't is an error,
  // so lock down the local string storage to avoid locking and report an
  // error instead if not found.
  HttpHeader::_frozen = true;
  size_t max_content_length = 0;
  uint64_t offset_time = 0;
  int transaction_count = 0;
  if (!Session_List.empty()) {
    offset_time = Session_List.front()->_start;
  }
  for (auto ssn : Session_List) {
    ssn->_start -= offset_time;
    transaction_count += ssn->_transactions.size();
    for (auto const &txn : ssn->_transactions) {
      max_content_length = std::max<size_t>(max_content_length, txn._req._content_size);
    }
  }
  errata.info("Parsed {} transactions.", transaction_count);
  HttpHeader::set_max_content_length(max_content_length);

  float rate_multiplier = 0.0;
  auto rate_arg{arguments.get("rate")};
  auto repeat_arg{arguments.get("repeat")};
  auto sleep_limit_arg{arguments.get("sleep-limit")};
  int repeat_count = 0;
  uint64_t sleep_limit = 500000;
  if (rate_arg.size() == 1 && !Session_List.empty()) {
    int target = atoi(rate_arg[0].c_str());
    if (target == 0.0) {
      rate_multiplier = 0.0;
    } else {
      rate_multiplier = (transaction_count * 1000000.0) / (target * Session_List.back()->_start);
    }
    errata.info(
        "Rate multiplier: {}, transaction count: {}, time delta: {}, "
        "first time {}",
        rate_multiplier,
        transaction_count,
        Session_List.back()->_start,
        offset_time);
  }

  if (repeat_arg.size() == 1) {
    repeat_count = atoi(repeat_arg[0].c_str());
  } else {
    repeat_count = 1;
  }

  if (sleep_limit_arg.size() == 1) {
    sleep_limit = atoi(sleep_limit_arg[0].c_str());
  }

  auto start = std::chrono::high_resolution_clock::now();
  unsigned n_ssn = 0;
  unsigned n_txn = 0;
  for (int i = 0; i < repeat_count; i++) {
    uint64_t firsttime = GetUTimestamp();
    uint64_t nexttime = 0;
    for (auto ssn : Session_List) {
      uint64_t curtime = GetUTimestamp();
      nexttime = (uint64_t)(rate_multiplier * ssn->_start) + firsttime;
      if (nexttime > curtime) {
        usleep(std::min(sleep_limit, nexttime - curtime));
      }
      ClientThreadInfo *thread_info =
          dynamic_cast<ClientThreadInfo *>(Client_Thread_Pool.get_worker());
      if (nullptr == thread_info) {
        errata.error("Failed to get worker thread");
      } else {
        // Only pointer to worker thread info.
        {
          std::unique_lock<std::mutex> lock(thread_info->_mutex);
          thread_info->_ssn = ssn.get();
          thread_info->_cvar.notify_one();
        }
      }
      ++n_ssn;
      n_txn += ssn->_transactions.size();
    }
  }
  // Wait until all threads are done
  Shutdown_Flag = true;
  Client_Thread_Pool.join_threads();

  auto delta = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::high_resolution_clock::now() - start);
  errata.info(
      "{} transactions in {} sessions (reuse {:.2f}) in {} ({:.3f} / "
      "millisecond).",
      n_txn,
      n_ssn,
      n_txn / static_cast<double>(n_ssn),
      delta,
      n_txn / static_cast<double>(delta.count()));
};

int
main(int /* argc */, char const *argv[])
{
  block_sigpipe();

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
          Engine::COMMAND_RUN.data(),
          Engine::COMMAND_RUN_ARGS.data(),
          "",
          MORE_THAN_ONE_ARG_N,
          [&]() -> void { engine.command_run(); })
      .add_option("--no-proxy", "", "Use proxy data instead of client data.")
      .add_option(
          "--repeat",
          "",
          "Specify a number of times to repeat replaying the data set.",
          "",
          1,
          "")
      .add_option(
          "--sleep-limit",
          "",
          "Limit the amount of time spent sleeping between sessions."
          "(microseconds)",
          "",
          1,
          "")
      .add_option("--rate", "", "Specify desired transacton rate (requests per second).", "", 1, "")
      .add_option("--format", "-f", "Transaction key format", "", 1, "")
      .add_option(
          "--strict",
          "-s",
          "Verify all proxy responses against the content in the yaml "
          "file as opposed to "
          "just those with verification elements.")
      .add_option(
          "--client-cert",
          "",
          "Specify a TLS client certificate file containing both the public and "
          "private keys. Alternatively a directory containing client.pem and "
          "client.key files can be provided.",
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
          "--keys",
          "-k",
          "A whitelist of transactions to send.",
          "",
          MORE_THAN_ZERO_ARG_N,
          "");

  // parse the arguments
  engine.arguments = engine.parser.parse(argv);

  ROOT_PATH = argv[0];
  ROOT_PATH = ROOT_PATH.parent_path().parent_path();

  std::string verbosity = "info";
  if (const auto verbose_argument{engine.arguments.get("verbose")}; verbose_argument) {
    verbosity = verbose_argument.value();
  }
  if (!configure_logging(verbosity)) {
    std::cerr << "Unrecognized verbosity option: " << verbosity << std::endl;
    return 1;
  }

  engine.arguments.invoke();
  return engine.status_code;
}
