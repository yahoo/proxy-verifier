/** @file
 * Implement the Proxy Verifier client.
 *
 * Copyright 2021, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "core/ArgParser.h"
#include "core/ProxyVerifier.h"
#include "core/YamlParser.h"
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
using namespace std::literals;
using std::chrono::duration_cast;
using std::chrono::microseconds;
using std::chrono::milliseconds;
using std::chrono::nanoseconds;
using ClockType = std::chrono::system_clock;
using TimePoint = std::chrono::time_point<ClockType, nanoseconds>;
using std::this_thread::sleep_for;

/** Whether to verify each response against the corresponding proxy-response
 * in the yaml file.
 */
bool Use_Strict_Checking = false;

std::unordered_set<std::string> Keys_Whitelist;

std::mutex LoadMutex;

std::list<std::shared_ptr<Ssn>> Session_List;

std::deque<swoc::IPEndpoint> Target, Target_Https;

/** Whether the replay-client constructs traffic according to client-request or
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

swoc::Rv<TimePoint>
get_start_time(YAML::Node const &node)
{
  swoc::Rv<TimePoint> zret;
  if (node[YAML_TIME_START_KEY]) {
    auto start_node{node[YAML_TIME_START_KEY]};
    if (start_node.IsScalar()) {
      auto t = swoc::svtou(start_node.Scalar());
      if (t != 0) {
        return TimePoint(nanoseconds(t));
      } else {
        zret.error(
            R"("{}" node value "{}" that is not a positive integer.)",
            YAML_TIME_START_KEY,
            start_node.Scalar());
      }
    } else {
      zret.error(R"("{}" key that is not a scalar.)", YAML_TIME_START_KEY);
    }
  }
  return zret;
}

swoc::Rv<microseconds>
get_delay_time(YAML::Node const &node)
{
  swoc::Rv<microseconds> zret;
  if (node[YAML_TIME_DELAY_KEY]) {
    auto delay_node{node[YAML_TIME_DELAY_KEY]};
    if (delay_node.IsScalar()) {
      auto &&[delay, delay_errata] = interpret_delay_string(delay_node.Scalar());
      zret.note(std::move(delay_errata));
      zret = delay;
    } else {
      zret.error(R"("{}" key that is not a scalar.)", YAML_TIME_DELAY_KEY);
    }
  }
  return zret;
}

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
  YAML::Node const *_txn_node = nullptr;
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
  _txn_node = nullptr;
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

  if (node[YAML_TIME_START_KEY]) {
    auto &&[start_time, start_time_errata] = get_start_time(node);
    if (!start_time_errata.is_ok()) {
      errata.note(std::move(start_time_errata));
      errata.error(
          R"(Session at "{}":{} has a bad "{}" key value.)",
          _path,
          _ssn->_line_no,
          YAML_TIME_START_KEY);
      return errata;
    }
    _ssn->_start = start_time;
  }

  if (node[YAML_TIME_DELAY_KEY]) {
    auto &&[delay_time, delay_errata] = get_delay_time(node);
    if (!delay_errata.is_ok()) {
      errata.note(std::move(delay_errata));
      errata.error(
          R"(Session at "{}":{} has a bad "{}" key value.)",
          _path,
          _ssn->_line_no,
          YAML_TIME_DELAY_KEY);
      return errata;
    }
    _ssn->_user_specified_delay_duration = delay_time;
  }
  return errata;
}

swoc::Errata
ClientReplayFileHandler::txn_open(YAML::Node const &node)
{
  swoc::Errata errata;
  _txn_node = &node;
  _txn._req._is_request = true;
  _txn._rsp._is_response = true;
  if (!node[YAML_CLIENT_REQ_KEY]) {
    errata.error(
        R"(Transaction node at "{}":{} does not have a client request [{}].)",
        _path,
        node.Mark().line,
        YAML_CLIENT_REQ_KEY);
  }
  if (!errata.is_ok()) {
    return errata;
  }
  if (node[YAML_TIME_START_KEY]) {
    auto &&[transaction_start_time, start_time_errata] = get_start_time(node);
    if (!start_time_errata.is_ok()) {
      errata.note(std::move(start_time_errata));
      errata.error(
          R"(Transaction at "{}":{} has a bad "{}" key value.)",
          _path,
          node.Mark().line,
          YAML_TIME_START_KEY);
      return errata;
    }
    if (transaction_start_time < _ssn->_start) {
      // Maybe the mechanisms used to measure session start and transaction
      // count are different and for some reason the session start time is
      // recorded as later than the transaction start. For our purposes, this
      // simply means that we should consider session start to be the time of
      // the earliest transaction.
      _ssn->_start = transaction_start_time;
    }
    _txn._start = transaction_start_time - _ssn->_start;
  }

  LoadMutex.lock();
  return errata;
}

swoc::Errata
ClientReplayFileHandler::client_request(YAML::Node const &node)
{
  swoc::Errata errata;
  if (!Use_Proxy_Request_Directives) {
    _txn._req._is_http2 = _ssn->is_h2;
    errata.note(YamlParser::populate_http_message(node, _txn._req));
    if (_txn._req._method.empty()) {
      errata.error(R"(client-request node without a method at "{}":{}.)", _path, node.Mark().line);
    }

    if (node[YAML_TIME_DELAY_KEY]) {
      auto &&[delay_time, delay_errata] = get_delay_time(node);
      if (!delay_errata.is_ok()) {
        errata.note(std::move(delay_errata));
        errata.error(
            R"(Session at "{}":{} has a bad "{}" key value.)",
            _path,
            _ssn->_line_no,
            YAML_TIME_DELAY_KEY);
        return errata;
      }
      _txn._user_specified_delay_duration = delay_time;
    }
  }
  return errata;
}

swoc::Errata
ClientReplayFileHandler::proxy_request(YAML::Node const &node)
{
  swoc::Errata errata;
  if (Use_Proxy_Request_Directives) {
    _txn._req._is_http2 = _ssn->is_h2;
    errata.note(YamlParser::populate_http_message(node, _txn._req));
    if (_txn._req._method.empty()) {
      errata.error(R"(proxy-request node without a method at "{}":{}.)", _path, node.Mark().line);
    }

    if (node[YAML_TIME_DELAY_KEY]) {
      auto &&[delay_time, delay_errata] = get_delay_time(node);
      if (!delay_errata.is_ok()) {
        errata.note(std::move(delay_errata));
        errata.error(
            R"(Session at "{}":{} has a bad "{}" key value.)",
            _path,
            _ssn->_line_no,
            YAML_TIME_DELAY_KEY);
        return errata;
      }
      _txn._user_specified_delay_duration = delay_time;
    }
  }
  return errata;
}

swoc::Errata
ClientReplayFileHandler::proxy_response(YAML::Node const &node)
{
  if (!Use_Proxy_Request_Directives) {
    // We only expect proxy responses when we are behaving according to the
    // client-request directives and there is a proxy.
    _txn._rsp._is_http2 = _ssn->is_h2;
    _txn._rsp._fields_rules = std::make_shared<HttpFields>(*global_config.txn_rules);
    return YamlParser::populate_http_message(node, _txn._rsp);
  }
  return {};
}

swoc::Errata
ClientReplayFileHandler::server_response(YAML::Node const &node)
{
  swoc::Errata errata;
  if (Use_Proxy_Request_Directives) {
    // If we are behaving like the proxy, then replay-client is talking directly
    // with the server and should expect the server's responses.
    _txn._rsp._is_http2 = _ssn->is_h2;
    _txn._rsp._fields_rules = std::make_shared<HttpFields>(*global_config.txn_rules);
    errata.note(YamlParser::populate_http_message(node, _txn._rsp));
    if (_txn._rsp._status == 0) {
      errata.error(R"(server-response node without a status at "{}":{})", _path, node.Mark().line);
    }
  }
  return errata;
}

swoc::Errata
ClientReplayFileHandler::apply_to_all_messages(HttpFields const &all_headers)
{
  _txn._req.merge(all_headers);
  _txn._rsp.merge(all_headers);
  return {};
}

swoc::Errata
ClientReplayFileHandler::txn_close()
{
  swoc::Errata errata;
  const auto &key{_txn._req.get_key()};
  if (key == HttpHeader::TRANSACTION_KEY_NOT_SET) {
    // A key cannot be found for this transaction. Fail parsing for this
    // because this is almost surely not what the user wants.
    errata.error(
        R"(Could not find a key of format "{}" for transaction at "{}":{}.)",
        HttpHeader::_key_format,
        _path,
        _txn_node->Mark().line);
  } else {
    // The user need not specify the key in the server-response node. For logging
    // purposes, make sure _txn._rsp is aware of the key.
    _txn._rsp.set_key(key);
    if (Keys_Whitelist.empty() || Keys_Whitelist.count(key) > 0) {
      _ssn->_transactions.emplace_back(std::move(_txn));
    }
  }
  this->txn_reset();
  LoadMutex.unlock();
  return errata;
}

swoc::Errata
ClientReplayFileHandler::ssn_close()
{
  {
    std::lock_guard<std::mutex> lock(LoadMutex);
    if (!_ssn->_transactions.empty()) {
      auto const &e = _ssn->post_process_transactions();
      if (!e.is_ok()) {
        swoc::Errata errata;
        errata.note(e);
        errata.error(
            R"("{}":{} Could not process transactions in session.)",
            _path,
            _ssn->_line_no);
      }
      Session_List.push_back(_ssn);
    }
  }
  this->ssn_reset();
  return {};
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

  /// The process return code with which to exit.
  static int process_exit_code;
};

int Engine::process_exit_code = 0;

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
    session = std::make_unique<H2Session>(ssn._client_sni, ssn._client_verify_mode);
    real_target = &target_https;
    errata.diag("Connecting via HTTP/2 over TLS.");
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
    errata.note(session->run_transactions(ssn._transactions, real_target, ssn._rate_multiplier));
  }
  if (!errata.is_ok()) {
    Engine::process_exit_code = 1;
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

void
Engine::command_run()
{
  auto args{arguments.get("run")};
  swoc::Errata errata;

  if (args.size() < 3) {
    errata.error(R"(Not enough arguments for "{}" command.\n{})", COMMAND_RUN, COMMAND_RUN_ARGS);
    process_exit_code = 1;
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
    process_exit_code = 1;
    return;
  }
  errata.note(resolve_ips(args[2], Target_Https));
  if (!errata.is_ok()) {
    process_exit_code = 1;
    return;
  }

  auto key_format_arg{arguments.get("format")};
  if (key_format_arg) {
    HttpHeader::_key_format = key_format_arg[0];
  }

  auto cert_arg{arguments.get("client-cert")};
  if (cert_arg.size() >= 1) {
    errata.note(TLSSession::configure_client_cert(cert_arg[0]));
    if (!errata.is_ok()) {
      errata.error(R"(Invalid client-cert path "{}")", cert_arg[0]);
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

  auto keys_arg{arguments.get("keys")};
  if (!keys_arg.empty()) {
    for (auto const &key : keys_arg) {
      Keys_Whitelist.insert(key);
    }
  }

  errata.info(R"(Loading replay data from "{}".)", args[0]);
  errata.note(YamlParser::load_replay_files(
      swoc::file::path{args[0]},
      [](swoc::file::path const &file) -> swoc::Errata {
        ClientReplayFileHandler handler;
        return YamlParser::load_replay_file(file, handler);
      },
      10));
  if (!errata.is_ok()) {
    process_exit_code = 1;
    return;
  }

  // Sort the Session_List and adjust the time offsets
  Session_List.sort([](const std::shared_ptr<Ssn> ssn1, const std::shared_ptr<Ssn> ssn2) {
    return ssn1->_start < ssn2->_start;
  });

  size_t max_content_length = 0;
  int transaction_count = 0;
  for (auto ssn : Session_List) {
    transaction_count += ssn->_transactions.size();
    for (auto const &txn : ssn->_transactions) {
      max_content_length = std::max<size_t>(max_content_length, txn._req._content_size);
    }
  }
  auto const session_count = Session_List.size();
  errata.info("Parsed {} transactions in {} sessions.", transaction_count, session_count);
  HttpHeader::set_max_content_length(max_content_length);

  Session::init(transaction_count);
  errata.diag(R"(Initializing TLS)");
  TLSSession::init();
  errata.diag(R"(Initialize H2)");
  H2Session::init(&process_exit_code);

  auto sleep_limit_arg{arguments.get("sleep-limit")};
  microseconds sleep_limit = 500ms;
  if (sleep_limit_arg.size() == 1) {
    sleep_limit = microseconds(atoi(sleep_limit_arg[0].c_str()));
  }

  auto thread_limit_arg{arguments.get("thread-limit")};
  if (thread_limit_arg.size() == 1) {
    auto const thread_limit_int = atoi(thread_limit_arg[0].c_str());
    Client_Thread_Pool.set_max_threads(thread_limit_int);
  }

  // A value of zero means to run the transactions as fast as possible.
  double rate_multiplier = 0.0;
  auto rate_arg{arguments.get("rate")};
  auto repeat_arg{arguments.get("repeat")};
  int repeat_count = 0;

  TimePoint recording_start_time;
  if (!Session_List.empty()) {
    // Note that, from above, the sessions are sorted from earliest session
    // _start time to latest. Therefore the first Ssn is the earliest one.
    recording_start_time = Session_List.front()->_start;
  }
  // The amount of time that the recording took will be considered approximated
  // by the difference of the time of the last session and the time of the
  // first session. In reality it would be more accurate to have the time the
  // last session ended rather than started, but this is hopefully close enough.
  auto recording_duration = 0ns;
  if (!Session_List.empty()) {
    recording_duration = Session_List.back()->_start - recording_start_time;
  }
  auto sleep_time = 0us;
  bool use_sleep_time = false;
  if (rate_arg.size() == 1 && !Session_List.empty()) {
    int target_rate = atoi(rate_arg[0].c_str());
    if (target_rate == 0.0) {
      rate_multiplier = 0.0;
    } else {
      // We want to determine our multiplier for how long we should sleep
      // between each session. We have recorded in the replay file a time stamp
      // for each session. If that's not in the replay file, we assume 1
      // microsecond between each session. We start with the basic rate
      // equation:
      //
      // recorded_rate * time = num_transactions
      //
      // Where for us:
      //   * recorded_rate is number of transactions per microsecond.
      //   * t is in microseconds
      //
      // Thus the rate at the time of the replay per the recorded capture is:
      //
      // recorded_rate = num_transactions / time
      //
      // Our multiplier is, conceptually, simply the ratio of the recorded
      // rate to the target rate:
      //
      // multiplier = recorded_rate / target_rate
      //
      // Thus if the recorded rate is 5,000 rps, and the target rate is 10,000
      // rps, then the delay between each session should be halved via
      // multiplying by 0.5.
      //
      // However, the recorded rate is in microseconds and the user provides a
      // rate per second, so we have to muliply the recorded rate by 1,000,000
      // to normalize both rates to a per second unit:
      //
      // multiplier = (recorded_rate * 1,000,000) / target_rate
      if (recording_duration == 0ns) {
        // Session timing data is not provided, but the user wants a specific
        // rate. We simply need to calculate how much time to sleep between
        // sessions. To simplify the math, our "recording_duration" will simply be
        // the session_count, i.e, 1 microsecond for each session.
        auto const sleep_time_raw =
            static_cast<int>((transaction_count * 1'000'000.0) / (target_rate * session_count));
        auto sleep_time = microseconds(sleep_time_raw);
        sleep_time = std::min(sleep_time, sleep_limit);
        use_sleep_time = true;
      } else {
        rate_multiplier = (transaction_count * 1'000'000.0) /
                          (target_rate * duration_cast<microseconds>(recording_duration).count());
      }
    }
    errata.info(
        "Rate multiplier: {}, per session sleep time: {} ms, transaction count: {}, recording "
        "duration: {} ms",
        rate_multiplier,
        duration_cast<milliseconds>(sleep_time).count(),
        transaction_count,
        duration_cast<milliseconds>(recording_duration).count());
  }

  if (repeat_arg.size() == 1) {
    repeat_count = atoi(repeat_arg[0].c_str());
  } else {
    repeat_count = 1;
  }

  auto replay_start_time = ClockType::now();
  unsigned n_ssn = 0;
  unsigned n_txn = 0;
  for (int i = 0; i < repeat_count; i++) {
    auto const this_iteration_start_time = ClockType::now();
    for (auto ssn : Session_List) {
      if (ssn->_user_specified_delay_duration > 0us) {
        sleep_for(ssn->_user_specified_delay_duration);
      } else if (use_sleep_time) {
        sleep_for(sleep_time);
        // Transactions will be run with no rate limiting.
      } else if (rate_multiplier != 0) {
        ssn->_rate_multiplier = rate_multiplier;
        auto const curtime = ClockType::now();
        auto const start_offset = ssn->_start - recording_start_time;
        auto const nexttime = (rate_multiplier * start_offset) + this_iteration_start_time;
        if (nexttime > curtime) {
          sleep_for(std::min(sleep_limit, duration_cast<microseconds>(nexttime - curtime)));
        }
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

  auto replay_duration = duration_cast<milliseconds>(ClockType::now() - replay_start_time);
  errata.info(
      "{} transactions in {} sessions (reuse {:.2f}) in {} milliseconds ({:.3f} / "
      "millisecond).",
      n_txn,
      n_ssn,
      n_txn / static_cast<double>(n_ssn),
      replay_duration.count(),
      n_txn / static_cast<double>(replay_duration.count()));

  TLSSession::terminate();
  H2Session::terminate();
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

  static std::string const thread_limit_description =
      std::string("Specify the maximum number of threads to use for handling "
                  "concurrent connections. Default: ") +
      std::to_string(ThreadPool::default_max_threads);

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
      .add_option("--thread-limit", "", thread_limit_description.c_str(), "", 1, "")
      .add_option(
          "--rate",
          "",
          "Specify desired transacton rate (requests per second). 1 means to "
          "run at the rate recorded in the replay file. 0 means to run the "
          "transactions as fast as possible. The default is 0.",
          "",
          1,
          "")
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

  std::string verbosity = "info";
  if (const auto verbose_argument{engine.arguments.get("verbose")}; verbose_argument) {
    verbosity = verbose_argument.value();
  }
  if (!configure_logging(verbosity)) {
    std::cerr << "Unrecognized verbosity option: " << verbosity << std::endl;
    return 1;
  }

  engine.arguments.invoke();
  return engine.process_exit_code;
}
