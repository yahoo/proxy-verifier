/** @file
 * Unit tests for HttpReplay.h.
 *
 * Copyright 2026, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "catch.hpp"
#include "core/Localizer.h"
#include "core/ProxyVerifier.h"
#include "core/YamlParser.h"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <stdlib.h>
#include <string>
#include <thread>
#include <vector>

using namespace std::literals;
using std::chrono::microseconds;

constexpr bool IS_VALID = true;

namespace
{
class ReplayFileHandlerTester : public ReplayFileHandler
{
public:
  using ReplayFileHandler::HttpProtocol;
  using ReplayFileHandler::ParsedProtocolNode;
  using ReplayFileHandler::parse_protocol_node;
};

class FailingTxnOpenHandler : public ReplayFileHandler
{
public:
  swoc::Errata
  txn_open(YAML::Node const & /* node */) override
  {
    swoc::Errata errata;
    errata.note(S_ERROR, "Synthetic transaction open failure.");
    ++txn_open_calls;
    return errata;
  }

  swoc::Errata
  client_request(YAML::Node const & /* node */) override
  {
    ++client_request_calls;
    return {};
  }

  swoc::Errata
  txn_close() override
  {
    ++txn_close_calls;
    return {};
  }

  int txn_open_calls = 0;
  int client_request_calls = 0;
  int txn_close_calls = 0;
};

class SessionTrackingHandler : public ReplayFileHandler
{
public:
  swoc::Errata
  ssn_open(YAML::Node const & /* node */) override
  {
    ++ssn_open_calls;
    return {};
  }

  swoc::Errata
  ssn_close() override
  {
    ++ssn_close_calls;
    return {};
  }

  int ssn_open_calls = 0;
  int ssn_close_calls = 0;
};

class CountingReplayFileHandler : public ReplayFileHandler
{
public:
  swoc::Errata
  ssn_open(YAML::Node const & /* node */) override
  {
    ++ssn_open_calls;
    return {};
  }

  swoc::Errata
  txn_open(YAML::Node const & /* node */) override
  {
    ++txn_open_calls;
    return {};
  }

  swoc::Errata
  client_request(YAML::Node const &node) override
  {
    ++client_request_calls;
    HttpHeader message;
    message.set_is_request();
    return YamlParser::populate_http_message(node, message);
  }

  int ssn_open_calls = 0;
  int txn_open_calls = 0;
  int client_request_calls = 0;
};

class CapturingReplayFileHandler : public ReplayFileHandler
{
public:
  swoc::Errata
  client_request(YAML::Node const &node) override
  {
    request.set_is_request();
    return YamlParser::populate_http_message(node, request);
  }

  HttpHeader request;
};

class LocalizerPhaseGuard
{
public:
  LocalizerPhaseGuard() : m_was_frozen(Localizer::localization_is_frozen())
  {
    Localizer::start_localization();
  }

  ~LocalizerPhaseGuard()
  {
    if (m_was_frozen) {
      Localizer::freeze_localization();
    } else {
      Localizer::start_localization();
    }
  }

private:
  bool m_was_frozen = false;
};

class TemporaryDirectory
{
public:
  TemporaryDirectory()
  {
    std::error_code ec;
    auto const temp_dir = std::filesystem::temp_directory_path(ec);
    REQUIRE(!ec);

    auto const template_path = (temp_dir / "pv-yamlparser-XXXXXX").string();
    std::vector<char> dir_template(template_path.begin(), template_path.end());
    dir_template.push_back('\0');

    auto *created_dir = ::mkdtemp(dir_template.data());
    REQUIRE(created_dir != nullptr);
    path = created_dir;
  }

  ~TemporaryDirectory()
  {
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
  }

  std::filesystem::path path;
};
} // namespace

struct ParseDelaySpecificationTestCase
{
  std::string const description;
  std::string const delay_specification;

  bool is_valid;
  microseconds const expected_delay;
};

std::initializer_list<ParseDelaySpecificationTestCase> parse_delay_specification_test_cases = {
    {
        .description = "Verify a microseconds specification.",
        .delay_specification = "10us",
        .is_valid = IS_VALID,
        .expected_delay = 10us,
    },
    {
        .description = "Verify a milliseconds specification.",
        .delay_specification = "12ms",
        .is_valid = IS_VALID,
        .expected_delay = 12'000us,
    },
    {
        .description = "Verify a seconds specification.",
        .delay_specification = "22s",
        .is_valid = IS_VALID,
        .expected_delay = 22'000'000us,
    },
    {
        .description = "Verify that the value 0 is allowed.",
        .delay_specification = "0us",
        .is_valid = IS_VALID,
        .expected_delay = 0us,
    },
    {
        .description = "Verify correct handling of surrounding white space.",
        .delay_specification = " \t  8us\t\n",
        .is_valid = IS_VALID,
        .expected_delay = 8us,
    },
    {
        .description = "Verify correct handling of internal white space.",
        .delay_specification = "8  \t  us",
        .is_valid = IS_VALID,
        .expected_delay = 8us,
    },
    {
        .description = "Verify correct handling of internal and surrounding white space.",
        .delay_specification = "\t  8  \t  us  \t \r\n",
        .is_valid = IS_VALID,
        .expected_delay = 8us,
    },

    /*
     * Failure parsing cases.
     */
    {
        .description = "Verify an empty string fails parsing.",
        .delay_specification = "",
        .is_valid = !IS_VALID,
        .expected_delay = 0us,
    },
    {
        .description = "Verify omission of a suffix fails parsing.",
        .delay_specification = "10",
        .is_valid = !IS_VALID,
        .expected_delay = 0us,
    },
    {
        .description = "Verify omission of a number fails parsing.",
        .delay_specification = "us",
        .is_valid = !IS_VALID,
        .expected_delay = 0us,
    },
    {
        .description = "Verify a decimal value fails parsing.",
        .delay_specification = "10.2ms",
        .is_valid = !IS_VALID,
        .expected_delay = 0us,
    },
    {
        .description = "Verify an unrecognized suffix fails parsing.",
        .delay_specification = "10ns",
        .is_valid = !IS_VALID,
        .expected_delay = 0us,
    },
};

TEST_CASE("Verify interpretation of delay specification strings", "[delay_specification]")
{
  auto const &test_case = GENERATE(values(parse_delay_specification_test_cases));
  auto &&[parsed_delay_value, delay_errata] = interpret_delay_string(test_case.delay_specification);
  if (test_case.is_valid) {
    CHECK(delay_errata.is_ok());
    CHECK(parsed_delay_value == test_case.expected_delay);
  } else {
    CHECK(parsed_delay_value == 0us);
    CHECK_FALSE(delay_errata.is_ok());
  }
}

struct ParseOnConnectActionTestCase
{
  std::string const description;
  std::string const yaml;
  bool is_valid;
  Txn::ConnectAction const expected_action;
};

std::initializer_list<ParseOnConnectActionTestCase> parse_on_connect_action_test_cases = {
    {
        .description = "Verify the on_connect directive defaults to accept.",
        .yaml = "{}",
        .is_valid = IS_VALID,
        .expected_action = Txn::ConnectAction::ACCEPT,
    },
    {
        .description = "Verify accept is parsed.",
        .yaml = "{ on_connect: accept }",
        .is_valid = IS_VALID,
        .expected_action = Txn::ConnectAction::ACCEPT,
    },
    {
        .description = "Verify refuse is parsed.",
        .yaml = "{ on_connect: refuse }",
        .is_valid = IS_VALID,
        .expected_action = Txn::ConnectAction::REFUSE,
    },
    {
        .description = "Verify reset is parsed.",
        .yaml = "{ on_connect: reset }",
        .is_valid = IS_VALID,
        .expected_action = Txn::ConnectAction::RESET,
    },
    {
        .description = "Verify invalid values fail parsing.",
        .yaml = "{ on_connect: later }",
        .is_valid = !IS_VALID,
        .expected_action = Txn::ConnectAction::ACCEPT,
    },
    {
        .description = "Verify non-scalar values fail parsing.",
        .yaml = "{ on_connect: [reset] }",
        .is_valid = !IS_VALID,
        .expected_action = Txn::ConnectAction::ACCEPT,
    },
};

TEST_CASE("Verify interpretation of on_connect actions", "[on_connect]")
{
  auto const &test_case = GENERATE(values(parse_on_connect_action_test_cases));
  auto const node = YAML::Load(test_case.yaml);
  auto &&[action, action_errata] = get_on_connect_action(node);
  if (test_case.is_valid) {
    CHECK(action_errata.is_ok());
    CHECK(action == test_case.expected_action);
  } else {
    CHECK_FALSE(action_errata.is_ok());
  }
}

struct ServerResponseValidationTestCase
{
  std::string const description;
  std::string const yaml;
  bool is_valid;
};

std::initializer_list<ServerResponseValidationTestCase> server_response_validation_test_cases = {
    {
        .description = "Verify status is required without on_connect.",
        .yaml = "{ reason: OK }",
        .is_valid = !IS_VALID,
    },
    {
        .description = "Verify status is required with on_connect accept.",
        .yaml = "{ on_connect: accept }",
        .is_valid = !IS_VALID,
    },
    {
        .description = "Verify status is optional with on_connect refuse.",
        .yaml = "{ on_connect: refuse }",
        .is_valid = IS_VALID,
    },
    {
        .description = "Verify status is optional with on_connect reset.",
        .yaml = "{ on_connect: reset }",
        .is_valid = IS_VALID,
    },
};

TEST_CASE("Verify server-response validation for on_connect", "[on_connect]")
{
  auto const &test_case = GENERATE(values(server_response_validation_test_cases));
  auto const node = YAML::Load(test_case.yaml);
  HttpHeader response{true};
  response.set_is_response();
  auto errata = YamlParser::populate_http_message(node, response);
  auto &&[action, action_errata] = get_on_connect_action(node);
  errata.note(std::move(action_errata));
  if (response._status == 0 && action == Txn::ConnectAction::ACCEPT) {
    errata.note(S_ERROR, "server-response node is missing a required status.");
  }

  if (test_case.is_valid) {
    CHECK(errata.is_ok());
  } else {
    CHECK_FALSE(errata.is_ok());
  }
}

TEST_CASE("Verify verbose protocol sequences parse into a common protocol object", "[protocol]")
{
  auto const protocol_node = YAML::Load(R"(
[
  { name: http, version: 2 },
  { name: tls, sni: test_sni, verify-mode: 1 },
  { name: proxy-protocol, version: 2, src-addr: 127.0.0.1:1000, dst-addr: 127.0.0.1:2000 },
  { name: tcp },
  { name: ip }
]
)");

  ReplayFileHandlerTester::ParsedProtocolNode parsed_protocol{protocol_node};
  REQUIRE(parsed_protocol.is_valid());
  CHECK(parsed_protocol.get_http_protocol() == ReplayFileHandlerTester::HttpProtocol::HTTP2);
  CHECK(parsed_protocol.is_tls());
  REQUIRE(parsed_protocol.get_tls_sni_name().has_value());
  CHECK(parsed_protocol.get_tls_sni_name().value() == "test_sni");
  REQUIRE(parsed_protocol.get_tls_verify_mode().has_value());
  CHECK(parsed_protocol.get_tls_verify_mode().value() == 1);
  REQUIRE(parsed_protocol.get_proxy_protocol_version().has_value());
  CHECK(parsed_protocol.get_proxy_protocol_version().value() == 2);
  REQUIRE(parsed_protocol.get_proxy_protocol_src_addr().has_value());
  CHECK(parsed_protocol.get_proxy_protocol_src_addr().value() == "127.0.0.1:1000");
  REQUIRE(parsed_protocol.get_proxy_protocol_dst_addr().has_value());
  CHECK(parsed_protocol.get_proxy_protocol_dst_addr().value() == "127.0.0.1:2000");
}

TEST_CASE("Verify protocol stack shorthand parses into a common protocol object", "[protocol]")
{
  auto const protocol_node = YAML::Load(R"(
stack: http2
tls:
  sni: test_sni
  verify-mode: 1
proxy-protocol: 2
)");

  auto const parsed_protocol = ReplayFileHandlerTester::parse_protocol_node(protocol_node);
  REQUIRE(parsed_protocol.is_ok());
  CHECK(
      parsed_protocol.result().get_http_protocol() == ReplayFileHandlerTester::HttpProtocol::HTTP2);
  CHECK(parsed_protocol.result().is_tls());
  REQUIRE(parsed_protocol.result().get_tls_sni_name().has_value());
  CHECK(parsed_protocol.result().get_tls_sni_name().value() == "test_sni");
  REQUIRE(parsed_protocol.result().get_tls_verify_mode().has_value());
  CHECK(parsed_protocol.result().get_tls_verify_mode().value() == 1);
  REQUIRE(parsed_protocol.result().get_proxy_protocol_version().has_value());
  CHECK(parsed_protocol.result().get_proxy_protocol_version().value() == 2);
}

TEST_CASE("Verify http stack synthesizes HTTP/1 defaults", "[protocol]")
{
  auto const protocol_node = YAML::Load("{ stack: http }");
  ReplayFileHandlerTester::ParsedProtocolNode parsed_protocol{protocol_node};
  REQUIRE(parsed_protocol.is_valid());
  CHECK(parsed_protocol.get_http_protocol() == ReplayFileHandlerTester::HttpProtocol::HTTP);
  CHECK_FALSE(parsed_protocol.is_tls());
}

TEST_CASE("Verify https stack synthesizes TLS defaults", "[protocol]")
{
  auto const protocol_node = YAML::Load("{ stack: https }");
  ReplayFileHandlerTester::ParsedProtocolNode parsed_protocol{protocol_node};
  REQUIRE(parsed_protocol.is_valid());
  CHECK(parsed_protocol.get_http_protocol() == ReplayFileHandlerTester::HttpProtocol::HTTPS);
  CHECK(parsed_protocol.is_tls());
}

TEST_CASE("Verify conflicting protocol stack and TLS options are rejected", "[protocol]")
{
  SECTION("flattened TLS shorthand")
  {
    auto const protocol_node = YAML::Load("{ stack: http2, sni: test_sni }");
    ReplayFileHandlerTester::ParsedProtocolNode parsed_protocol{protocol_node};
    CHECK_FALSE(parsed_protocol.is_valid());
  }

  SECTION("explicit tls map")
  {
    auto const protocol_node = YAML::Load("{ stack: http, tls: { sni: test_sni } }");
    ReplayFileHandlerTester::ParsedProtocolNode parsed_protocol{protocol_node};
    CHECK_FALSE(parsed_protocol.is_valid());
  }

  SECTION("explicit http layer override")
  {
    auto const protocol_node = YAML::Load("{ stack: http2, http: { version: 3 } }");
    ReplayFileHandlerTester::ParsedProtocolNode parsed_protocol{protocol_node};
    CHECK_FALSE(parsed_protocol.is_valid());
  }
}

TEST_CASE("Verify explicit TLS maps can be combined with stack shorthand", "[protocol]")
{
  auto const protocol_node = YAML::Load(R"(
stack: http2
tls:
  sni: test_sni_with_map
  request-certificate: true
)");

  auto const parsed_protocol = ReplayFileHandlerTester::parse_protocol_node(protocol_node);
  REQUIRE(parsed_protocol.is_ok());
  CHECK(parsed_protocol.result().is_tls());
  REQUIRE(parsed_protocol.result().get_tls_sni_name().has_value());
  CHECK(parsed_protocol.result().get_tls_sni_name().value() == "test_sni_with_map");
  REQUIRE(parsed_protocol.result().should_request_certificate().has_value());
  CHECK(parsed_protocol.result().should_request_certificate().value());
}

TEST_CASE("Verify transaction callbacks are skipped after transaction open failure", "[yaml]")
{
  auto const content = R"(
meta:
  version: "1.0"
sessions:
  - transactions:
      - client-request:
          method: GET
          url: http://example.com/
          version: "1.1"
          headers:
            fields:
              - [ Host, example.com ]
)";

  FailingTxnOpenHandler handler;
  auto errata = YamlParser::load_replay_file(swoc::file::path{"synthetic.yaml"}, content, handler);

  CHECK_FALSE(errata.is_ok());
  CHECK(handler.txn_open_calls == 1);
  CHECK(handler.client_request_calls == 0);
  CHECK(handler.txn_close_calls == 0);
}

TEST_CASE("Verify malformed transaction lists fail the session cleanly", "[yaml]")
{
  auto const content = R"(
meta:
  version: "1.0"
sessions:
  - transactions: {}
)";

  SessionTrackingHandler handler;
  auto errata = YamlParser::load_replay_file(swoc::file::path{"synthetic.yaml"}, content, handler);

  CHECK_FALSE(errata.is_ok());
  CHECK(handler.ssn_open_calls == 1);
  CHECK(handler.ssn_close_calls == 1);
}

TEST_CASE("Verify concise protocol maps reject non-scalar keys", "[protocol]")
{
  auto const protocol_node = YAML::Load(R"(
? [stack]
: http
)");

  auto const parsed_protocol = ReplayFileHandlerTester::parse_protocol_node(protocol_node);
  CHECK_FALSE(parsed_protocol.is_ok());
}

TEST_CASE("Verify Localizer supports concurrent localization", "[localizer]")
{
  LocalizerPhaseGuard localizer_phase;
  static constexpr int thread_count = 8;
  static constexpr int iterations = 256;

  struct LocalizerThreadResult
  {
    swoc::TextView lower;
    swoc::TextView upper;
    swoc::TextView plain;
    std::string expected_plain;
  };

  std::vector<LocalizerThreadResult> results(thread_count);
  std::vector<std::thread> threads;
  threads.reserve(thread_count);

  for (int i = 0; i < thread_count; ++i) {
    threads.emplace_back([&, i]() {
      for (int iteration = 0; iteration < iterations; ++iteration) {
        auto const lower_input =
            iteration % 2 == 0 ? swoc::TextView{"HOST"} : swoc::TextView{"Host"};
        auto const upper_input = iteration % 2 == 0 ? swoc::TextView{"content-length"} :
                                                      swoc::TextView{"Content-Length"};
        results[i].lower = Localizer::localize_lower(lower_input);
        results[i].upper = Localizer::localize_upper(upper_input);

        results[i].expected_plain =
            "thread-" + std::to_string(i) + "-iteration-" + std::to_string(iteration);
        results[i].plain = Localizer::localize(swoc::TextView{results[i].expected_plain});
      }
    });
  }

  for (auto &thread : threads) {
    thread.join();
  }
  Localizer::freeze_localization();

  for (auto const &result : results) {
    CHECK(result.lower == "host");
    CHECK(result.upper == "CONTENT-LENGTH");
    CHECK(std::string(result.plain.data(), result.plain.size()) == result.expected_plain);
  }
  for (int i = 1; i < thread_count; ++i) {
    CHECK(results[i].lower.data() == results[0].lower.data());
    CHECK(results[i].upper.data() == results[0].upper.data());
  }
}

TEST_CASE("Verify load_replay_files parses all files with multiple parser threads", "[yaml]")
{
  LocalizerPhaseGuard localizer_phase;
  TemporaryDirectory temp_dir;

  static constexpr int file_count = 12;
  static constexpr int sessions_per_file = 2;
  static constexpr int transactions_per_session = 3;

  for (int file_index = 0; file_index < file_count; ++file_index) {
    auto const file_path = temp_dir.path / ("replay_" + std::to_string(file_index) + ".json");
    std::ofstream file(file_path);
    REQUIRE(file.is_open());
    file << "{\n"
            "  \"meta\": {\"version\": \"1.0\"},\n"
            "  \"sessions\": [\n";
    for (int session_index = 0; session_index < sessions_per_file; ++session_index) {
      file << "    {\n"
              "      \"transactions\": [\n";
      for (int transaction_index = 0; transaction_index < transactions_per_session;
           ++transaction_index) {
        file << "        {\n"
                "          \"client-request\": {\n"
                "            \"method\": \"GET\",\n"
                "            \"url\": \"http://example.com/"
             << file_index << "/" << session_index << "/" << transaction_index
             << "\",\n"
                "            \"version\": \"1.1\",\n"
                "            \"headers\": {\n"
                "              \"fields\": [[\"Host\", \"example.com\"]]\n"
                "            }\n"
                "          }\n"
                "        }";
        if (transaction_index + 1 < transactions_per_session) {
          file << ",";
        }
        file << "\n";
      }
      file << "      ]\n"
              "    }";
      if (session_index + 1 < sessions_per_file) {
        file << ",";
      }
      file << "\n";
    }
    file << "  ]\n"
            "}\n";
  }

  std::atomic<int> parsed_files = 0;
  std::atomic<int> parsed_sessions = 0;
  std::atomic<int> parsed_transactions = 0;
  std::atomic<int> parsed_requests = 0;
  bool shutdown_flag = false;

  auto errata = YamlParser::load_replay_files(
      swoc::file::path{temp_dir.path.string()},
      [&](swoc::file::path const &path, std::string const &content) -> swoc::Errata {
        CountingReplayFileHandler handler;
        auto file_errata = YamlParser::load_replay_file(path, content, handler);
        parsed_files.fetch_add(1);
        parsed_sessions.fetch_add(handler.ssn_open_calls);
        parsed_transactions.fetch_add(handler.txn_open_calls);
        parsed_requests.fetch_add(handler.client_request_calls);
        return file_errata;
      },
      shutdown_flag,
      1,
      4);

  CHECK(errata.is_ok());
  CHECK(parsed_files.load() == file_count);
  CHECK(parsed_sessions.load() == file_count * sessions_per_file);
  CHECK(parsed_transactions.load() == file_count * sessions_per_file * transactions_per_session);
  CHECK(parsed_requests.load() == file_count * sessions_per_file * transactions_per_session);
}

TEST_CASE(
    "Verify replay file parsing preserves merge behavior while skipping merge-free files",
    "[yaml]")
{
  auto const no_merge_content = R"(
meta:
  version: "1.0"
sessions:
  - transactions:
      - client-request:
          method: GET
          url: http://example.com/plain
          version: "1.1"
          headers:
            fields:
              - [ Host, plain.example.com ]
)";

  CapturingReplayFileHandler plain_handler;
  auto plain_errata =
      YamlParser::load_replay_file(swoc::file::path{"plain.yaml"}, no_merge_content, plain_handler);

  CHECK(plain_errata.is_ok());
  CHECK(plain_handler.request._method == "GET");
  CHECK(plain_handler.request._url == "http://example.com/plain");
  REQUIRE(plain_handler.request._fields_rules != nullptr);
  auto const plain_host = plain_handler.request._fields_rules->_fields.find("host");
  REQUIRE(plain_host != plain_handler.request._fields_rules->_fields.end());
  CHECK(plain_host->second == "plain.example.com");

  auto const merge_content = R"(
meta:
  version: "1.0"
base-request: &base-request
  method: GET
  url: http://example.com/merged
  version: "1.1"
  headers:
    fields:
      - [ Host, merged.example.com ]
sessions:
  - transactions:
      - client-request:
          <<: *base-request
)";

  CapturingReplayFileHandler merged_handler;
  auto merged_errata =
      YamlParser::load_replay_file(swoc::file::path{"merged.yaml"}, merge_content, merged_handler);

  CHECK(merged_errata.is_ok());
  CHECK(merged_handler.request._method == "GET");
  CHECK(merged_handler.request._url == "http://example.com/merged");
  REQUIRE(merged_handler.request._fields_rules != nullptr);
  auto const merged_host = merged_handler.request._fields_rules->_fields.find("host");
  REQUIRE(merged_host != merged_handler.request._fields_rules->_fields.end());
  CHECK(merged_host->second == "merged.example.com");
}
