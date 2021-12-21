/** @file
 * Declaration of YamlParser, the YAML file parsing class.
 *
 * Copyright 2022, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <unordered_set>

#include "yaml-cpp/yaml.h"

#include "swoc/BufferWriter.h"
#include "swoc/Errata.h"
#include "swoc/MemArena.h"
#include "swoc/TextView.h"
#include "swoc/bwf_base.h"
#include "swoc/swoc_file.h"

class HttpFields;
class HttpHeader;
class RuleCheck;

// Delay specification units.
static const std::string MICROSECONDS_SUFFIX{"us"};
static const std::string MILLISECONDS_SUFFIX{"ms"};
static const std::string SECONDS_SUFFIX{"s"};

// Definitions of keys in the CONFIG files.
// These need to be @c std::string or the node look up will construct a @c
// std::string.
static const std::string YAML_META_KEY{"meta"};
static const std::string YAML_GLOBALS_KEY{"global-field-rules"};
static const std::string YAML_SSN_KEY{"sessions"};
static const std::string YAML_TIME_START_KEY{"connection-time"};
static const std::string YAML_TIME_DELAY_KEY{"delay"};
static const std::string YAML_SSN_PROTOCOL_KEY{"protocol"};
static const std::string YAML_SSN_PROTOCOL_NAME{"name"};
static const std::string YAML_SSN_PROTOCOL_VERSION{"version"};
static const std::string YAML_SSN_PROTOCOL_TLS_NAME{"tls"};
static const std::string YAML_SSN_PROTOCOL_HTTP_NAME{"http"};
static const std::string YAML_SSN_PROTOCOL_PP_NAME{"proxy-protocol"};
static const std::string YAML_SSN_PP_SRC_ADDR_KEY{"src-addr"};
static const std::string YAML_SSN_PP_DST_ADDR_KEY{"dst-addr"};
static const std::string YAML_SSN_TLS_SNI_KEY{"sni"};
static const std::string YAML_SSN_TLS_ALPN_PROTOCOLS_KEY{"alpn-protocols"};
static const std::string YAML_SSN_TLS_VERIFY_MODE_KEY{"verify-mode"};
static const std::string YAML_SSN_TLS_REQUEST_CERTIFICATE_KEY{"request-certificate"};
static const std::string YAML_SSN_TLS_PROXY_PROVIDED_CERTIFICATE_KEY{"proxy-provided-certificate"};
static const std::string YAML_TXN_KEY{"transactions"};
static const std::string YAML_CLIENT_REQ_KEY{"client-request"};
static const std::string YAML_PROXY_REQ_KEY{"proxy-request"};
static const std::string YAML_SERVER_RSP_KEY{"server-response"};
static const std::string YAML_PROXY_RSP_KEY{"proxy-response"};
static const std::string YAML_ALL_MESSAGES_KEY{"all"};
static const std::string YAML_FRAMES_KEY{"frames"};
static const std::string YAML_ERROR_CODE_KEY{"error-code"};
static const std::string YAML_HDR_KEY{"headers"};
static const std::string YAML_TRAILER_KEY{"trailers"};
static const std::string YAML_FIELDS_KEY{"fields"};
static const std::string YAML_HTTP_STATUS_KEY{"status"};
static const std::string YAML_HTTP_REASON_KEY{"reason"};
static const std::string YAML_HTTP_METHOD_KEY{"method"};
static const std::string YAML_HTTP_SCHEME_KEY{"scheme"};
static const std::string YAML_HTTP_VERSION_KEY{"version"};
static const std::string YAML_HTTP_AWAIT_KEY{"await"};
static const std::string YAML_HTTP2_KEY{"http2"};
static const std::string YAML_HTTP2_PSEUDO_METHOD_KEY{":method"};
static const std::string YAML_HTTP2_PSEUDO_SCHEME_KEY{":scheme"};
static const std::string YAML_HTTP2_PSEUDO_AUTHORITY_KEY{":authority"};
static const std::string YAML_HTTP2_PSEUDO_PATH_KEY{":path"};
static const std::string YAML_HTTP2_PSEUDO_STATUS_KEY{":status"};
static const std::string YAML_HTTP_STREAM_ID_KEY{"stream-id"};
static const std::string YAML_HTTP_URL_KEY{"url"};
static const std::string YAML_CONTENT_KEY{"content"};
static const std::string YAML_CONTENT_SIZE_KEY{"size"};
static const std::string YAML_CONTENT_DATA_KEY{"data"};
static const std::string YAML_CONTENT_VERIFY_KEY{"verify"};
static const std::string YAML_CONTENT_ENCODING_KEY{"encoding"};
static const std::string YAML_CONTENT_TRANSFER_KEY{"transfer"};

static constexpr size_t YAML_RULE_KEY_INDEX{0};
static constexpr size_t YAML_RULE_VALUE_INDEX{1};
static constexpr size_t YAML_RULE_TYPE_INDEX{2};

static const std::string YAML_RULE_VALUE_MAP_KEY{"value"};
static const std::string YAML_RULE_TYPE_MAP_KEY{"as"};
static const std::string YAML_RULE_TYPE_MAP_KEY_NOT{"not"};
static const std::string YAML_RULE_CASE_MAP_KEY{"case"};

static constexpr swoc::TextView FIELD_HOST{"host"};
static constexpr swoc::TextView FIELD_EXPECT{"expect"};

static constexpr bool ASSUME_EQUALITY_RULE = true;

// YAML support utilities.
namespace swoc
{
inline BufferWriter &
bwformat(BufferWriter &w, bwf::Spec const & /* spec */, YAML::Mark const &mark)
{
  return w.print("line {}", mark.line);
}
} // namespace swoc

/** Interpret a chrono delay specified from a string.
 *
 * This function interprets the value as specified in a YAML_TIME_DELAY_KEY.
 *
 * @param[in] delay A string representation of a delay, e.g., "10s" or "10us".
 *
 * @return The interpreted version of the delay.
 */
swoc::Rv<std::chrono::microseconds> interpret_delay_string(swoc::TextView delay);

/** Parse the node for YAML_TIME_DELAY_KEY and return the delay value it
 * specifies.
 *
 * @param[in] node The parent node containing a YAML_TIME_START_KEY value.
 *
 * @return The specified delay, parsed and converted (if need be) to
 * microseconds.
 */
swoc::Rv<std::chrono::microseconds> get_delay_time(YAML::Node const &node);

struct VerificationConfig
{
  std::shared_ptr<HttpFields> txn_rules;
};

/** Protocol class for loading a replay file.
 * The client and server are expected subclass this an provide an
 * implementation.
 */
class ReplayFileHandler
{
public:
  ReplayFileHandler() = default;
  virtual ~ReplayFileHandler() = default;

  /** The rules associated with YAML_GLOBALS_KEY. */
  VerificationConfig global_config;

  virtual swoc::Errata
  file_open(swoc::file::path const &path)
  {
    _path = path.string();
    return {};
  }
  virtual swoc::Errata
  file_close()
  {
    return {};
  }
  virtual swoc::Errata
  ssn_open(YAML::Node const & /* node */)
  {
    return {};
  }
  virtual swoc::Errata
  ssn_close()
  {
    return {};
  }

  /** Open the transaction node.
   *
   * @param node Transaction node.
   * @return Errors, if any.
   *
   * This is required to do any base validation of the transaction such as
   * verifying required keys.
   */
  virtual swoc::Errata
  txn_open(YAML::Node const & /* node */)
  {
    return {};
  }

  virtual swoc::Errata
  txn_close()
  {
    return {};
  }
  virtual swoc::Errata
  client_request(YAML::Node const & /* node */)
  {
    return {};
  }
  virtual swoc::Errata
  proxy_request(YAML::Node const & /* node */)
  {
    return {};
  }
  virtual swoc::Errata
  server_response(YAML::Node const & /* node */)
  {
    return {};
  }
  virtual swoc::Errata
  proxy_response(YAML::Node const & /* node */)
  {
    return {};
  }
  virtual swoc::Errata
  apply_to_all_messages(HttpFields const & /* all_headers */)
  {
    return {};
  }

protected:
  /** Parse the "protocol" node for the requested protocol.
   *
   * Keep in mind that the "protocol" node is the protocol stack containing a
   * set of protocol descriptions, such as "tcp", "tls", etc.
   *
   * @param[in] protocol_node The "protocol" node from which to search for a
   * specified protocol node.
   *
   * @para[in] protocol_name The key for the protocol node to return.
   *
   * @return The protocol node or a node whose type is "YAML::NodeType::Undefined"
   * if the node did not exist in the protocol map.
   */
  static swoc::Rv<YAML::Node const> parse_for_protocol_node(
      YAML::Node const &protocol_node,
      std::string_view protocol_name);

  /** Parse a "tls" node for an "sni" key and return the value.
   *
   * @param[in] tls_node The tls node from which to parse the SNI.
   *
   * @return The SNI from the "tls" node or empty string if it doesn't exist.
   */
  static swoc::Rv<std::string> parse_sni(YAML::Node const &tls_node);

  /** Parse a "tls" node for the given verify-mode node value.
   *
   * @param[in] tls_node The tls node from which to parse the verify-mode.
   *
   * @return The value of verify-mode, or -1 if it doesn't exist.
   */
  static swoc::Rv<int> parse_verify_mode(YAML::Node const &tls_node);

  static swoc::Rv<std::string> parse_alpn_protocols_node(YAML::Node const &tls_node);

protected:
  /** The replay file associated with this handler.
   */
  swoc::file::path _path;
};

/** The class responsible for parsing YAML message nodes. */
class YamlParser
{
public:
  /** Parse the YAML file executing callbacks into a handler.
   *
   * @param[in] path The path to the YAML file to parse.
   *
   * @param[in] handler Conceptually, this contains the set of callbacks to
   *   dispatch into as the YAML file is parsed.
   *
   * @return Any errata from parsing the file.
   */
  static swoc::Errata load_replay_file(swoc::file::path const &path, ReplayFileHandler &handler);

  using loader_t = std::function<swoc::Errata(swoc::file::path const &)>;

  /** Parse the specified YAML file(s).
   *
   * @param[in] path The path to the file or directory containing YAML
   *   files to parse. Note this may actually be a path to a single file.
   *
   * @param[in] loader The function to use for each file in path.
   *
   * @param[in] n_threads The number of threads to use to parse the files in
   *   path.
   *
   * @return Any errata from parsing the file.
   */
  static swoc::Errata
  load_replay_files(swoc::file::path const &path, loader_t loader, int n_threads = 10);

  /** Populate an HTTP message from a YAML node.
   *
   * @param[in] node The YAML node from which to parse HTTP message information.
   * @param[out] message The HTTP message to populate from node.
   *
   * @return Any errata from parsing the node.
   */
  static swoc::Errata populate_http_message(YAML::Node const &node, HttpHeader &message);

  /** Populate a HTTP fields from a YAML node.
   *
   * @param[in] node The YAML node from which to parse HTTP field information.
   * @param[out] fields The HTTP fields to populate from node.
   *
   * @return Any errata from parsing the node.
   */
  static swoc::Errata parse_global_rules(YAML::Node const &node, HttpFields &fields);

private:
  /** Indicate that parsing has started.
   */
  static swoc::Errata parsing_is_started();

  /** Indicate that parsing is completed.
   *
   * This is helpful for indicating the end of the parsing phase. Functionally
   * this means that string localization should be completed at this point.
   */
  static swoc::Errata parsing_is_done();

  /** Process HTTP/2 pseudo headers from the message node.
   *
   * @param[in] node The YAML node from which to parse HTTP pseudo headers.
   * @param[out] message The object to populate with pseudo headers.
   *
   * @return Any errata from parsing the node.
   */
  static swoc::Errata process_pseudo_headers(YAML::Node const &node, HttpHeader &message);

  /** Process fields and verification rules from the fields node.
   *
   * @param[in] node The YAML node containing fields.
   * @param[out] fields The object to populate with fields and rules.
   *
   * @return Any errata from parsing the node.
   */
  static swoc::Errata parse_fields_and_rules(
      YAML::Node const &fields_rules,
      HttpFields &fields,
      bool assume_equality_rule);

  /** Process URL information from the node
   *
   * @param[in] node The YAML node URL information.
   * @param[out] fields The object to populate with URL data from node.
   *
   * @return Any errata from parsing the node.
   */
  static swoc::Errata
  parse_url_rules(YAML::Node const &url_rules, HttpFields &fields, bool assume_equality_rule);

  /** Process URL information from the node
   *
   * @param[in] node The YAML node for body verification.
   * @param[out] rule_check The object to populate with body verification rule from node.
   * @param[in] content Optional content from data node if present.
   *
   * @return Any errata from parsing the node.
   */
  static swoc::Errata parse_body_verification(
      YAML::Node const &node,
      std::shared_ptr<RuleCheck> &rule_check,
      bool assume_equality_rule,
      swoc::TextView content = "");

private:
  using ClockType = std::chrono::system_clock;
  using TimePoint = std::chrono::time_point<ClockType, std::chrono::nanoseconds>;
  static TimePoint _parsing_start_time;
};
