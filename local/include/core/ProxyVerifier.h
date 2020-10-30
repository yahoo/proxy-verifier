/** @file
 * Common data structures and definitions for Proxy Verifier tools.
 *
 * Copyright 2020, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <chrono>
#include <condition_variable>
#include <deque>
#include <memory>
#include <nghttp2/nghttp2.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <string>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>

#include "yaml-cpp/yaml.h"

#include "swoc/BufferWriter.h"
#include "swoc/Errata.h"
#include "swoc/MemArena.h"
#include "swoc/TextView.h"
#include "swoc/bwf_base.h"
#include "swoc/ext/HashFNV.h"
#include "swoc/swoc_file.h"
#include "swoc/swoc_ip.h"

using clock_type = std::chrono::system_clock;

// Definitions of keys in the CONFIG files.
// These need to be @c std::string or the node look up will construct a @c
// std::string.
static const std::string YAML_META_KEY{"meta"};
static const std::string YAML_GLOBALS_KEY{"global-field-rules"};
static const std::string YAML_SSN_KEY{"sessions"};
static const std::string YAML_TIME_START_KEY{"connection-time"};
static const std::string YAML_SSN_PROTOCOL_KEY{"protocol"};
static const std::string YAML_SSN_PROTOCOL_NAME{"name"};
static const std::string YAML_SSN_PROTOCOL_VERSION{"version"};
static const std::string YAML_SSN_PROTOCOL_TLS_NAME{"tls"};
static const std::string YAML_SSN_PROTOCOL_HTTP_NAME{"http"};
static const std::string YAML_SSN_TLS_SNI_KEY{"sni"};
static const std::string YAML_SSN_TLS_VERIFY_MODE_KEY{"verify-mode"};
static const std::string YAML_SSN_TLS_REQUEST_CERTIFICATE_KEY{"request-certificate"};
static const std::string YAML_SSN_TLS_PROXY_PROVIDED_CERTIFICATE_KEY{"proxy-provided-certificate"};
static const std::string YAML_TXN_KEY{"transactions"};
static const std::string YAML_CLIENT_REQ_KEY{"client-request"};
static const std::string YAML_PROXY_REQ_KEY{"proxy-request"};
static const std::string YAML_SERVER_RSP_KEY{"server-response"};
static const std::string YAML_PROXY_RSP_KEY{"proxy-response"};
static const std::string YAML_ALL_MESSAGES_KEY{"all"};
static const std::string YAML_HDR_KEY{"headers"};
static const std::string YAML_FIELDS_KEY{"fields"};
static const std::string YAML_HTTP_VERSION_KEY{"version"};
static const std::string YAML_HTTP_STATUS_KEY{"status"};
static const std::string YAML_HTTP_REASON_KEY{"reason"};
static const std::string YAML_HTTP_METHOD_KEY{"method"};
static const std::string YAML_HTTP_SCHEME_KEY{"scheme"};
static const std::string YAML_HTTP2_KEY{"http2"};
static const std::string YAML_HTTP_STREAM_ID_KEY{"stream-id"};
static const std::string YAML_HTTP_URL_KEY{"url"};
static const std::string YAML_CONTENT_KEY{"content"};
static const std::string YAML_CONTENT_SIZE_KEY{"size"};
static const std::string YAML_CONTENT_DATA_KEY{"data"};
static const std::string YAML_CONTENT_ENCODING_KEY{"encoding"};
static const std::string YAML_CONTENT_TRANSFER_KEY{"transfer"};

static constexpr size_t YAML_RULE_NAME_KEY{0};
static constexpr size_t YAML_RULE_DATA_KEY{1};
static constexpr size_t YAML_RULE_TYPE_KEY{2};

static const std::string YAML_RULE_EQUALS{"equal"};
static const std::string YAML_RULE_PRESENCE{"present"};
static const std::string YAML_RULE_ABSENCE{"absent"};
static const std::string YAML_RULE_CONTAINS{"contains"};
static const std::string YAML_RULE_PREFIX{"prefix"};
static const std::string YAML_RULE_SUFFIX{"suffix"};

static constexpr size_t MAX_HDR_SIZE = 131072; // Max our ATS is configured for
static constexpr size_t MAX_DRAIN_BUFFER_SIZE = 1 << 20;
/// HTTP end of line.
static constexpr swoc::TextView HTTP_EOL{"\r\n"};
/// HTTP end of header.
static constexpr swoc::TextView HTTP_EOH{"\r\n\r\n"};

extern bool Verbose;

class HttpHeader;

/** Configure the process to block SIGPIPE.
 *
 * Unless we block SIGPIPE, the process abruptly stops if SSL_write triggers
 * the signal if the peer drops the connection before we write to the socket.
 * This results in an abrupt termination of the process. SSL_write will return
 * a -1 in these circumstances if the SIGPIPE doesn't interrupt it, so even
 * with the signal blocked we will still report the issue and continue
 * gracefully if SIGPIPE is raised under these circumstances.
 *
 * @return 0 on success, non-zero on failure.
 */
swoc::Rv<int> block_sigpipe();

uint64_t GetUTimestamp();

/** Configure logging.
 *
 * @param[in] verbose_argument The user-specified verbosity requested.
 */
swoc::Errata configure_logging(const std::string_view verbose_argument);

namespace swoc
{
BufferWriter &bwformat(BufferWriter &w, bwf::Spec const &spec, HttpHeader const &h);

namespace bwf
{
/** Format wrapper for @c errno.
 * This stores a copy of the argument or @c errno if an argument isn't provided.
 * The output is then formatted with the short, long, and numeric value of @c
 * errno. If the format specifier is type 'd' then just the numeric value is
 * printed.
 */
struct SSLError
{
  unsigned long _e;
  explicit SSLError(int e = ERR_peek_last_error()) : _e(e) { }
};
} // namespace bwf

BufferWriter &bwformat(BufferWriter &w, bwf::Spec const &spec, bwf::SSLError const &error);
} // namespace swoc

/**
 * Field Verification
 *
 * The objects below implement header verification. Header verification is used
 * by the verifier-server to verify header expectations for the requests coming
 * from the proxy. Correspondingly, header verification is also used by the
 * verifier-client to verify header expectations for the responses coming from
 * the proxy.
 *
 * A RuleCheck is the base class for the three types of implemented
 * verification mechanisms:
 *
 *   1. Absence: an HTTP header with the given name should not exist in the
 *   request or response being verified.
 *
 *   2. Presence: an HTTP header with the given name should exist in the
 *   request or response being verified.
 *
 *   3. Equality: an HTTP header with the given name and value should exist
 *   in the request or response being verified.
 *
 *   4. Contains: an HTTP header with the given name and the given value
 *   somewhere in the header value should exist in the request or response
 *   being verified.
 *
 *   5. Prefix: an HTTP header with the given name and the given value as
 *   a prefix in the header value should exist in the request or response
 *   being verified.
 *
 *   6. Suffix: an HTTP header with the given name and the given value as
 *   a suffix in the header value should exist in the request or response
 *   being verified.
 *
 * Thus rules are the expectations that are provided to proxy-verifier
 * concerning transactions coming out of the proxy. In the absence of a rule, no
 * verification is done.
 *
 * Rules are applied in one of three ways, presented here in order from broad
 * to specific:
 *
 *   1. Via the --strict command line argument. This tells proxy-verifier to
 * treat each proxy request header field without a verification rule as if it
 * had an equality verification value.
 *
 *   2. Via the YAML_META_KEY:YAML_GLOBALS_KEY nodes. This specifies fields and
 *   rules expected across all transactions in the json file.
 *
 *   3. Via field rules in field nodes on a per-transaction basis.
 *
 * Notice that each of these mechanisms can be overridden by a more specific
 * specification. Thus --strict sets an equality expectation on all proxy
 * request and response header fields. If, however, a node has an absence
 * rule for a field value, then the absence rule, being more specific, will
 * override the broader equality expectation set by --strict.
 *
 * As an aside, in addition to this field verification logic,
 * Session::run_transaction verifies that the proxy returns the expected
 * response status code as recorded in the replay file.
 */
struct Hash
{
  swoc::Hash64FNV1a::value_type
  operator()(swoc::TextView view) const
  {
    return swoc::Hash64FNV1a{}.hash_immediate(swoc::transform_view_of(&tolower, view));
  }
  bool
  operator()(swoc::TextView const &lhs, swoc::TextView const &rhs) const
  {
    return 0 == strcasecmp(lhs, rhs);
  }
};

class RuleCheck
{
  /// References the make_* functions below.
  using MakeRuleFunction =
      std::function<std::shared_ptr<RuleCheck>(swoc::TextView, swoc::TextView)>;
  using RuleOptions = std::unordered_map<swoc::TextView, MakeRuleFunction, Hash, Hash>;
  static RuleOptions options; ///< Returns function to construct a RuleCheck child class for a
                              ///< given rule type ("equals", "presence", "absence",
                              ///< "contains", "prefix", "or "suffix")

  using MakeDuplicateFieldRuleFunction =
      std::function<std::shared_ptr<RuleCheck>(swoc::TextView, std::list<swoc::TextView> &&)>;
  using DuplicateFieldRuleOptions =
      std::unordered_map<swoc::TextView, MakeDuplicateFieldRuleFunction, Hash, Hash>;
  static DuplicateFieldRuleOptions
      duplicate_field_options; ///< Returns function to construct a RuleCheck
                               ///< child class for a given duplicate field rule
                               ///< type ("equals", "presence", "absence",
                               ///< "contains", "prefix", "or "suffix")

protected:
  /// Name the expects_duplicate_fields parameter to the Rule constructors.
  static constexpr bool EXPECTS_DUPLICATE_FIELDS = true;

  /// All rules have a name of the field that needs to be checked.
  swoc::TextView _name;

public:
  virtual ~RuleCheck() { }

  /** Initialize options with std::functions for creating RuleChecks.
   *
   */
  static void options_init();

  /** Generate @a RuleCheck with @a node with factory pattern.
   *
   * @param name The name of the field. This should be localized.
   * @param value The value of the field. This should be localized.
   * @param rule_type The verification rule value from the node. This need not
   * be localized.
   * @return A pointer to the RuleCheck instance generated, holding a key (and
   * potentially value) TextView for the rule to compare inputs to
   */
  static std::shared_ptr<RuleCheck> make_rule_check(
      swoc::TextView localized_name,
      swoc::TextView localized_value,
      swoc::TextView rule_type);

  /**
   * @param values The values of the field. This should be localized.
   */
  static std::shared_ptr<RuleCheck> make_rule_check(
      swoc::TextView localized_name,
      std::list<swoc::TextView> &&localized_values,
      swoc::TextView rule_type);

  /** Generate @a EqualityCheck, invoked by the factory function when the
   * "equals" flag is present.
   *
   * @param node The name of the target field
   * @param name The associated value with the target field,
   * that is used with strcasecmp comparisons
   * @return A pointer to the EqualityCheck instance generated, holding key and
   * value TextViews for the rule to compare inputs to
   */
  static std::shared_ptr<RuleCheck> make_equality(swoc::TextView name, swoc::TextView value);

  /**
   * @param values The list of values to expect in the response.
   */
  static std::shared_ptr<RuleCheck> make_equality(
      swoc::TextView name,
      std::list<swoc::TextView> &&values);

  /** Generate @a PresenceCheck, invoked by the factory function when the
   * "absence" flag is present.
   *
   * @param name The name of the target field
   * @param value (unused) Used in order to have the same signature as
   * make_equality
   * @return A pointer to the Presence instance generated, holding a name
   * TextView for the rule to compare inputs to
   */
  static std::shared_ptr<RuleCheck> make_presence(swoc::TextView name, swoc::TextView value);

  /**
   * @param values (unused) The list of values specified in the YAML node.
   */
  static std::shared_ptr<RuleCheck> make_presence(
      swoc::TextView name,
      std::list<swoc::TextView> &&values);

  /** Generate @a AbsenceCheck, invoked by the factory function when the
   * "absence" flag is present.
   *
   * @param name The name of the target field
   * @param value (unused) Used in order to have the same signature as
   * make_equality
   * @return A pointer to the AbsenceCheck instance generated, holding a name
   * TextView for the rule to compare inputs to
   */
  static std::shared_ptr<RuleCheck> make_absence(swoc::TextView name, swoc::TextView value);

  /**
   * @param values (unused) The list of values specified in the YAML node.
   */
  static std::shared_ptr<RuleCheck> make_absence(
      swoc::TextView name,
      std::list<swoc::TextView> &&values);

  /** Generate @a ContainsCheck, invoked by the factory function when the
   * "contains" flag is present.
   *
   * @param name The name of the target field
   * @param value The associated "contains" value with the target field,
   * that is used with strcasecmp comparisons
   * @return A pointer to the ContainsCheck instance generated, holding a name
   * TextView for the rule to compare inputs to
   */
  static std::shared_ptr<RuleCheck> make_contains(swoc::TextView name, swoc::TextView value);

  /**
   * @param values The list of values to expect in the response.
   */
  static std::shared_ptr<RuleCheck> make_contains(
      swoc::TextView name,
      std::list<swoc::TextView> &&values);

  /** Generate @a PrefixCheck, invoked by the factory function when the
   * "prefix" flag is present.
   *
   * @param name The name of the target field
   * @param value The associated "prefix" value with the target field,
   * that is used with strcasecmp comparisons
   * @return A pointer to the PrefixCheck instance generated, holding a name
   * TextView for the rule to compare inputs to
   */
  static std::shared_ptr<RuleCheck> make_prefix(swoc::TextView name, swoc::TextView value);

  /**
   * @param values The list of values to expect in the response.
   */
  static std::shared_ptr<RuleCheck> make_prefix(
      swoc::TextView name,
      std::list<swoc::TextView> &&values);

  /** Generate @a SuffixCheck, invoked by the factory function when the
   * "suffix" flag is present.
   *
   * @param name The name of the target field
   * @param value The associated "suffix" value with the target field,
   * that is used with strcasecmp comparisons
   * @return A pointer to the SuffixCheck instance generated, holding a name
   * TextView for the rule to compare inputs to
   */
  static std::shared_ptr<RuleCheck> make_suffix(swoc::TextView name, swoc::TextView value);

  /**
   * @param values (unused) The list of values specified in the YAML node.
   */
  static std::shared_ptr<RuleCheck> make_suffix(
      swoc::TextView name,
      std::list<swoc::TextView> &&values);

  /** Pure virtual function to test whether the input name and value fulfill the
   * rules for the test
   *
   * @param transaction_key The key identifying the transaction.
   * @param name The name of the target field (null if not found).
   * @param value The value of the target field (null if not found).
   * @return Whether the check was successful.
   */
  virtual bool test(swoc::TextView transaction_key, swoc::TextView name, swoc::TextView value)
      const = 0;

  virtual bool test(
      swoc::TextView transaction_key,
      swoc::TextView name,
      const std::list<swoc::TextView> &values) const = 0;

  /** Indicate whether this RuleCheck needs to inspect field values.
   *
   * @return True if field values are relevant to this rule, false otherwise.
   */
  virtual bool expects_duplicate_fields() const = 0;
};

class EqualityCheck : public RuleCheck
{
public:
  ~EqualityCheck() { }

  /** Construct @a EqualityCheck with a given name and value.
   *
   * @param name The name of the target field
   * @param value The associated value with the target field,
   * that is used with strcasecmp comparisons
   */
  EqualityCheck(swoc::TextView name, swoc::TextView value);

  /** Construct @a EqualityCheck with a given name and set of expected values.
   *
   * @param name The name of the target field
   * @param value The associated values with the target field,
   * that is used with strcasecmp comparisons
   */
  EqualityCheck(swoc::TextView name, std::list<swoc::TextView> &&values);

  /** Test whether the name and value both match the expected name and value
   * per the values instantiated in construction.
   *
   * Reports errors in verbose mode.
   *
   * @param key The identifying transaction key.
   * @param name The name of the target field (null if not found)
   * @param value The value of the target field (null if not found)
   * @return Whether the check was successful or not
   */
  bool test(swoc::TextView key, swoc::TextView name, swoc::TextView value) const override;

  /** Test whether the name and values both match the expected name and values
   * per the values instantiated in construction.
   *
   * Reports errors in verbose mode.
   *
   * @param key The identifying transaction key.
   * @param name The name of the target field (null if not found)
   * @param values The values of the target field (null if not found)
   * @return Whether the check was successful or not
   */
  bool test(swoc::TextView key, swoc::TextView name, std::list<swoc::TextView> const &values)
      const override;

  /** Whether this Rule is configured for duplicate fields.
   *
   * @return True of the Rule is configured for duplicate fields, false
   * otherwise.
   */
  bool
  expects_duplicate_fields() const override
  {
    return _expects_duplicate_fields;
  }

private:
  swoc::TextView _value;                  ///< Only EqualityChecks require value comparisons.
  std::list<swoc::TextView> _values;      ///< Only EqualityChecks require value comparisons.
  bool _expects_duplicate_fields = false; ///< Whether the Rule is configured for duplicate fields.
};

class PresenceCheck : public RuleCheck
{
public:
  /** Construct @a PresenceCheck with a given name.
   *
   * @param name The name of the target field
   * @param expects_duplicate_fields Whether the rule should be configured for
   * duplicate fields.
   */
  PresenceCheck(swoc::TextView name, bool expects_duplicate_fields);

  /** Test whether the name matches the expected name. Reports errors in verbose
   * mode.
   *
   * @param key The identifying transaction key.
   * @param name The name of the target field (null if not
   * found)
   * @param value (unused) The value of the target field (null if not found)
   * @return Whether the check was successful or not
   */
  bool test(swoc::TextView key, swoc::TextView name, swoc::TextView value) const override;

  /**
   * @param values (unused) The valuas of the target field (null
   * if not found)
   */
  bool test(swoc::TextView key, swoc::TextView name, std::list<swoc::TextView> const &values)
      const override;

  /** Whether this Rule is configured for duplicate fields.
   *
   * @return True of the Rule is configured for duplicate fields, false
   * otherwise.
   */
  bool
  expects_duplicate_fields() const override
  {
    return _expects_duplicate_fields;
  }

private:
  /** Whether this Rule is configured for duplicate fields. */
  bool _expects_duplicate_fields = false;
};

class AbsenceCheck : public RuleCheck
{
public:
  /** Construct @a AbsenceCheck with a given name.
   *
   * @param name The name of the target field
   * @param expects_duplicate_fields Whether the rule should be configured for
   * duplicate fields.
   */
  AbsenceCheck(swoc::TextView name, bool expects_duplicate_fields);

  /** Test whether the name is null (does not match the expected name). Reports
   * errors in verbose mode.
   *
   * @param key The identifying transaction key.
   * @param name The name of the target field (null if not
   * found)
   * @param value (unused) The value of the target field (null
   * if not found)
   * @return Whether the check was successful or not
   */
  bool test(swoc::TextView key, swoc::TextView name, swoc::TextView value) const override;

  /**
   * @param values (unused) The value of the target field (null
   * if not found)
   */
  bool test(swoc::TextView key, swoc::TextView name, std::list<swoc::TextView> const &values)
      const override;

  /** Whether this Rule is configured for duplicate fields.
   *
   * @return True of the Rule is configured for duplicate fields, false
   * otherwise.
   */
  bool
  expects_duplicate_fields() const override
  {
    return _expects_duplicate_fields;
  }

private:
  /** Whether this Rule is configured for duplicate fields. */
  bool _expects_duplicate_fields = false;
};

class ContainsCheck : public RuleCheck
{
public:
  ~ContainsCheck() { }

  /** Construct @a ContainsCheck with a given name and "contains" value.
   *
   * @param name The name of the target field
   * @param value The associated "contains" value with the target field,
   * that is used with strcasecmp comparisons
   */
  ContainsCheck(swoc::TextView name, swoc::TextView value);

  /** Construct @a ContainsCheck with a given name and set of "contains" values.
   *
   * @param name The name of the target field
   * @param value The associated "contains" values with the target field,
   * that is used with strcasecmp comparisons
   */
  ContainsCheck(swoc::TextView name, std::list<swoc::TextView> &&values);

  /** Test whether the name matches the expected name and the value contains
   * the expected value per the values instantiated in construction.
   *
   * Reports errors in verbose mode.
   *
   * @param key The identifying transaction key.
   * @param name The name of the target field (null if not found)
   * @param value The value of the target field (null if not found)
   * @return Whether the check was successful or not
   */
  bool test(swoc::TextView key, swoc::TextView name, swoc::TextView value) const override;

  /** Test whether the name and matches the expected name and the values contain
   * the expected values per the values instantiated in construction.
   *
   * Reports errors in verbose mode.
   *
   * @param key The identifying transaction key.
   * @param name The name of the target field (null if not found)
   * @param values The values of the target field (null if not found)
   * @return Whether the check was successful or not
   */
  bool test(swoc::TextView key, swoc::TextView name, std::list<swoc::TextView> const &values)
      const override;

  /** Whether this Rule is configured for duplicate fields.
   *
   * @return True of the Rule is configured for duplicate fields, false
   * otherwise.
   */
  bool
  expects_duplicate_fields() const override
  {
    return _expects_duplicate_fields;
  }

private:
  swoc::TextView _value;                  ///< ContainsChecks require value comparisons.
  std::list<swoc::TextView> _values;      ///< ContainsChecks require value comparisons.
  bool _expects_duplicate_fields = false; ///< Whether the Rule is configured for duplicate fields.
};

class PrefixCheck : public RuleCheck
{
public:
  ~PrefixCheck() { }

  /** Construct @a PrefixCheck with a given name and value.
   *
   * @param name The name of the target field
   * @param value The associated value with the target field,
   * that is used with strcasecmp comparisons
   */
  PrefixCheck(swoc::TextView name, swoc::TextView value);

  /** Construct @a PrefixCheck with a given name and set of expected values.
   *
   * @param name The name of the target field
   * @param value The associated values with the target field,
   * that is used with strcasecmp comparisons
   */
  PrefixCheck(swoc::TextView name, std::list<swoc::TextView> &&values);

  /** Test whether the name matches the expected name and the value is prefixed
   * with the expected value per the values instantiated in construction.
   *
   * Reports errors in verbose mode.
   *
   * @param key The identifying transaction key.
   * @param name The name of the target field (null if not found)
   * @param value The value of the target field (null if not found)
   * @return Whether the check was successful or not
   */
  bool test(swoc::TextView key, swoc::TextView name, swoc::TextView value) const override;

  /** Test whether the name matches the expected name and the values are prefixed
   * with the expected value per the values instantiated in construction.
   *
   * Reports errors in verbose mode.
   *
   * @param key The identifying transaction key.
   * @param name The name of the target field (null if not found)
   * @param values The values of the target field (null if not found)
   * @return Whether the check was successful or not
   */
  bool test(swoc::TextView key, swoc::TextView name, std::list<swoc::TextView> const &values)
      const override;

  /** Whether this Rule is configured for duplicate fields.
   *
   * @return True of the Rule is configured for duplicate fields, false
   * otherwise.
   */
  bool
  expects_duplicate_fields() const override
  {
    return _expects_duplicate_fields;
  }

private:
  swoc::TextView _value;                  ///< PrefixChecks require value comparisons.
  std::list<swoc::TextView> _values;      ///< PrefixChecks require value comparisons.
  bool _expects_duplicate_fields = false; ///< Whether the Rule is configured for duplicate fields.
};

class SuffixCheck : public RuleCheck
{
public:
  ~SuffixCheck() { }

  /** Construct @a SuffixCheck with a given name and value.
   *
   * @param name The name of the target field
   * @param value The associated "suffix" value with the target field,
   * that is used with strcasecmp comparisons
   */
  SuffixCheck(swoc::TextView name, swoc::TextView value);

  /** Construct @a SuffixCheck with a given name and set of expected values.
   *
   * @param name The name of the target field
   * @param value The associated "suffix" values with the target field,
   * that is used with strcasecmp comparisons
   */
  SuffixCheck(swoc::TextView name, std::list<swoc::TextView> &&values);

  /** Test whether the name matches the expected name and the value is suffixed
   * with the expected value per the values instantiated in construction.
   *
   * Reports errors in verbose mode.
   *
   * @param key The identifying transaction key.
   * @param name The name of the target field (null if not found)
   * @param value The value of the target field (null if not found)
   * @return Whether the check was successful or not
   */
  bool test(swoc::TextView key, swoc::TextView name, swoc::TextView value) const override;

  /** Test whether the name matches the expected name and the values are suffixed
   * with the expected values per the values instantiated in construction.
   *
   * Reports errors in verbose mode.
   *
   * @param key The identifying transaction key.
   * @param name The name of the target field (null if not found)
   * @param values The values of the target field (null if not found)
   * @return Whether the check was successful or not
   */
  bool test(swoc::TextView key, swoc::TextView name, std::list<swoc::TextView> const &values)
      const override;

  /** Whether this Rule is configured for duplicate fields.
   *
   * @return True of the Rule is configured for duplicate fields, false
   * otherwise.
   */
  bool
  expects_duplicate_fields() const override
  {
    return _expects_duplicate_fields;
  }

private:
  swoc::TextView _value;                  ///< SuffixChecks require value comparisons.
  std::list<swoc::TextView> _values;      ///< SuffixChecks require value comparisons.
  bool _expects_duplicate_fields = false; ///< Whether the Rule is configured for duplicate fields.
};

class HttpFields
{
  using self_type = HttpFields;
  /// Contains the RuleChecks for given field names.
  using Rules = std::unordered_multimap<swoc::TextView, std::shared_ptr<RuleCheck>, Hash, Hash>;
  using Fields = std::unordered_multimap<swoc::TextView, std::string, Hash, Hash>;

public:
  Rules _rules;   ///< Maps field names to functors.
  Fields _fields; ///< Maps field names to values.

  /** Add the field and rules from other into self.
   *
   * @note duplicate field names between this and other will result in
   * duplicate fields being added.
   *
   * @param[in] other The HttpFields from which to add fields and rules.
   */
  void merge(self_type const &other);

  /** Parse a node holding as an attribute an individual field array of rules.
   * Used instead of parse_fields_and_rules on nodes like global_rules_node.
   * Calls parse_fields_and_rules.
   *
   * @param[in] node YAML Node with Fields attribute holding array of rules.
   *
   *   For example:
   *     node:
   *       fields:
   *         - [ X-Test-Header, 23 ]
   *
   * @return swoc::Errata holding any encountered errors
   */
  swoc::Errata parse_global_rules(YAML::Node const &node);

  /** Parse an individual array of fields and rules.
   *
   * @param[in] node Array of fields and rules in YAML node format
   *
   *   For example:
   *       fields:
   *         - [ X-Test-Header, 23 ]
   *
   * @param[in] assume_equality_rule Whether to assume an equality rule in the
   *   absence of another verification rule.
   * @return swoc::Errata holding any encountered errors
   */
  swoc::Errata parse_fields_and_rules(YAML::Node const &node, bool assume_equality_rule);
  static constexpr bool ASSUME_EQUALITY_RULE = true;

  /** Convert _fields into nghttp2_nv and add them to the vector provided
   *
   * @param[out] l vector of nghttp2_nv structs to populate from _fields.
   */
  void add_fields_to_ngnva(nghttp2_nv *l) const;

  friend class HttpHeader;
};

struct VerificationConfig
{
  std::shared_ptr<HttpFields> txn_rules;
};

class HttpHeader
{
  using self_type = HttpHeader;
  using TextView = swoc::TextView;

  //  using NameSet = std::unordered_set<TextView, std::hash<std::string_view>>;

  using NameSet = std::unordered_set<swoc::TextView, Hash, Hash>;

public:
  /// Parsing results.
  enum ParseResult {
    PARSE_OK,        ///< Parse finished successfully.
    PARSE_ERROR,     ///< Invalid data.
    PARSE_INCOMPLETE ///< Parsing not complete.
  };

  /// Important header fields.
  /// @{
  static TextView FIELD_CONTENT_LENGTH;
  static TextView FIELD_TRANSFER_ENCODING;
  static TextView FIELD_HOST;
  /// @}

  /// Mark which status codes have no content by default.
  static std::bitset<600> STATUS_NO_CONTENT;

  /// @param[in] verify_strictly Whether strict verification is enabled.
  HttpHeader(bool verify_strictly = false);
  HttpHeader(self_type const &) = delete;
  HttpHeader(self_type &&that) = default;
  self_type &operator=(self_type &&that) = default;

  swoc::Errata load(YAML::Node const &node);
  swoc::Errata parse_url(TextView url);

  swoc::Rv<ParseResult> parse_request(TextView data);
  swoc::Rv<ParseResult> parse_response(TextView data);

  swoc::Errata update_content_length(TextView method);
  swoc::Errata update_transfer_encoding();

  swoc::Errata serialize(swoc::BufferWriter &w) const;

  std::string make_key() const;

  /** Verify that the fields in 'this' correspond to the provided rules.
   *
   * @param rules_ HeaderRules to iterate over, contains RuleCheck objects
   * @return Whether any rules were violated
   */
  bool verify_headers(swoc::TextView key, HttpFields const &rules_) const;

  int32_t _stream_id = -1; ///< For protocols with streams, this is the stream identifier.
  unsigned _status = 0;
  TextView _reason;
  /// If @a content_size is valid but not @a content_data, synthesize the
  /// content. This is split instead of @c TextView because these get set
  /// independently during load.
  char const *_content_data = nullptr; ///< Literal data for the content.
  size_t _content_size = 0;            ///< Length of the content.
  TextView _method;                    // Required
  TextView _http_version;
  TextView _url;

  bool _send_continue = false;

  // H2 pseudo-headers
  TextView _scheme;    // Required for method
  TextView _authority; // Required for method
  TextView _path;      // Required for method

  /// Maps field names to functors (rules) and field names to values (fields)
  std::shared_ptr<HttpFields> _fields_rules = nullptr;

  /// Body is chunked.
  bool _chunked_p = false;
  /// No Content-Length - close after sending body.
  bool _content_length_p = false;

  /// Format string to generate a key from a transaction.
  static std::string _key_format;

  /// String localization frozen?
  static bool _frozen;

  static void set_max_content_length(size_t n);

  static void global_init();

  /// Precomputed content buffer.
  static swoc::MemSpan<char> _content;

protected:
  class Binding : public swoc::bwf::NameBinding
  {
    using BufferWriter = swoc::BufferWriter;

  public:
    Binding(HttpHeader const &hdr) : _hdr(hdr) { }
    /** Override of virtual method to provide an implementation.
     *
     * @param w Output.
     * @param spec Format specifier for output.
     * @return @a w
     *
     * This is called from the formatting logic to generate output for a named
     * specifier. Subclasses that need to handle name dispatch differently need
     * only override this method.
     */
    BufferWriter &operator()(BufferWriter &w, swoc::bwf::Spec const &spec) const override;

  protected:
    HttpHeader const &_hdr;
  };

public:
  /** Convert @a text to a localized view.
   *
   * In the context of Proxy Verifier, localization is the process by which
   * references to memory in one region are copied to a memory arena. This is
   * used during configuration processing to take configuration node strings,
   * the memory of which will be freed after processing the config, and copy
   * those strings into an arena which can be used during the processing of
   * HTTP transactions later in the program's lifetime.
   *
   * That being the case, these localization functions should only be used
   * while processing the configuration files and not after.
   *
   * @param[in] text Text to localize.
   * @return The localized view, or @a text if localization is frozen and @a
   * text is not found.
   *
   * @a text will be localized if string localization is not frozen, or @a text
   * is already localized.
   */
  static TextView localize(TextView text);
  static TextView localize(char const *text);

  /** Convert @a name to a localized view converted to lower case characters.
   *
   * These should be used to case-insensitive common strings, such as HTTP
   * headers. In addition to storing case-insensitively, this also stores the
   * values in a cache to save space.
   *
   * @see localize documentation for parameter descriptions.
   */
  static TextView localize_lower(TextView text);
  static TextView localize_lower(char const *text);

protected:
  /// Encoding for input text.
  enum class Encoding {
    TEXT, ///< Plain text, no encoding.
    URI   //< URI encoded.
  };

  /** Convert @a name to a localized view.
   *
   * @param name Text to localize.
   * @param enc Type of decoding to perform before localization.
   * @return The localized view, or @a name if localization is frozen and @a
   * name is not found.
   *
   * @a name will be localized if string localization is not frozen, or @a name
   * is already localized. @a enc specifies the text is encoded and needs to be
   * decoded before localization.
   */
  static TextView localize(TextView text, Encoding enc);

  static NameSet _names;
  static swoc::MemArena _arena;

  bool _verify_strictly;

private:
  /** A convenience boolean for the corresponding parameter to localize_helper.
   */
  static constexpr bool SHOULD_LOWER = true;

  /** Convert @a text to a localized view.
   *
   * @param[in] text Text to localize.
   * @param[in] should_lower Whether text should be converted to lower case
   *   letters.
   * @return The localized view, or @a text if localization is frozen and @a
   * text is not found.
   *
   * @a text will be localized if string localization is not frozen, or @a text
   * is already localized.
   */
  static TextView localize_helper(TextView text, bool should_lower);
};

struct Txn
{
  Txn(bool verify_strictly) : _req{verify_strictly}, _rsp{verify_strictly} { }

  uint64_t _start = 0; ///< Start time in HR ticks.
  HttpHeader _req;     ///< Request to send.
  HttpHeader _rsp;     ///< Rules for response to expect.
};

struct Ssn
{
  std::list<Txn> _transactions;
  swoc::file::path _path;
  unsigned _line_no = 0;
  uint64_t _start = 0; ///< Start time in HR ticks.
  /// The desired length of time in ms to replay this session.
  float _rate_multiplier = 0.0;
  /// The SNI to send from the client to the proxy.
  std::string _client_sni;
  /// The TLS verify mode for the client against the proxy.
  int _client_verify_mode = SSL_VERIFY_NONE;
  bool is_tls = false;
  bool is_h2 = false;

  swoc::Errata post_process_transactions();
};

/** A session reader.
 * This is essentially a wrapper around a socket to support use of @c epoll on
 * the socket. The goal is to enable a read operation that waits for data but
 * returns as soon as any data is available.
 */
class Session
{
public:
  Session();
  virtual ~Session();

  /** Set the the socket to be associated with this stream.
   *
   * @param[in] fd The socket with which this stream is associated.
   *
   * @return Any messaging related to setting this socket.
   */
  virtual swoc::Errata set_fd(int fd);

  /** A getter for the socket for this stream. */
  virtual int get_fd() const;

  /** Wait upon and complete the security layer handshakes.
   *
   * Sub classes can override this to implement a presentation layer handshake.
   *
   * @return Any relevant messaging.
   */
  virtual swoc::Errata
  accept()
  {
    return swoc::Errata{};
  }

  /** Initiate the security layer handshakes.
   *
   * Sub classes can override this to implement a presentation layer handshake.
   *
   * @return Any relevant messaging.
   */
  virtual swoc::Errata connect();

  /** Poll on the stream's socket until there is incoming data.
   *
   * @param[in] timeout The timeout, in milliseconds, for the poll.
   *
   * @return The return value of the poll. See poll(2) for a description of
   * this value.
   */
  virtual swoc::Rv<int> poll(std::chrono::milliseconds timeout);

  /** Read from the stream's socket into span.
   *
   * @param[in] span The destination for the bytes read from the socket.
   *
   * @return The number of bytes read and an errata with any messaging.
   */
  virtual swoc::Rv<ssize_t> read(swoc::MemSpan<char> span);

  /** Read the headers to a buffer.
   *
   * @param[in] w The buffer into which to write the headers.
   *
   * @return The number of bytes read and an errata with messaging.
   */
  virtual swoc::Rv<ssize_t> read_header(swoc::FixedBufferWriter &w);

  /** Read body bytes out of the socket.
   *
   * @param[in] hdr The headers which specify how many body bytes to read.
   *
   * @param[in] expected_content_size The response's content-length value
   * or, failing that, the content:size value from the dumped response.
   *
   * @param[in] initial The body already read from the socket.
   *
   * @return The number of bytes drained and an errata with messaging.
   */
  virtual swoc::Rv<size_t>
  drain_body(HttpHeader const &hdr, size_t expected_content_size, swoc::TextView initial);

  virtual swoc::Errata do_connect(swoc::IPEndpoint const *real_target);

  /** Write the content in data to the socket.
   *
   * @param[in] data The content to write to the socket.
   *
   * @return The number of bytes written and an errata with any messaging.
   */
  virtual swoc::Rv<ssize_t> write(swoc::TextView data);

  /** Write the header to the socket.
   *
   * @param[in] hdr The headers to write to the socket.
   *
   * @return The number of bytes written and an errata with any messaging.
   */
  virtual swoc::Rv<ssize_t> write(HttpHeader const &hdr);

  /** Write the number of body bytes as specified by hdr.
   *
   * @param[in] hdr The header to inspect to determine how many body bytes to
   * write.
   *
   * @return The number of bytes written and an errata with any messaging.
   */
  virtual swoc::Rv<ssize_t> write_body(HttpHeader const &hdr);

  /** Whether the connection is currently closed. */
  bool is_closed() const;

  /** Close the connection. */
  virtual void close();

  static swoc::Errata init(int num_transactions);

  virtual swoc::Errata run_transactions(
      std::list<Txn> const &txn,
      swoc::IPEndpoint const *real_target,
      float rate_multiplier);
  virtual swoc::Errata run_transaction(Txn const &json_txn);

private:
  virtual swoc::Rv<size_t>
  drain_body_internal(HttpHeader &hdr, Txn const &json_txn, swoc::TextView initial);

private:
  int _fd = -1; ///< Socket.
};

inline int
Session::get_fd() const
{
  return _fd;
}
inline bool
Session::is_closed() const
{
  return _fd < 0;
}

class TLSSession : public Session
{
public:
  using super_type = Session;

  TLSSession() = default;
  TLSSession(swoc::TextView const &client_sni, int client_verify_mode = SSL_VERIFY_NONE);
  ~TLSSession() override;

  /** @see Session::read */
  swoc::Rv<ssize_t> read(swoc::MemSpan<char> span) override;
  /** @see Session::write */
  swoc::Rv<ssize_t> write(swoc::TextView data) override;

  /** @see Session::close */
  void close() override;
  /** @see Session::accept */
  swoc::Errata accept() override;
  /** @see Session::connect */
  swoc::Errata connect() override;
  swoc::Errata connect(SSL_CTX *ctx);

  SSL *
  get_ssl()
  {
    return _ssl;
  }

  // static members
  static swoc::Errata init();
  static swoc::Errata init(SSL_CTX *&server_context, SSL_CTX *&client_context);

  /** Register the TLS handshake verification mode of the server per the SNI.
   *
   * This function is only relevant to the server.
   *
   * This specifies what verification mode should be done against the client in
   * the TLS handshake if the client uses the given SNI in the client hello.
   *
   * @param[in] sni The SNI which is the key for the mode value.
   *
   * @param[in] mode The verification mode to use in TLS handshakes in which
   * the sni is the servername in the client hello.
   */
  static void register_sni_for_client_verification(std::string_view sni, int mode);

  /** A lookup function for the registered verification mode given the SNI.
   *
   * This function is only relevant to the server.
   *
   * @param[in] sni The SNI key from which the mode value is queried.
   *
   * @return The verification mode for the given SNI previously registered via
   * register_sni_for_client_verification. If no such SNI has been registered,
   * then SSL_VERIFY_NONE will be returned as a default.
   */
  static int get_verify_mode_for_sni(std::string_view sni);

  /** Configure the use of a client certificate.
   *
   * @param[in] cert_path The path to a directory with "client.pem" and
   * "client.key" files, or the path to a file with both the private and public
   * keys.
   *
   * @return logging and status information via an Errata.
   */
  static swoc::Errata configure_client_cert(std::string_view cert_path);

  /** Configure the use of a server certificate.
   *
   * @param[in] cert_path The path to a directory with "client.pem" and
   * "client.key" files, or the path to a file with both the private and public
   * keys.
   *
   * @return logging and status information via an Errata.
   */
  static swoc::Errata configure_server_cert(std::string_view cert_path);

  /** Configure the use of a CA.
   *
   * @param[in] cert_path The path to a directory contain CA files or a file
   * containing CA information.
   *
   * @return logging and status information via an Errata.
   */
  static swoc::Errata configure_ca_cert(std::string_view cert_path);

public:
  /// The client or server public key file. This may also contain the private
  /// key.
  static swoc::file::path certificate_file;

  /// The client or server private key file if not in the certificate_file.
  static swoc::file::path privatekey_file;

  /// The CA file which may contain mutiple CA certs.
  static swoc::file::path ca_certificate_file;

  /// The CA directory containing one or more CA cert files.
  static swoc::file::path ca_certificate_dir;

protected:
  /** A helper file to configure a host certificate.
   *
   * @param[in] cert_path The path to a directory with private and public key
   * files or the path to a file with both the private and public keys.
   *
   * @param[in] public_file The name to expect for the public file if cert_path
   * is a directory.
   *
   * @param[in] private_file The name to expect for the private file if
   * cert_path is a directory.
   *
   * @return logging and status information via an Errata.
   */
  static swoc::Errata configure_host_cert(
      std::string_view cert_path,
      std::string_view public_file,
      std::string_view private_key);

  /** Configure the context to use any provided certificates.
   *
   * @param[in] context The context upon which to configure the host and CA certificates.
   *
   * @return An errata indicating the status of the configuration.
   */
  static swoc::Errata configure_certificates(SSL_CTX *&context);

protected:
  SSL *_ssl = nullptr;
  /** The SNI to be sent by the client (as opposed to the one expected by the
   * server from the proxy). This only applies to the client.
   */
  std::string _client_sni;

  /** The verify mode for the client in the TLS handshake with the proxy.
   * This only applies to the client.
   */
  int _client_verify_mode = SSL_VERIFY_NONE;

  static SSL_CTX *server_context;
  static SSL_CTX *client_context;

  /** The verification mode of the verifier server against the proxy in the TLS
   * handshake as specified per the SNI received from the proxy.
   */
  static std::unordered_map<std::string, int> _verify_mode_per_sni;
};

class H2StreamState
{
public:
  H2StreamState();
  H2StreamState(int32_t stream_id);
  H2StreamState(int32_t stream_id, char *send_body, int send_body_length);

  int32_t _stream_id = 0;
  int _data_to_recv = 0;
  size_t _send_body_offset = 0;
  char const *_send_body = nullptr;
  size_t _send_body_length = 0;
  HttpHeader const *_req = nullptr;
  HttpHeader const *_resp = nullptr;
  bool _wait_for_continue = false;
  std::string _key;
  std::chrono::time_point<std::chrono::system_clock> _stream_start;
};

class H2Session : public TLSSession
{
public:
  using super_type = TLSSession;
  H2Session();
  ~H2Session();
  swoc::Rv<ssize_t> read(swoc::MemSpan<char> span) override;
  swoc::Rv<ssize_t> write(swoc::TextView data) override;
  swoc::Rv<ssize_t> write(HttpHeader const &hdr) override;

  swoc::Errata connect() override;
  static swoc::Errata init(SSL_CTX *&server_context, SSL_CTX *&client_context);
  static swoc::Errata
  init()
  {
    return H2Session::init(h2_server_context, h2_client_context);
  }
  swoc::Errata session_init();
  swoc::Errata send_client_connection_header();
  swoc::Errata run_transactions(
      std::list<Txn> const &txn,
      swoc::IPEndpoint const *real_target,
      float rate_multiplier) override;
  swoc::Errata run_transaction(Txn const &txn) override;

  nghttp2_session *
  get_session()
  {
    return _session;
  }

  std::map<int32_t, std::unique_ptr<H2StreamState>> _stream_map;

protected:
  nghttp2_session *_session;
  nghttp2_session_callbacks *_callbacks;
  nghttp2_option *_options;

  static SSL_CTX *h2_server_context;
  static SSL_CTX *h2_client_context;

private:
  swoc::Errata pack_headers(HttpHeader const &hdr, nghttp2_nv *&nv_hdr, int &hdr_count);
  nghttp2_nv tv_to_nv(char const *name, swoc::TextView v);
};

class ChunkCodex
{
public:
  /// The callback when a chunk is decoded.
  /// @param chunk Data for the chunk in the provided view.
  /// @param offset The offset from the full chunk for @a chunk.
  /// @param size The size of the full chunk.
  /// Because the data provided might not contain the entire chunk, a chunk can
  /// come back piecemeal in the callbacks. The @a offset and @a size specify
  /// where in the actual chunk the particular piece in @a chunk is placed.
  using ChunkCallback = std::function<bool(swoc::TextView chunk, size_t offset, size_t size)>;
  enum Result {
    CONTINUE, ///< The parser expects more bytes.
    DONE,     ///< The final done chunk is completed.
    ERROR     ///< A parsing error has ocurred.
  };

  /** Parse @a data as chunked encoded.
   *
   * @param data Data to parse.
   * @param cb Callback to receive decoded chunks.
   * @return Parsing result.
   *
   * The parsing is designed to be restartable so that data can be passed
   * directly from the socket to this object, without doing any gathering.
   */
  Result parse(swoc::TextView data, ChunkCallback const &cb);

  /** Write @a data to @a fd using chunked encoding.
   *
   * @param fd Output file descriptor.
   * @param data [in,out] Data to write.
   * @param chunk_size Size of chunks.
   * @return A pair of
   *   - The number of bytes written from @a data (not including the chunk
   * encoding).
   *   - An error code, which will be 0 if all data was successfully written.
   */
  std::tuple<ssize_t, std::error_code>
  transmit(Session &session, swoc::TextView data, size_t chunk_size = 4096);

protected:
  size_t _size = 0; ///< Size of the current chunking being decoded.
  size_t _off = 0;  ///< Number of bytes in the current chunk already sent to the callback.
  /// Buffer to hold size text in case it falls across @c parse call boundaries.
  swoc::LocalBufferWriter<16> _size_text;

  /// Parsing state.
  enum class State {
    INIT, ///< Initial state, no parsing has occurred.
    SIZE, ///< Parsing the chunk size.
    CR,   ///< Expecting the size terminating CR
    LF,   ///< Expecting the size terminating LF.
    BODY, ///< Inside the chunk body.
    POST_BODY_CR,
    POST_BODY_LF,
    FINAL ///< Terminating (size zero) chunk parsed.
  } _state = State::INIT;
};

// YAML support utilities.
namespace swoc
{
inline BufferWriter &
bwformat(BufferWriter &w, bwf::Spec const & /* spec */, YAML::Mark const &mark)
{
  return w.print("line {}", mark.line);
}
} // namespace swoc

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

protected:
  /** The replay file associated with this handler.
   */
  swoc::file::path _path;
};

swoc::Errata Load_Replay_File(swoc::file::path const &path, ReplayFileHandler &handler);

swoc::Errata Load_Replay_Directory(
    swoc::file::path const &path,
    swoc::Errata (*loader)(swoc::file::path const &),
    int n_threads = 10);

swoc::Errata parse_ips(std::string arg, std::deque<swoc::IPEndpoint> &target);
swoc::Errata resolve_ips(std::string arg, std::deque<swoc::IPEndpoint> &target);
swoc::Rv<swoc::IPEndpoint> Resolve_FQDN(swoc::TextView host);

class ThreadInfo
{
public:
  std::thread *_thread = nullptr;
  std::condition_variable _cvar;
  std::mutex _mutex;
  virtual bool data_ready() = 0;
};

// This must be a list so that iterators / pointers to elements do not go stale.
class ThreadPool
{
public:
  void wait_for_work(ThreadInfo *info);
  ThreadInfo *get_worker();
  virtual std::thread make_thread(std::thread *) = 0;
  void join_threads();

protected:
  std::list<std::thread> _allThreads;
  // Pool of ready / idle threads.
  std::deque<ThreadInfo *> _threadPool;
  std::condition_variable _threadPoolCvar;
  std::mutex _threadPoolMutex;
  const size_t max_threads = 2000;
};
