/** @file
 * Common data structures and definitions for Proxy Verifier tools.
 *
 * Copyright 2021, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "case_insensitive_utils.h"

#include <chrono>
#include <condition_variable>
#include <deque>
#include <list>
#include <memory>
#include <nghttp2/nghttp2.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <string>
#include <thread>
#include <vector>
#include <unistd.h>
#include <map>
#include <unordered_map>

#include "swoc/BufferWriter.h"
#include "swoc/Errata.h"
#include "swoc/Lexicon.h"
#include "swoc/MemArena.h"
#include "swoc/TextView.h"
#include "swoc/bwf_base.h"
#include "swoc/swoc_file.h"
#include "swoc/swoc_ip.h"

enum class UrlPart {
  Scheme,
  Host,
  Port,
  Authority,
  Path,
  Query,
  Fragment,
  Error,
  UrlPartCount = Error
};

static const std::string VERIFICATION_DIRECTIVE_EQUALS{"equal"};
static const std::string VERIFICATION_DIRECTIVE_PRESENCE{"present"};
static const std::string VERIFICATION_DIRECTIVE_ABSENCE{"absent"};
static const std::string VERIFICATION_DIRECTIVE_CONTAINS{"contains"};
static const std::string VERIFICATION_DIRECTIVE_PREFIX{"prefix"};
static const std::string VERIFICATION_DIRECTIVE_SUFFIX{"suffix"};

static const std::string URL_PART_SCHEME{"scheme"};
static const std::string URL_PART_HOST{"host"};
static const std::string URL_PART_PORT{"port"};
static const std::string URL_PART_AUTHORITY{"net-loc"};
static const std::string URL_PART_PATH{"path"};
static const std::string URL_PART_QUERY{"query"};
static const std::string URL_PART_FRAGMENT{"fragment"};

static const swoc::Lexicon<UrlPart> URL_PART_NAMES{
    {{UrlPart::Scheme, {URL_PART_SCHEME}},
     {UrlPart::Host, {URL_PART_HOST}},
     {UrlPart::Port, {URL_PART_PORT}},
     {UrlPart::Authority, {URL_PART_AUTHORITY, "authority"}},
     {UrlPart::Path, {URL_PART_PATH}},
     {UrlPart::Query, {URL_PART_QUERY}},
     {UrlPart::Fragment, {URL_PART_FRAGMENT}}},
    {UrlPart::Error}};

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

/** Configure logging.
 *
 * @param[in] verbose_argument The user-specified verbosity requested.
 */
swoc::Errata configure_logging(const std::string_view verbose_argument);

/** Get a printable version of the ALPN wire format string.
 *
 * For example, given this character array:
 * {2, 'h', '2', 7, 'h', 't', 't', 'p', '1', '.', '1'}
 *
 * This will return:
 * "h2,http1.1"
 *
 * @param[in] alpn_wire_string The alpn char array as passed to
 * SSL_select_next_proto.
 *
 * @return a printable version of the alpn string.
 */
std::string get_printable_alpn_string(std::string_view alpn_wire_string);

namespace swoc
{
inline namespace SWOC_VERSION_NS
{
BufferWriter &bwformat(BufferWriter &w, bwf::Spec const &spec, HttpHeader const &h);
BufferWriter &bwformat(BufferWriter &w, bwf::Spec const &spec, std::chrono::milliseconds const &s);

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
  explicit SSLError() : _e(ERR_peek_last_error()) { }
  explicit SSLError(int e) : _e(e) { }
  explicit SSLError(SSL const *ssl, int e) : _e(SSL_get_error(ssl, e)) { }
};
} // namespace bwf

BufferWriter &bwformat(BufferWriter &w, bwf::Spec const &spec, bwf::SSLError const &error);
} // namespace SWOC_VERSION_NS
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
class RuleCheck
{
  /// References the make_* functions below.
  using MakeRuleFunction =
      std::function<std::shared_ptr<RuleCheck>(swoc::TextView, swoc::TextView)>;
  using RuleOptions = std::unordered_map<swoc::TextView, MakeRuleFunction, Hash, Hash>;
  static RuleOptions options; ///< Returns function to construct a RuleCheck child class for a
                              ///< given rule type ("equals", "presence", "absence",
                              ///< "contains", "prefix", "or "suffix")

  using MakeURLRuleFunction = std::function<std::shared_ptr<RuleCheck>(UrlPart, swoc::TextView)>;
  using URLRuleOptions = std::unordered_map<swoc::TextView, MakeURLRuleFunction, Hash, Hash>;
  static URLRuleOptions url_rule_options; ///< Returns function to construct a RuleCheck child class
                                          ///< for a given URL rule type ("equals", "presence",
                                          ///< "absence", "contains", "prefix", "or "suffix")

  using MakeDuplicateFieldRuleFunction =
      std::function<std::shared_ptr<RuleCheck>(swoc::TextView, std::vector<swoc::TextView> &&)>;
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
  bool _is_field;

public:
  virtual ~RuleCheck() = default;

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

  /** Generate @a RuleCheck with @a node with factory pattern.
   *
   * @param url_part The part of the URL. Pre-parsed to an enum.
   * @param value The value of the field. This should be localized.
   * @param rule_type The verification rule value from the node. This need not
   * be localized.
   * @return A pointer to the RuleCheck instance generated, potentially holding
   * a value TextView for the rule to compare inputs to
   */
  static std::shared_ptr<RuleCheck>
  make_rule_check(UrlPart url_part, swoc::TextView localized_value, swoc::TextView rule_type);

  /**
   * @param values The values of the field. This should be localized.
   */
  static std::shared_ptr<RuleCheck> make_rule_check(
      swoc::TextView localized_name,
      std::vector<swoc::TextView> &&localized_values,
      swoc::TextView rule_type);

  /** Generate @a EqualityCheck, invoked by the factory function when the
   * "equals" flag is present for a field check.
   *
   * @param node The name of the target field
   * @param name The associated value with the target field,
   * that is used with strcasecmp comparisons
   * @return A pointer to the EqualityCheck instance generated, holding key and
   * value TextViews for the rule to compare inputs to
   */
  static std::shared_ptr<RuleCheck> make_equality(swoc::TextView name, swoc::TextView value);

  /** Generate @a EqualityCheck, invoked by the factory function when the
   * "equals" flag is present.
   *
   * @param part The ID of the target URL part
   * @param name The associated value with the target field,
   * that is used with strcasecmp comparisons
   * @return A pointer to the EqualityCheck instance generated, holding key and
   * value TextViews for the rule to compare inputs to
   */
  static std::shared_ptr<RuleCheck> make_equality(UrlPart url_part, swoc::TextView value);

  /**
   * @param values The list of values to expect in the response.
   */
  static std::shared_ptr<RuleCheck> make_equality(
      swoc::TextView name,
      std::vector<swoc::TextView> &&values);

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

  /** Generate @a PresenceCheck, invoked by the factory function when the
   * "absence" flag is present.
   *
   * @param part The ID of the target URL part
   * @param value (unused) Used in order to have the same signature as
   * make_equality
   * @return A pointer to the Presence instance generated, holding a name
   * TextView for the rule to compare inputs to
   */
  static std::shared_ptr<RuleCheck> make_presence(UrlPart url_part, swoc::TextView value);

  /**
   * @param values (unused) The list of values specified in the YAML node.
   */
  static std::shared_ptr<RuleCheck> make_presence(
      swoc::TextView name,
      std::vector<swoc::TextView> &&values);

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

  /** Generate @a AbsenceCheck, invoked by the factory function when the
   * "absence" flag is present.
   *
   * @param part The ID of the target URL part
   * @param value (unused) Used in order to have the same signature as
   * make_equality
   * @return A pointer to the AbsenceCheck instance generated, holding a name
   * TextView for the rule to compare inputs to
   */
  static std::shared_ptr<RuleCheck> make_absence(UrlPart url_part, swoc::TextView value);

  /**
   * @param values (unused) The list of values specified in the YAML node.
   */
  static std::shared_ptr<RuleCheck> make_absence(
      swoc::TextView name,
      std::vector<swoc::TextView> &&values);

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

  /** Generate @a ContainsCheck, invoked by the factory function when the
   * "contains" flag is present.
   *
   * @param part The ID of the target URL part
   * @param value The associated "contains" value with the target part,
   * that is used with strcasecmp comparisons
   * @return A pointer to the ContainsCheck instance generated, holding a name
   * TextView for the rule to compare inputs to
   */
  static std::shared_ptr<RuleCheck> make_contains(UrlPart url_part, swoc::TextView value);

  /**
   * @param values The list of values to expect in the response.
   */
  static std::shared_ptr<RuleCheck> make_contains(
      swoc::TextView name,
      std::vector<swoc::TextView> &&values);

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

  /** Generate @a PrefixCheck, invoked by the factory function when the
   * "prefix" flag is present.
   *
   * @param part The ID of the target URL part
   * @param value The associated "prefix" value with the target part,
   * that is used with strcasecmp comparisons
   * @return A pointer to the PrefixCheck instance generated, holding a name
   * TextView for the rule to compare inputs to
   */
  static std::shared_ptr<RuleCheck> make_prefix(UrlPart url_part, swoc::TextView value);

  /**
   * @param values The list of values to expect in the response.
   */
  static std::shared_ptr<RuleCheck> make_prefix(
      swoc::TextView name,
      std::vector<swoc::TextView> &&values);

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

  /** Generate @a SuffixCheck, invoked by the factory function when the
   * "suffix" flag is present.
   *
   * @param part The ID of the target URL part
   * @param value The associated "suffix" value with the target field,
   * that is used with strcasecmp comparisons
   * @return A pointer to the SuffixCheck instance generated, holding a name
   * TextView for the rule to compare inputs to
   */
  static std::shared_ptr<RuleCheck> make_suffix(UrlPart url_part, swoc::TextView value);

  /**
   * @param values (unused) The list of values specified in the YAML node.
   */
  static std::shared_ptr<RuleCheck> make_suffix(
      swoc::TextView name,
      std::vector<swoc::TextView> &&values);

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
      const std::vector<swoc::TextView> &values) const = 0;

  /** Indicate whether this RuleCheck needs to inspect field values.
   *
   * @return True if field values are relevant to this rule, false otherwise.
   */
  virtual bool expects_duplicate_fields() const = 0;

  /** Returns the name of what the test operates on ("URI Part" or "Field Name")
   *
   * @return The name of the attribute operated on
   */
  swoc::TextView
  target_type() const
  {
    if (_is_field) {
      return "Field Name";
    } else {
      return "URI Part";
    }
  }
};

class EqualityCheck : public RuleCheck
{
public:
  ~EqualityCheck() = default;

  /** Construct @a EqualityCheck with a given name and value.
   *
   * @param name The name of the target field
   * @param value The associated value with the target field,
   * that is used with strcasecmp comparisons
   */
  EqualityCheck(swoc::TextView name, swoc::TextView value);

  /** Construct @a EqualityCheck with a given URL part and value.
   *
   * @param part The ID of the target URL part
   * @param value The associated value with the target URL part,
   * that is used with strcasecmp comparisons
   */
  EqualityCheck(UrlPart url_part, swoc::TextView value);

  /** Construct @a EqualityCheck with a given name and set of expected values.
   *
   * @param name The name of the target field
   * @param value The associated values with the target field,
   * that is used with strcasecmp comparisons
   */
  EqualityCheck(swoc::TextView name, std::vector<swoc::TextView> &&values);

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
  bool test(swoc::TextView key, swoc::TextView name, std::vector<swoc::TextView> const &values)
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
  std::vector<swoc::TextView> _values;    ///< Only EqualityChecks require value comparisons.
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

  /** Construct @a PresenceCheck with a given URL part.
   *
   * @param part The ID of the target URL part
   */
  PresenceCheck(UrlPart url_part);

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
  bool test(swoc::TextView key, swoc::TextView name, std::vector<swoc::TextView> const &values)
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

  /** Construct @a AbsenceCheck with a given URL part.
   *
   * @param part The ID of the target URL part
   * @param expects_duplicate_fields Whether the rule should be configured for
   * duplicate fields.
   */
  AbsenceCheck(UrlPart url_part);

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
  bool test(swoc::TextView key, swoc::TextView name, std::vector<swoc::TextView> const &values)
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

class SubstrCheck : public RuleCheck
{
public:
  virtual ~SubstrCheck() = default;

  /** Test whether the name matches the expected name and the value contains,
   * is prefixed with, or is suffixed with the expected value per the
   * values instantiated in construction.
   *
   * Reports errors in verbose mode.
   *
   * @param key The identifying transaction key.
   * @param name The name of the target field (null if not found)
   * @param value The value of the target field (null if not found)
   * @return Whether the check was successful or not
   */
  bool test(swoc::TextView key, swoc::TextView name, swoc::TextView value) const override;

  /** Test whether the name matches the expected name and the values contain,
   * are prefixed with, or are suffixed with the expected values per the
   * values instantiated in construction.
   *
   * Reports errors in verbose mode.
   *
   * @param key The identifying transaction key.
   * @param name The name of the target field (null if not found)
   * @param values The values of the target field (null if not found)
   * @return Whether the check was successful or not
   */
  bool test(swoc::TextView key, swoc::TextView name, std::vector<swoc::TextView> const &values)
      const override;

  /** Returns the name of the test for debug messages, such as "contains"
   *
   * @return The name or ID of the test type
   */
  virtual swoc::TextView get_test_name() const = 0;

  virtual bool test_tv(swoc::TextView value, swoc::TextView test) const = 0;

protected:
  swoc::TextView _value;                  ///< SubstrChecks require value comparisons.
  std::vector<swoc::TextView> _values;    ///< SubstrChecks require value comparisons.
  bool _expects_duplicate_fields = false; ///< Whether the Rule is configured for duplicate fields.
};

class ContainsCheck : public SubstrCheck
{
public:
  ~ContainsCheck() = default;

  /** Construct @a ContainsCheck with a given name and "contains" value.
   *
   * @param name The name of the target field
   * @param value The associated "contains" value with the target field,
   * that is used with strcasecmp comparisons
   */
  ContainsCheck(swoc::TextView name, swoc::TextView value);

  /** Construct @a ContainsCheck with a given URL part and value.
   *
   * @param url_part The ID of the target URL part
   * @param value The associated value with the target URL part,
   * that is used with strcasecmp comparisons
   */
  ContainsCheck(UrlPart url_part, swoc::TextView value);

  /** Construct @a ContainsCheck with a given name and set of "contains" values.
   *
   * @param name The name of the target field
   * @param value The associated "contains" values with the target field,
   * that is used with strcasecmp comparisons
   */
  ContainsCheck(swoc::TextView name, std::vector<swoc::TextView> &&values);

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

  swoc::TextView
  get_test_name() const override
  {
    return "Contains";
  }

  bool test_tv(swoc::TextView value, swoc::TextView test) const override;
};

class PrefixCheck : public SubstrCheck
{
public:
  ~PrefixCheck() = default;

  /** Construct @a PrefixCheck with a given name and value.
   *
   * @param name The name of the target field
   * @param value The associated value with the target field,
   * that is used with strcasecmp comparisons
   */
  PrefixCheck(swoc::TextView name, swoc::TextView value);

  /** Construct @a PrefixCheck with a given URL part and value.
   *
   * @param url_part The ID of the target URL part
   * @param value The associated value with the target URL part,
   * that is used with strcasecmp comparisons
   */
  PrefixCheck(UrlPart url_part, swoc::TextView value);

  /** Construct @a PrefixCheck with a given name and set of expected values.
   *
   * @param name The name of the target field
   * @param value The associated values with the target field,
   * that is used with strcasecmp comparisons
   */
  PrefixCheck(swoc::TextView name, std::vector<swoc::TextView> &&values);

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

  swoc::TextView
  get_test_name() const override
  {
    return "Prefix";
  }

  bool test_tv(swoc::TextView value, swoc::TextView test) const override;
};

class SuffixCheck : public SubstrCheck
{
public:
  ~SuffixCheck() = default;

  /** Construct @a SuffixCheck with a given name and value.
   *
   * @param name The name of the target field
   * @param value The associated "suffix" value with the target field,
   * that is used with strcasecmp comparisons
   */
  SuffixCheck(swoc::TextView name, swoc::TextView value);

  /** Construct @a SuffixCheck with a given URL part and value.
   *
   * @param url_part The ID of the target URL part
   * @param value The associated value with the target URL part,
   * that is used with strcasecmp comparisons
   */
  SuffixCheck(UrlPart url_part, swoc::TextView value);

  /** Construct @a SuffixCheck with a given name and set of expected values.
   *
   * @param name The name of the target field
   * @param value The associated "suffix" values with the target field,
   * that is used with strcasecmp comparisons
   */
  SuffixCheck(swoc::TextView name, std::vector<swoc::TextView> &&values);

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

  swoc::TextView
  get_test_name() const override
  {
    return "Suffix";
  }

  bool test_tv(swoc::TextView value, swoc::TextView test) const override;
};

class HttpFields
{
  using self_type = HttpFields;
  /// Contains the RuleChecks for given field names.

  // For both of these, these must be the ordered multimap because duplicate
  // field verification requires that we verify the correct order of the field
  // values.
  using Rules = std::multimap<swoc::TextView, std::shared_ptr<RuleCheck>, CaseInsensitiveCompare>;
  using Fields = std::multimap<swoc::TextView, std::string, CaseInsensitiveCompare>;

  struct Field
  {
    swoc::TextView name;
    swoc::TextView value;
  };
  using FieldsSequence = std::vector<Field>;

public:
  HttpFields();

  Rules _rules;   ///< Maps field names to functors.
  Fields _fields; ///< Maps field names to values.

  /** The ordered set of fields in which the request or response fields should
   * be sent as specifed by the YAML replay file, or the ordered fields in the
   * request or response as received by the Proxy.
   */
  FieldsSequence _fields_sequence;

  /** The capacity to reserve up front for _fields_sequnce.
   *
   * An analysis of 1.2 million messages from production traffic showed that
   * 94% of HTTP request and response messages had 30 or less fields.
   * _fields_sequence is a list of std::string_view tuples, so they are
   * relatively small. Thus reserving this space ahead of time is a cheap cost
   * to pay for the potential performance benefit of avoiding reallocations.
   */
  static constexpr auto num_fields_to_reserve = 30;

  std::vector<std::shared_ptr<RuleCheck>>
      _url_rules[static_cast<size_t>(UrlPart::UrlPartCount)]; ///< Maps URL part names to functors.
  swoc::TextView
      _url_parts[static_cast<size_t>(UrlPart::UrlPartCount)]; ///< Maps URL part names to values.

  /** Add an HTTP field to the set of fields.
   *
   * @param[in] name The field name for the new field.
   * @param[in] value The field value for the new field.
   */
  void add_field(swoc::TextView name, swoc::TextView value);

  /** Add the field and rules from other into self.
   *
   * @note duplicate field names between this and other will result in
   * duplicate fields being added.
   *
   * @param[in] other The HttpFields from which to add fields and rules.
   */
  void merge(self_type const &other);

  /** Convert _fields into nghttp2_nv and add them to the vector provided
   *
   * This assumes that the pseudo header fields are handled separately.  If
   * such fields are in the _fields container they are not added here to the
   * nghttp2_nv vector.
   *
   * @param[out] l vector of nghttp2_nv structs to populate from _fields.
   */
  void add_fields_to_ngnva(nghttp2_nv *l) const;

  friend class HttpHeader;
};

class HttpHeader
{
  using self_type = HttpHeader;
  using TextView = swoc::TextView;

public:
  /// Parsing results.
  enum ParseResult {
    PARSE_OK,        ///< Parse finished successfully.
    PARSE_ERROR,     ///< Invalid data.
    PARSE_INCOMPLETE ///< Parsing not complete.
  };

  /// Important header fields.
  /// @{
  static constexpr swoc::TextView FIELD_CONTENT_LENGTH = "content-length";
  static constexpr swoc::TextView FIELD_TRANSFER_ENCODING = "transfer-encoding";
  /// @}

  /// Mark which status codes have no content by default.
  static std::bitset<600> STATUS_NO_CONTENT;

  /// @param[in] verify_strictly Whether strict verification is enabled.
  HttpHeader(bool verify_strictly = false);
  HttpHeader(self_type const &) = delete;
  HttpHeader(self_type &&that) = default;
  self_type &operator=(self_type &&that) = default;

  swoc::Errata parse_url(TextView url);

  static UrlPart parse_url_part(TextView name);

  swoc::Rv<ParseResult> parse_request(TextView data);
  swoc::Rv<ParseResult> parse_response(TextView data);

  swoc::Errata update_content_length(TextView method);
  swoc::Errata update_transfer_encoding();

  swoc::Errata serialize(swoc::BufferWriter &w) const;

  /** A marker indicating that this transaction's key is not yet set nor derived.
   */
  static constexpr char const *const TRANSACTION_KEY_NOT_SET = "*N/A*";

  /** Set _key for this message via self-inspection (i.e., via URL and field
   * processing) per the specified key format (see --format). */
  void derive_key();

  /** Set a key for this message.
   *
   * By design this takes precedence over deriving the key from the headers.
   * That is, setting the key via this function will override any key derived
   * from the headers via derive_key() and will prevent future calls to
   * derive_key() from overriding this explicitly set value. We never expect
   * the derived key (if derivable) and a set key to differ, but be aware of
   * this precedence behavior when reading the code.
   *
   * @param[in] new_key The key to set for this message.
   */
  void set_key(swoc::TextView new_key);

  /** Get the key for this message.
   *
   * A key can be set via one of two mechanisms:
   *   1. Implicitly via the header fields during previous header parsing.
   *   2. Explicitly via set_key.
   *
   * @return A key if the header fields describe a key or if the user
   * previously set a key via set_key, or TRANSACTION_KEY_NOT_SET otherwise.
   */
  std::string get_key() const;

  /** Verify that the fields in 'this' correspond to the provided rules.
   *
   * @param rules_ HeaderRules to iterate over, contains RuleCheck objects
   * @return Whether any rules were violated
   */
  bool verify_headers(swoc::TextView key, HttpFields const &rules_) const;

  /** Add the fields and rules from other into self's _fields_rules.
   *
   * @note duplicate field names between this and other will result in
   * duplicate fields being added.
   *
   * @param[in] other The HttpFields from which to add fields and rules.
   */
  void merge(HttpFields const &other);

  /// Whether this is an HTTP/2 message.
  bool _is_http2 = false;

  /// Whether this is an HTTP request
  bool _is_request = false;

  /// Whether this is an HTTP response
  bool _is_response = false;

  /// Whether the _fields array contains pseudo header fields.
  bool _contains_pseudo_headers_in_fields_array = false;
  int32_t _stream_id = -1; ///< For protocols with streams, this is the stream identifier.

  /// The HTTP response status, such as 200, 304, etc.
  unsigned _status = 0;

  /// A string version of _status, such as "200", "304", etc. We create this
  /// local version around so that if an HTTP/2 response is generated and
  /// passed to an nghttp2 array, this keeps the storage for the string
  /// persistent across the callback.
  std::string _status_string;

  /// The reason phrase, such as "OK" for a 200 HTTP/1.x response.
  ///
  /// This is left empty for HTTP/2 responses because the spec intentionally
  /// omits reason phrases. See RFC 7540, section 8.1.2.4.
  TextView _reason;
  /// If @a content_size is valid but not @a content_data, synthesize the
  /// content. This is split instead of @c TextView because these get set
  /// independently during load.

  char const *_content_data = nullptr; ///< Literal data for the content.

  /// The size of content we should prepare to send.
  size_t _content_size = 0;

  /// The size of content recorded that was sent in the replay file.
  ///
  /// This is helpful to reference when replaying traffic. We may decide to try
  /// to send n bytes because that's what the content-length indicates, but it
  /// could be that, due to the handling of something like a 304, the proxy may
  /// decide to close the connection before we were able to write the data. If
  /// that happens during our replay and the recorded content size indicates
  /// this, then we don't warn about it.
  size_t _recorded_content_size = 0;
  TextView _method; // Required
  TextView _http_version;
  TextView _url;

  bool _send_continue = false;

  // H2 pseudo-headers: parts of URL
  // Required for method
  TextView _scheme;
  TextView _authority;
  TextView _path;

  // URI headers: for URL verification
  TextView uri_scheme;
  TextView uri_host;
  TextView uri_port;
  TextView uri_authority;
  TextView uri_path;
  TextView uri_query;
  TextView uri_fragment;

  /// Maps field names to functors (rules) and field names to values (fields)
  std::shared_ptr<HttpFields> _fields_rules = nullptr;

  /// Body is chunked.
  bool _chunked_p = false;
  /// No Content-Length - close after sending body.
  bool _content_length_p = false;

  /// Format string to generate a key from a transaction.
  static std::string _key_format;

  static void set_max_content_length(size_t n);

  static void global_init();

  /// Precomputed content buffer.
  static swoc::MemSpan<char> _content;

  bool _verify_strictly;

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

private:
  /** The key associated with this HTTP transaction. */
  std::string _key;
};

struct Txn
{
  Txn(bool verify_strictly) : _req{verify_strictly}, _rsp{verify_strictly} { }

  std::chrono::nanoseconds _start; ///< The delay since the beginning of the session.

  /// How long the user said to delay for this transaction.
  std::chrono::microseconds _user_specified_delay_duration{0};
  HttpHeader _req; ///< Request to send.
  HttpHeader _rsp; ///< Rules for response to expect.
};

struct Ssn
{
  std::list<Txn> _transactions;
  swoc::file::path _path;
  unsigned _line_no = 0;

  using ClockType = std::chrono::system_clock;
  using TimePoint = std::chrono::time_point<ClockType, std::chrono::nanoseconds>;
  TimePoint _start; ///< Start time at which the session began.

  /// How long the user said to delay for this session.
  std::chrono::microseconds _user_specified_delay_duration{0};

  /// The desired length of time in ms to replay this session.
  double _rate_multiplier = 0.0;
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

  /** Poll until there is header data to read.
   *
   * @param[in] timeout The timeout, in milliseconds, for the poll.
   *
   * @return 0 if the poll timed out, -1 on failure or the socket is closed, a
   * positive value on success.
   */
  virtual swoc::Rv<int> poll_for_headers(std::chrono::milliseconds timeout);

  /** Poll until there is data on the socket.
   *
   * @param[in] timeout The timeout, in milliseconds, for the poll.
   * @param[in] events The event(s) to poll upon. (See the man page for poll(2)).
   *
   * @return 0 if the poll timed out, -1 on failure or the socket is closed, a
   * positive value on success.
   */
  virtual swoc::Rv<int> poll_for_data_on_socket(
      std::chrono::milliseconds timeout,
      short events = POLLIN);

  virtual swoc::Rv<std::shared_ptr<HttpHeader>> read_and_parse_request(swoc::FixedBufferWriter &w);

  /** Read body bytes out of the socket.
   *
   * @param[in] hdr The headers which specify how many body bytes to read.
   *
   * @param[in] expected_content_size The response's content-length value
   * or, failing that, the content:size value from the dumped response.
   *
   * @param[in] bytes_read The content read to this put from the socket.
   *
   * @return The number of total drained body bytes, including the contents of
   * initial. This count is strictly the number of body bytes and does not
   * include any chunk header bytes (if chunk encoding was used).
   */
  virtual swoc::Rv<size_t>
  drain_body(HttpHeader const &hdr, size_t expected_content_size, swoc::TextView bytes_read);

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
      double rate_multiplier);
  virtual swoc::Errata run_transaction(Txn const &json_txn);

protected:
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
  virtual swoc::Rv<ssize_t> read_headers(swoc::FixedBufferWriter &w);

private:
  virtual swoc::Rv<size_t>
  drain_body_internal(HttpHeader &hdr, Txn const &json_txn, swoc::TextView initial);

private:
  int _fd = -1; ///< Socket.
  ssize_t _body_offset = 0;
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

/** A class encapsulating how Proxy Verifier should behave in a TLS handshake.
 *
 * This is used by the Verifier Server. Instances of this are keyed off of SNI.
 */
class TLSHandshakeBehavior
{
public:
  TLSHandshakeBehavior() = default;
  // Make sure we don't accidentally copy these.
  TLSHandshakeBehavior(TLSHandshakeBehavior const &) = delete;
  TLSHandshakeBehavior(TLSHandshakeBehavior &&) = default;
  TLSHandshakeBehavior &operator=(TLSHandshakeBehavior &&) = default;
  ~TLSHandshakeBehavior() = default;

  /** Set the TLS verify mode to use via SSL_set_verify. */
  void set_verify_mode(int verify_mode);

  /** A getter for the TLS verify mode set via set_verify_mode. */
  int get_verify_mode() const;

  /** Set the raw bytes to use in SSL_select_next_proto to specify
   * the server's accepted protocols.
   *
   * @param[in] alpn_protocols The protos string accepted by
   * SSL_select_next_proto. This has its own specific length-value structure.
   * See https://www.openssl.org/docs/man1.1.0/man3/SSL_set_alpn_protos.html
   * for details.
   */
  void set_alpn_protocols_string(std::string_view alpn_protocols);

  /** A getter for the string set via set_alpn_protocols_string. */
  std::string_view get_alpn_wire_string() const;

private:
  /// The verify mode to pass to SSL_set_verify().
  int _verify_mode = SSL_VERIFY_NONE;
  /// The exact set of bytes to pass to SSL_CTX_set_alpn_protos.
  std::string _alpn_wire_string;
};

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
  /** @see Session::write */
  swoc::Rv<ssize_t>
  write(HttpHeader const &hdr) override
  {
    // The base Session::write will serialize the header then polymorphically
    // call the TLSSession::write(TextView) version.
    return Session::write(hdr);
  }

  /** Poll until there is data on the socket after an SSL operation fails.
   *
   * Note that Proxy Verifier is organized using non-blocking sockets in which
   * read or write operations are attempted with a poll used after EAGAIN or
   * SSL_ERROR_WANT_READ/WRITE errors. This handles the poll for the latter
   * such SSL errors.
   *
   * @param[in] timeout The timeout, in milliseconds, for the poll.
   * @param[in] ssl_error The ssl_error retrieved after an SSL_write or SSL_read failure.
   *
   * @return 0 if the poll timed out, -1 on failure or the socket is closed, a
   * positive value on success.
   */
  virtual swoc::Rv<int> poll_for_data_on_ssl_socket(
      std::chrono::milliseconds timeout,
      int ssl_error);

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
  static void terminate();

  /** Register the TLS handshake verification mode of the server per the SNI.
   *
   * This function is only relevant to the server.
   *
   * This specifies what verification mode should be done against the client in
   * the TLS handshake if the client uses the given SNI in the client hello.
   *
   * @param[in] sni The SNI which is the key for the handshake behavior.
   *
   * @param[in] handshake_behavior Dictates how proxy verifier should behave
   * during a TLS handshake with the given SNI.
   */
  static void register_tls_handshake_behavior(
      std::string_view sni,
      TLSHandshakeBehavior &&handshake_behavior);

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

  /** A lookup function for the registered alpn protocol string given the SNI.
   *
   * This function is only relevant to the server.
   *
   * @param[in] sni The SNI key from which the alpn string is queried.
   *
   * @return The wire format alpn protocol string for the given SNI previously
   * registered via register_sni_for_client_verification. If no such SNI has
   * been registered, then an empty string will be returned as a default.
   */
  static std::string_view get_alpn_protocol_string_for_sni(std::string_view sni);

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
  static swoc::Errata client_init(SSL_CTX *&client_context);
  static swoc::Errata server_init(SSL_CTX *&server_context);
  static void terminate(SSL_CTX *&context);

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

  /** The handshake behavior of the verifier server against the proxy in the TLS
   * handshake as specified per the SNI received from the proxy.
   */
  static std::unordered_map<std::string, TLSHandshakeBehavior> _handshake_behavior_per_sni;
};

class H2StreamState
{
public:
  H2StreamState();
  ~H2StreamState();

  /** Increment the nghttp2 reference count on buf and return a view of it.
   *
   * A reference count to the buffer will be held for the remainder of the
   * lifetime of the stream.
   *
   * @param[in] buf The nghttp2 ref counted buffer to register and for which a
   * TextView will be returned.
   *
   * @return A view representation of the given buffer.
   */
  swoc::TextView register_rcbuf(nghttp2_rcbuf *rcbuf);

  /** Indicate that the stream has closed. */
  void set_stream_has_closed();

  /** Return whether this stream has closed. */
  bool get_stream_has_closed() const;

  /** Set the stream_id for this and the appropriate members. */
  void set_stream_id(int32_t id);

  /** Retrieve the stream id for this stream. */
  int32_t get_stream_id() const;

  /** Store the nghttp2 response headers to be freed upon destruction. */
  void store_nv_response_headers_to_free(nghttp2_nv *hdrs);

  /** Store the nghttp2 request headers to be freed upon destruction. */
  void store_nv_request_headers_to_free(nghttp2_nv *hdrs);

public:
  size_t _send_body_offset = 0;
  char const *_body_to_send = nullptr;
  size_t _send_body_length = 0;
  size_t _received_body_length = 0;
  bool _wait_for_continue = false;
  std::string _key;
  /** The composed URL parts from :method, :authority, and :path pseudo headers
   * from the request.
   *
   * This is stored in this object to persist its storage because parse_url
   * assigns from this string TextViews.
   */
  std::string _composed_url;
  std::chrono::time_point<std::chrono::system_clock> _stream_start;
  HttpHeader const *_specified_response = nullptr;

  /// The HTTP request headers for this stream.
  std::shared_ptr<HttpHeader> _request_from_client;
  /// The HTTP response headers for this stream.
  std::shared_ptr<HttpHeader> _response_from_server;

private:
  int32_t _stream_id = -1;
  std::deque<nghttp2_rcbuf *> _rcbufs_to_free;
  bool _stream_has_closed = false;
  nghttp2_nv *_request_nv_headers = nullptr;
  nghttp2_nv *_response_nv_headers = nullptr;
};

class H2Session : public TLSSession
{
public:
  using super_type = TLSSession;
  H2Session();
  H2Session(swoc::TextView const &client_sni, int client_verify_mode = SSL_VERIFY_NONE);
  ~H2Session();
  swoc::Rv<ssize_t> read(swoc::MemSpan<char> span) override;
  swoc::Rv<ssize_t> write(swoc::TextView data) override;
  swoc::Rv<ssize_t> write(HttpHeader const &hdr) override;

  /** For HTTP/2, we read on the socket until an entire stream is done.
   *
   * For HTTP/1, we first read headers to get the Content-Length or other
   * header information to direct reading the body. For HTTP/2, this isn't
   * an issue because bodies are explicitly framed.
   */
  swoc::Rv<int> poll_for_headers(std::chrono::milliseconds timeout) override;
  swoc::Rv<std::shared_ptr<HttpHeader>> read_and_parse_request(swoc::FixedBufferWriter &w) override;
  swoc::Rv<size_t> drain_body(
      HttpHeader const &hdr,
      size_t expected_content_size,
      swoc::TextView bytes_read) override;

  swoc::Errata accept() override;
  swoc::Errata connect() override;
  static swoc::Errata init(int *process_exit_code);
  static void terminate();
  swoc::Errata client_session_init();
  swoc::Errata server_session_init();
  swoc::Errata send_connection_settings();
  swoc::Errata run_transactions(
      std::list<Txn> const &txn,
      swoc::IPEndpoint const *real_target,
      double rate_multiplier) override;
  swoc::Errata run_transaction(Txn const &txn) override;

  nghttp2_session *
  get_session()
  {
    return _session;
  }

  /** Indicate that the stream has ended (received the END_STREAM flag).
   *
   * @param[in] stream_id The stream identifier for which the end stream has
   * been processed.
   */
  void set_stream_has_ended(int32_t stream_id);

  /// Whether an entire stream has been received and is ready for processing.
  bool get_a_stream_has_ended() const;

  /// Return whether this session is for a listening server.
  bool get_is_server() const;

  void record_stream_state(int32_t stream_id, std::shared_ptr<H2StreamState> stream_state);

  /** Indicates that that the user should receive a non-zero status code.
   *
   * Most of this code is blocking a procedural and this can be communicated to
   * the caller via Errata. But the HTTP/2 nghttp2 callbacks do not return
   * directly to a caller. Therefore this is used to communicate a non-zero
   * status.
   */
  static void set_non_zero_exit_status();

public:
  /// A mapping from stream_id to H2StreamState.
  std::unordered_map<int32_t, std::shared_ptr<H2StreamState>> _stream_map;

protected:
  static swoc::Errata client_init(SSL_CTX *&client_context);
  static swoc::Errata server_init(SSL_CTX *&server_context);
  static void terminate(SSL_CTX *&client_context);

private:
  /** Populate an nghttp2 vector from the information in an HttpHeader instance.
   *
   * @param[in] hdr The instance from which to pack headers.
   * @param[out] nv_hdr The packed headers.
   * @param[out] hdr_count The size of the nv_hdr vector.
   *
   * @return Any errata information from the packing operation.
   */
  swoc::Errata pack_headers(HttpHeader const &hdr, nghttp2_nv *&nv_hdr, int &hdr_count);
  nghttp2_nv tv_to_nv(char const *name, swoc::TextView v);
  void set_expected_response_for_last_request(HttpHeader const &response);

private:
  /// Whether this session is for a listening server.
  bool _is_server = false;

  nghttp2_session *_session = nullptr;
  nghttp2_session_callbacks *_callbacks = nullptr;
  nghttp2_option *_options = nullptr;
  bool _h2_is_negotiated = false;

  std::deque<int32_t> _ended_streams;
  std::shared_ptr<H2StreamState> _last_added_stream;

#ifndef OPENSSL_NO_NEXTPROTONEG
  static unsigned char next_proto_list[256];
  static size_t next_proto_list_len;
#endif /* !OPENSSL_NO_NEXTPROTONEG */

  /** The client context to use for HTTP/2 connections.
   *
   * This is used per HTTP/2 connection so that ALPN advertises h2. For HTTP/1
   * TLS connections, client_context is used which does not advertise h2
   * support.
   *
   * A dedicated server context is not needed because, if H2Session::init() is
   * used, the same server_context is used for both TLS and HTTP/2 sessions.
   */
  static SSL_CTX *h2_client_context;

  /// The system status code. This is set to non-zero if problems are detected.
  static int *process_exit_code;
};

class ChunkCodex
{
public:
  /// The callback when a chunk is decoded.
  /// @param chunk Chunk body (not headers, etc.) for the chunk in the provided view.
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
  static constexpr size_t default_max_threads = 2'000;
  void set_max_threads(size_t new_max);

protected:
  std::list<std::thread> _allThreads;
  // Pool of ready / idle threads.
  std::deque<ThreadInfo *> _threadPool;
  std::condition_variable _threadPoolCvar;
  std::mutex _threadPoolMutex;
  size_t max_threads = default_max_threads;
};
