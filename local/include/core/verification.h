/** @file
 * Common data structures and definitions for Proxy Verifier tools.
 *
 * Copyright 2021, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "http.h"

#include <memory>
#include <string>
#include <vector>
#include <unordered_map>

#include "swoc/Errata.h"
#include "swoc/TextView.h"

static const std::string VERIFICATION_DIRECTIVE_EQUALS{"equal"};
static const std::string VERIFICATION_DIRECTIVE_PRESENCE{"present"};
static const std::string VERIFICATION_DIRECTIVE_ABSENCE{"absent"};
static const std::string VERIFICATION_DIRECTIVE_CONTAINS{"contains"};
static const std::string VERIFICATION_DIRECTIVE_PREFIX{"prefix"};
static const std::string VERIFICATION_DIRECTIVE_SUFFIX{"suffix"};

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
