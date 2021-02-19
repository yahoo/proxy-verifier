/** @file
 * Common implementation for Proxy Verifier
 *
 * Copyright 2021, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "core/verification.h"

#include "swoc/bwf_ex.h"
#include "swoc/bwf_ip.h"
#include "swoc/bwf_std.h"

using swoc::Errata;
using swoc::TextView;
using namespace swoc::literals;
using namespace std::literals;

using MSG_BUFF = swoc::LocalBufferWriter<1024>;

RuleCheck::RuleOptions RuleCheck::options;
RuleCheck::URLRuleOptions RuleCheck::url_rule_options;
RuleCheck::DuplicateFieldRuleOptions RuleCheck::duplicate_field_options;

void
RuleCheck::options_init()
{
  options = RuleOptions();

  // Overloaded resolution works with function pointers, but not with
  // std::functions. We have to help out the compiler, therefore, via casting
  // to the correct function type.
  using single_field_function_type = std::shared_ptr<RuleCheck> (*)(TextView, TextView);
  options[TextView(VERIFICATION_DIRECTIVE_EQUALS)] =
      static_cast<single_field_function_type>(make_equality);
  options[TextView(VERIFICATION_DIRECTIVE_PRESENCE)] =
      static_cast<single_field_function_type>(make_presence);
  options[TextView(VERIFICATION_DIRECTIVE_ABSENCE)] =
      static_cast<single_field_function_type>(make_absence);
  options[TextView(VERIFICATION_DIRECTIVE_CONTAINS)] =
      static_cast<single_field_function_type>(make_contains);
  options[TextView(VERIFICATION_DIRECTIVE_PREFIX)] =
      static_cast<single_field_function_type>(make_prefix);
  options[TextView(VERIFICATION_DIRECTIVE_SUFFIX)] =
      static_cast<single_field_function_type>(make_suffix);

  url_rule_options = URLRuleOptions();
  using url_function_type = std::shared_ptr<RuleCheck> (*)(UrlPart, TextView);
  url_rule_options[TextView(VERIFICATION_DIRECTIVE_EQUALS)] =
      static_cast<url_function_type>(make_equality);
  url_rule_options[TextView(VERIFICATION_DIRECTIVE_PRESENCE)] =
      static_cast<url_function_type>(make_presence);
  url_rule_options[TextView(VERIFICATION_DIRECTIVE_ABSENCE)] =
      static_cast<url_function_type>(make_absence);
  url_rule_options[TextView(VERIFICATION_DIRECTIVE_CONTAINS)] =
      static_cast<url_function_type>(make_contains);
  url_rule_options[TextView(VERIFICATION_DIRECTIVE_PREFIX)] =
      static_cast<url_function_type>(make_prefix);
  url_rule_options[TextView(VERIFICATION_DIRECTIVE_SUFFIX)] =
      static_cast<url_function_type>(make_suffix);

  duplicate_field_options = DuplicateFieldRuleOptions();
  using duplicate_field_function_type =
      std::shared_ptr<RuleCheck> (*)(TextView, std::vector<TextView> &&);
  duplicate_field_options[TextView(VERIFICATION_DIRECTIVE_EQUALS)] =
      static_cast<duplicate_field_function_type>(make_equality);
  duplicate_field_options[TextView(VERIFICATION_DIRECTIVE_PRESENCE)] =
      static_cast<duplicate_field_function_type>(make_presence);
  duplicate_field_options[TextView(VERIFICATION_DIRECTIVE_ABSENCE)] =
      static_cast<duplicate_field_function_type>(make_absence);
  duplicate_field_options[TextView(VERIFICATION_DIRECTIVE_CONTAINS)] =
      static_cast<duplicate_field_function_type>(make_contains);
  duplicate_field_options[TextView(VERIFICATION_DIRECTIVE_PREFIX)] =
      static_cast<duplicate_field_function_type>(make_prefix);
  duplicate_field_options[TextView(VERIFICATION_DIRECTIVE_SUFFIX)] =
      static_cast<duplicate_field_function_type>(make_suffix);
}

std::shared_ptr<RuleCheck>
RuleCheck::make_rule_check(TextView localized_name, TextView localized_value, TextView rule_type)
{
  Errata errata;

  auto fn_iter = options.find(rule_type);
  if (fn_iter == options.end()) {
    errata.info(R"(Invalid Test: Key: "{}")", rule_type);
    return nullptr;
  }
  return fn_iter->second(localized_name, localized_value);
}

std::shared_ptr<RuleCheck>
RuleCheck::make_rule_check(UrlPart url_part, TextView localized_value, TextView rule_type)
{
  Errata errata;

  auto fn_iter = url_rule_options.find(rule_type);
  if (fn_iter == url_rule_options.end()) {
    errata.info(R"(Invalid Test: Key: "{}")", rule_type);
    return nullptr;
  }
  return fn_iter->second(url_part, localized_value);
}

std::shared_ptr<RuleCheck>
RuleCheck::make_rule_check(
    TextView localized_name,
    std::vector<TextView> &&localized_values,
    TextView rule_type)
{
  Errata errata;

  auto fn_iter = duplicate_field_options.find(rule_type);
  if (fn_iter == duplicate_field_options.end()) {
    errata.info(R"(Invalid Test: Key: "{}")", rule_type);
    return nullptr;
  }
  return fn_iter->second(localized_name, std::move(localized_values));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_equality(TextView name, TextView value)
{
  return std::shared_ptr<RuleCheck>(new EqualityCheck(name, value));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_equality(UrlPart url_part, TextView value)
{
  return std::shared_ptr<RuleCheck>(new EqualityCheck(url_part, value));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_equality(TextView name, std::vector<TextView> &&values)
{
  return std::shared_ptr<RuleCheck>(new EqualityCheck(name, std::move(values)));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_presence(TextView name, TextView /* value */)
{
  return std::shared_ptr<RuleCheck>(new PresenceCheck(name, !EXPECTS_DUPLICATE_FIELDS));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_presence(UrlPart url_part, TextView /* value */)
{
  return std::shared_ptr<RuleCheck>(new PresenceCheck(url_part));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_presence(TextView name, std::vector<TextView> && /* values */)
{
  return std::shared_ptr<RuleCheck>(new PresenceCheck(name, EXPECTS_DUPLICATE_FIELDS));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_absence(TextView name, TextView /* value */)
{
  return std::shared_ptr<RuleCheck>(new AbsenceCheck(name, !EXPECTS_DUPLICATE_FIELDS));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_absence(UrlPart url_part, TextView /* value */)
{
  return std::shared_ptr<RuleCheck>(new AbsenceCheck(url_part));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_absence(TextView name, std::vector<TextView> && /* values */)
{
  return std::shared_ptr<RuleCheck>(new AbsenceCheck(name, EXPECTS_DUPLICATE_FIELDS));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_contains(TextView name, TextView value)
{
  return std::shared_ptr<RuleCheck>(new ContainsCheck(name, value));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_contains(UrlPart url_part, TextView value)
{
  return std::shared_ptr<RuleCheck>(new ContainsCheck(url_part, value));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_contains(TextView name, std::vector<TextView> &&values)
{
  return std::shared_ptr<RuleCheck>(new ContainsCheck(name, std::move(values)));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_prefix(TextView name, TextView value)
{
  return std::shared_ptr<RuleCheck>(new PrefixCheck(name, value));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_prefix(UrlPart url_part, TextView value)
{
  return std::shared_ptr<RuleCheck>(new PrefixCheck(url_part, value));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_prefix(TextView name, std::vector<TextView> &&values)
{
  return std::shared_ptr<RuleCheck>(new PrefixCheck(name, std::move(values)));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_suffix(TextView name, TextView value)
{
  return std::shared_ptr<RuleCheck>(new SuffixCheck(name, value));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_suffix(UrlPart url_part, TextView value)
{
  return std::shared_ptr<RuleCheck>(new SuffixCheck(url_part, value));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_suffix(TextView name, std::vector<TextView> &&values)
{
  return std::shared_ptr<RuleCheck>(new SuffixCheck(name, std::move(values)));
}

EqualityCheck::EqualityCheck(TextView name, TextView value)
{
  _name = name;
  _value = value;
  _is_field = true;
}

EqualityCheck::EqualityCheck(UrlPart url_part, TextView value)
{
  _name = URL_PART_NAMES[url_part];
  _value = value;
  _is_field = false;
}

EqualityCheck::EqualityCheck(TextView name, std::vector<TextView> &&values)
{
  _name = name;
  _values = std::move(values);
  _expects_duplicate_fields = true;
  _is_field = true;
}

PresenceCheck::PresenceCheck(TextView name, bool expects_duplicate_fields)
{
  _name = name;
  _expects_duplicate_fields = expects_duplicate_fields;
  _is_field = true;
}

PresenceCheck::PresenceCheck(UrlPart url_part)
{
  _name = URL_PART_NAMES[url_part];
  _is_field = false;
}

AbsenceCheck::AbsenceCheck(TextView name, bool expects_duplicate_fields)
{
  _name = name;
  _expects_duplicate_fields = expects_duplicate_fields;
  _is_field = true;
}

AbsenceCheck::AbsenceCheck(UrlPart url_part)
{
  _name = URL_PART_NAMES[url_part];
  _is_field = false;
}

ContainsCheck::ContainsCheck(TextView name, TextView value)
{
  _name = name;
  _value = value;
  _is_field = true;
}

ContainsCheck::ContainsCheck(UrlPart url_part, TextView value)
{
  _name = URL_PART_NAMES[url_part];
  _value = value;
  _is_field = false;
}

ContainsCheck::ContainsCheck(TextView name, std::vector<TextView> &&values)
{
  _name = name;
  _values = std::move(values);
  _expects_duplicate_fields = true;
  _is_field = true;
}

PrefixCheck::PrefixCheck(TextView name, TextView value)
{
  _name = name;
  _value = value;
  _is_field = true;
}

PrefixCheck::PrefixCheck(UrlPart url_part, TextView value)
{
  _name = URL_PART_NAMES[url_part];
  _value = value;
  _is_field = false;
}

PrefixCheck::PrefixCheck(TextView name, std::vector<TextView> &&values)
{
  _name = name;
  _values = std::move(values);
  _expects_duplicate_fields = true;
  _is_field = true;
}

SuffixCheck::SuffixCheck(TextView name, TextView value)
{
  _name = name;
  _value = value;
  _is_field = true;
}

SuffixCheck::SuffixCheck(UrlPart url_part, TextView value)
{
  _name = URL_PART_NAMES[url_part];
  _value = value;
  _is_field = false;
}

SuffixCheck::SuffixCheck(TextView name, std::vector<TextView> &&values)
{
  _name = name;
  _values = std::move(values);
  _expects_duplicate_fields = true;
  _is_field = true;
}

bool
EqualityCheck::test(TextView key, TextView name, TextView value) const
{
  Errata errata;
  if (name.empty()) {
    errata.info(
        R"(Equals Violation: Absent. Key: "{}", {}: "{}", Correct Value: "{}")",
        key,
        target_type(),
        _name,
        _value);
  } else if (strcmp(value, _value)) {
    errata.info(
        R"(Equals Violation: Different. Key: "{}", {}: "{}", Correct Value: "{}", Actual Value: "{}")",
        key,
        target_type(),
        _name,
        _value,
        value);
  } else {
    errata.info(
        R"(Equals Success: Key: "{}", {}: "{}", Value: "{}")",
        key,
        target_type(),
        _name,
        _value);
    return true;
  }
  return false;
}

bool
EqualityCheck::test(TextView key, TextView name, std::vector<TextView> const &values) const
{
  Errata errata;
  if (name.empty()) {
    MSG_BUFF message;
    message.print(R"(Equals Violation: Absent. Key: "{}", {}: "{}", )", key, target_type(), _name);
    message.print(R"(Correct Values:)");
    for (auto const &value : _values) {
      message.print(R"( "{}")", value);
    }
  } else if (_values != values) {
    MSG_BUFF message;
    message
        .print(R"(Equals Violation: Different. Key: "{}", {}: "{}", )", key, target_type(), _name);

    message.print(R"(Correct Values:)");
    for (auto const &value : _values) {
      message.print(R"( "{}")", value);
    }
    message.print(R"(, Received Values:)");
    for (auto const &value : values) {
      message.print(R"( "{}")", value);
    }
    errata.info(message.view());
  } else {
    MSG_BUFF message;
    message.print(R"(Equals Success: Key: "{}", {}: "{}", Values:)", key, target_type(), _name);
    for (auto const &value : values) {
      message.print(R"( "{}")", value);
    }
    errata.info(message.view());
    return true;
  }
  return false;
}

bool
PresenceCheck::test(TextView key, TextView name, TextView value) const
{
  Errata errata;
  if (name.empty()) {
    errata.info(R"(Presence Violation: Absent. Key: "{}", {}: "{}")", key, target_type(), _name);
    return false;
  }
  errata.info(
      R"(Presence Success: Key: "{}", {}: "{}", Value: "{}")",
      key,
      target_type(),
      _name,
      value);
  return true;
}

bool
PresenceCheck::test(TextView key, TextView name, std::vector<TextView> const &values) const
{
  Errata errata;
  if (name.empty()) {
    errata.info(R"(Presence Violation: Absent. Key: "{}", {}: "{}")", key, target_type(), _name);
    return false;
  }
  MSG_BUFF message;
  message.print(R"(Presence Success: Key: "{}", {}: "{}", Values:)", key, target_type(), _name);
  for (auto const &value : values) {
    message.print(R"( "{}")", value);
  }
  errata.info(message.view());
  return true;
}

bool
AbsenceCheck::test(TextView key, TextView name, TextView value) const
{
  Errata errata;
  if (!name.empty()) {
    errata.info(
        R"(Absence Violation: Present. Key: "{}", {}: "{}", Value: "{}")",
        key,
        target_type(),
        _name,
        value);
    return false;
  }
  errata.info(R"(Absence Success: Key: "{}", {}: "{}")", key, target_type(), _name);
  return true;
}

bool
AbsenceCheck::test(TextView key, TextView name, std::vector<TextView> const &values) const
{
  Errata errata;
  if (!name.empty()) {
    MSG_BUFF message;
    message.print(
        R"(Absence Violation: Present. Key: "{}", {}: "{}", Values:)",
        key,
        target_type(),
        _name);
    for (auto const &value : values) {
      message.print(R"( "{}")", value);
    }
    errata.info(message.view());
    return false;
  }
  errata.info(R"(Absence Success: Key: "{}", {}: "{}")", key, target_type(), _name);
  return true;
}

bool
SubstrCheck::test(TextView key, TextView name, TextView value) const
{
  Errata errata;
  if (name.empty()) {
    errata.info(
        R"({} Violation: Absent. Key: "{}", {}: "{}", Required Value: "{}")",
        get_test_name(),
        key,
        target_type(),
        _name,
        _value);
  } else if (test_tv(value, _value)) {
    errata.info(
        R"({} Violation: Not Found. Key: "{}", {}: "{}", Required Value: "{}", Actual Value: "{}")",
        get_test_name(),
        key,
        target_type(),
        _name,
        _value,
        value);
  } else {
    errata.info(
        R"({} Success: Key: "{}", {}: "{}", Required Value: "{}", Value: "{}")",
        get_test_name(),
        key,
        target_type(),
        _name,
        _value,
        value);
    return true;
  }
  return false;
}

bool
SubstrCheck::test(TextView key, TextView name, std::vector<TextView> const &values) const
{
  Errata errata;
  if (name.empty() || values.size() != _values.size()) {
    MSG_BUFF message;
    message.print(
        R"({} Violation: Absent/Mismatched. Key: "{}", {}: "{}", )",
        get_test_name(),
        key,
        target_type(),
        _name);
    message.print(R"(Required Values:)");
    for (auto const &value : _values) {
      message.print(R"( "{}")", value);
    }
    message.print(R"(, Received Values:)");
    for (auto const &value : values) {
      message.print(R"( "{}")", value);
    }
    errata.info(message.view());
    return false;
  }
  auto value_it = values.begin();
  auto test_it = _values.begin();
  while (value_it != values.end()) {
    if (test_tv(*value_it, *test_it)) {
      MSG_BUFF message;
      message.print(
          R"({} Violation: Not Found. Key: "{}", {}: "{}", )",
          get_test_name(),
          key,
          target_type(),
          _name);

      message.print(R"(Required Values:)");
      for (auto const &value : _values) {
        message.print(R"( "{}")", value);
      }
      message.print(R"(, Received Values:)");
      for (auto const &value : values) {
        message.print(R"( "{}")", value);
      }
      errata.info(message.view());
      break;
    }
    ++value_it;
    ++test_it;
  }
  MSG_BUFF message;
  message.print(R"({} Success: Key: "{}", {}: "{}", )", get_test_name(), key, target_type(), _name);

  message.print(R"(Required Values:)");
  for (auto const &value : _values) {
    message.print(R"( "{}")", value);
  }
  message.print(R"(, Received Values:)");
  for (auto const &value : values) {
    message.print(R"( "{}")", value);
  }
  errata.info(message.view());
  return true;
}

// Return true for failure, false for success
bool
ContainsCheck::test_tv(TextView value, TextView test) const
{
  return (value.find(test) == std::string::npos);
}

bool
PrefixCheck::test_tv(TextView value, TextView test) const
{
  return (!value.starts_with(test));
}

bool
SuffixCheck::test_tv(TextView value, TextView test) const
{
  return (!value.ends_with(test));
}
