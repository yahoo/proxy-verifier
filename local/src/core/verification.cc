/** @file
 * Common implementation for Proxy Verifier
 *
 * Copyright 2022, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "core/verification.h"
#include "core/ProxyVerifier.h"

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
  using single_field_function_type = std::shared_ptr<RuleCheck> (*)(TextView, TextView, bool, bool);
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
  using url_function_type = std::shared_ptr<RuleCheck> (*)(UrlPart, TextView, bool, bool);
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
      std::shared_ptr<RuleCheck> (*)(TextView, std::vector<TextView> &&, bool, bool);
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
RuleCheck::make_rule_check(
    TextView localized_name,
    TextView localized_value,
    TextView rule_type,
    bool is_inverted,
    bool is_nocase)
{
  Errata errata;

  auto fn_iter = options.find(rule_type);
  if (fn_iter == options.end()) {
    errata.note(S_INFO, R"(Invalid Test: Key: "{}")", rule_type);
    return nullptr;
  }
  return fn_iter->second(localized_name, localized_value, is_inverted, is_nocase);
}

std::shared_ptr<RuleCheck>
RuleCheck::make_rule_check(
    UrlPart url_part,
    TextView localized_value,
    TextView rule_type,
    bool is_inverted,
    bool is_nocase)
{
  Errata errata;

  auto fn_iter = url_rule_options.find(rule_type);
  if (fn_iter == url_rule_options.end()) {
    errata.note(S_INFO, R"(Invalid Test: Key: "{}")", rule_type);
    return nullptr;
  }
  return fn_iter->second(url_part, localized_value, is_inverted, is_nocase);
}

std::shared_ptr<RuleCheck>
RuleCheck::make_rule_check(
    TextView localized_name,
    std::vector<TextView> &&localized_values,
    TextView rule_type,
    bool is_inverted,
    bool is_nocase)
{
  Errata errata;

  auto fn_iter = duplicate_field_options.find(rule_type);
  if (fn_iter == duplicate_field_options.end()) {
    errata.note(S_INFO, R"(Invalid Test: Key: "{}")", rule_type);
    return nullptr;
  }
  return fn_iter->second(localized_name, std::move(localized_values), is_inverted, is_nocase);
}

std::shared_ptr<RuleCheck>
RuleCheck::make_equality(TextView name, TextView value, bool is_inverted, bool is_nocase)
{
  return std::shared_ptr<RuleCheck>(new EqualityCheck(name, value, is_inverted, is_nocase));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_equality(UrlPart url_part, TextView value, bool is_inverted, bool is_nocase)
{
  return std::shared_ptr<RuleCheck>(new EqualityCheck(url_part, value, is_inverted, is_nocase));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_equality(
    TextView name,
    std::vector<TextView> &&values,
    bool is_inverted,
    bool is_nocase)
{
  return std::shared_ptr<RuleCheck>(
      new EqualityCheck(name, std::move(values), is_inverted, is_nocase));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_presence(
    TextView name,
    TextView /* value */,
    bool is_inverted,
    bool /* is_nocase */)
{
  return std::shared_ptr<RuleCheck>(
      new PresenceCheck(name, !EXPECTS_DUPLICATE_FIELDS, is_inverted));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_presence(
    UrlPart url_part,
    TextView /* value */,
    bool is_inverted,
    bool /* is_nocase */)
{
  return std::shared_ptr<RuleCheck>(new PresenceCheck(url_part, is_inverted));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_presence(
    TextView name,
    std::vector<TextView> && /* values */,
    bool is_inverted,
    bool /* is_nocase */)
{
  return std::shared_ptr<RuleCheck>(new PresenceCheck(name, EXPECTS_DUPLICATE_FIELDS, is_inverted));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_absence(TextView name, TextView /* value */, bool is_inverted, bool /* is_nocase */)
{
  return std::shared_ptr<RuleCheck>(new AbsenceCheck(name, !EXPECTS_DUPLICATE_FIELDS, is_inverted));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_absence(
    UrlPart url_part,
    TextView /* value */,
    bool is_inverted,
    bool /* is_nocase */)
{
  return std::shared_ptr<RuleCheck>(new AbsenceCheck(url_part, is_inverted));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_absence(
    TextView name,
    std::vector<TextView> && /* values */,
    bool is_inverted,
    bool /* is_nocase */)
{
  return std::shared_ptr<RuleCheck>(new AbsenceCheck(name, EXPECTS_DUPLICATE_FIELDS, is_inverted));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_contains(TextView name, TextView value, bool is_inverted, bool is_nocase)
{
  return std::shared_ptr<RuleCheck>(new ContainsCheck(name, value, is_inverted, is_nocase));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_contains(UrlPart url_part, TextView value, bool is_inverted, bool is_nocase)
{
  return std::shared_ptr<RuleCheck>(new ContainsCheck(url_part, value, is_inverted, is_nocase));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_contains(
    TextView name,
    std::vector<TextView> &&values,
    bool is_inverted,
    bool is_nocase)
{
  return std::shared_ptr<RuleCheck>(
      new ContainsCheck(name, std::move(values), is_inverted, is_nocase));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_prefix(TextView name, TextView value, bool is_inverted, bool is_nocase)
{
  return std::shared_ptr<RuleCheck>(new PrefixCheck(name, value, is_inverted, is_nocase));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_prefix(UrlPart url_part, TextView value, bool is_inverted, bool is_nocase)
{
  return std::shared_ptr<RuleCheck>(new PrefixCheck(url_part, value, is_inverted, is_nocase));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_prefix(
    TextView name,
    std::vector<TextView> &&values,
    bool is_inverted,
    bool is_nocase)
{
  return std::shared_ptr<RuleCheck>(
      new PrefixCheck(name, std::move(values), is_inverted, is_nocase));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_suffix(TextView name, TextView value, bool is_inverted, bool is_nocase)
{
  return std::shared_ptr<RuleCheck>(new SuffixCheck(name, value, is_inverted, is_nocase));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_suffix(UrlPart url_part, TextView value, bool is_inverted, bool is_nocase)
{
  return std::shared_ptr<RuleCheck>(new SuffixCheck(url_part, value, is_inverted, is_nocase));
}

std::shared_ptr<RuleCheck>
RuleCheck::make_suffix(
    TextView name,
    std::vector<TextView> &&values,
    bool is_inverted,
    bool is_nocase)
{
  return std::shared_ptr<RuleCheck>(
      new SuffixCheck(name, std::move(values), is_inverted, is_nocase));
}

swoc::TextView
RuleCheck::target_type() const
{
  if (_is_field) {
    return "Field Name";
  } else {
    return "URI Part";
  }
}

swoc::TextView
RuleCheck::get_subtype() const
{
  if (_is_inverted) {
    if (_is_nocase) {
      return "Not No Case ";
    }
    return "Not ";
  }
  if (_is_nocase) {
    return "No Case ";
  } else {
    return "";
  }
}

swoc::TextView
RuleCheck::invert_result(bool success) const
{
  if (_is_inverted) {
    if (success) {
      return "Violation";
    } else {
      return "Success";
    }
  }
  if (success) {
    return "Success";
  } else {
    return "Violation";
  }
}

bool
RuleCheck::invert_if_applicable(bool input) const
{
  if (_is_inverted) {
    return !input;
  } else {
    return input;
  }
}

EqualityCheck::EqualityCheck(TextView name, TextView value, bool is_inverted, bool is_nocase)
{
  _name = name;
  _value = value;
  _is_field = true;
  _is_inverted = is_inverted;
  _is_nocase = is_nocase;
}

EqualityCheck::EqualityCheck(UrlPart url_part, TextView value, bool is_inverted, bool is_nocase)
{
  _name = URL_PART_NAMES[url_part];
  _value = value;
  _is_field = false;
  _is_inverted = is_inverted;
  _is_nocase = is_nocase;
}

EqualityCheck::EqualityCheck(
    TextView name,
    std::vector<TextView> &&values,
    bool is_inverted,
    bool is_nocase)
{
  _name = name;
  _values = std::move(values);
  _expects_duplicate_fields = true;
  _is_field = true;
  _is_inverted = is_inverted;
  _is_nocase = is_nocase;
}

PresenceCheck::PresenceCheck(TextView name, bool expects_duplicate_fields, bool is_inverted)
{
  _name = name;
  _expects_duplicate_fields = expects_duplicate_fields;
  _is_field = true;
  _is_inverted = is_inverted;
  _is_nocase = false;
}

PresenceCheck::PresenceCheck(UrlPart url_part, bool is_inverted)
{
  _name = URL_PART_NAMES[url_part];
  _is_field = false;
  _is_inverted = is_inverted;
  _is_nocase = false;
}

AbsenceCheck::AbsenceCheck(TextView name, bool expects_duplicate_fields, bool is_inverted)
{
  _name = name;
  _expects_duplicate_fields = expects_duplicate_fields;
  _is_field = true;
  _is_inverted = is_inverted;
  _is_nocase = false;
}

AbsenceCheck::AbsenceCheck(UrlPart url_part, bool is_inverted)
{
  _name = URL_PART_NAMES[url_part];
  _is_field = false;
  _is_inverted = is_inverted;
  _is_nocase = false;
}

ContainsCheck::ContainsCheck(TextView name, TextView value, bool is_inverted, bool is_nocase)
{
  _name = name;
  _value = value;
  _is_field = true;
  _is_inverted = is_inverted;
  _is_nocase = is_nocase;
}

ContainsCheck::ContainsCheck(UrlPart url_part, TextView value, bool is_inverted, bool is_nocase)
{
  _name = URL_PART_NAMES[url_part];
  _value = value;
  _is_field = false;
  _is_inverted = is_inverted;
  _is_nocase = is_nocase;
}

ContainsCheck::ContainsCheck(
    TextView name,
    std::vector<TextView> &&values,
    bool is_inverted,
    bool is_nocase)
{
  _name = name;
  _values = std::move(values);
  _expects_duplicate_fields = true;
  _is_field = true;
  _is_inverted = is_inverted;
  _is_nocase = is_nocase;
}

PrefixCheck::PrefixCheck(TextView name, TextView value, bool is_inverted, bool is_nocase)
{
  _name = name;
  _value = value;
  _is_field = true;
  _is_inverted = is_inverted;
  _is_nocase = is_nocase;
}

PrefixCheck::PrefixCheck(UrlPart url_part, TextView value, bool is_inverted, bool is_nocase)
{
  _name = URL_PART_NAMES[url_part];
  _value = value;
  _is_field = false;
  _is_inverted = is_inverted;
  _is_nocase = is_nocase;
}

PrefixCheck::PrefixCheck(
    TextView name,
    std::vector<TextView> &&values,
    bool is_inverted,
    bool is_nocase)
{
  _name = name;
  _values = std::move(values);
  _expects_duplicate_fields = true;
  _is_field = true;
  _is_inverted = is_inverted;
  _is_nocase = is_nocase;
}

SuffixCheck::SuffixCheck(TextView name, TextView value, bool is_inverted, bool is_nocase)
{
  _name = name;
  _value = value;
  _is_field = true;
  _is_inverted = is_inverted;
  _is_nocase = is_nocase;
}

SuffixCheck::SuffixCheck(UrlPart url_part, TextView value, bool is_inverted, bool is_nocase)
{
  _name = URL_PART_NAMES[url_part];
  _value = value;
  _is_field = false;
  _is_inverted = is_inverted;
  _is_nocase = is_nocase;
}

SuffixCheck::SuffixCheck(
    TextView name,
    std::vector<TextView> &&values,
    bool is_inverted,
    bool is_nocase)
{
  _name = name;
  _values = std::move(values);
  _expects_duplicate_fields = true;
  _is_field = true;
  _is_inverted = is_inverted;
  _is_nocase = is_nocase;
}

bool
EqualityCheck::test(TextView key, TextView name, TextView value) const
{
  Errata errata;
  if (name.empty()) {
    errata.note(
        S_INFO,
        R"({}Equals {}: Absent. Key: "{}", {}: "{}", Correct Value: "{}")",
        get_subtype(),
        invert_result(false),
        key,
        target_type(),
        _name,
        _value);
  } else if ((!_is_nocase && strcmp(value, _value)) || (_is_nocase && strcasecmp(value, _value))) {
    errata.note(
        S_INFO,
        R"({}Equals {}: Different. Key: "{}", {}: "{}", Correct Value: "{}", Actual Value: "{}")",
        get_subtype(),
        invert_result(false),
        key,
        target_type(),
        _name,
        _value,
        value);
  } else {
    if (_is_nocase) {
      errata.note(
          S_INFO,
          R"({}Equals {}: Key: "{}", {}: "{}", Required Value: "{}", Value: "{}")",
          get_subtype(),
          invert_result(true),
          key,
          target_type(),
          _name,
          _value,
          value);
    } else {
      errata.note(
          S_INFO,
          R"({}Equals {}: Key: "{}", {}: "{}", Value: "{}")",
          get_subtype(),
          invert_result(true),
          key,
          target_type(),
          _name,
          _value);
    }
    return invert_if_applicable(true);
  }
  return invert_if_applicable(false);
}

bool
EqualityCheck::test(TextView key, TextView name, std::vector<TextView> const &values) const
{
  Errata errata;
  if (name.empty()) {
    MSG_BUFF message;
    message.print(
        R"({}Equals {}: Absent. Key: "{}", {}: "{}", )",
        get_subtype(),
        invert_result(false),
        key,
        target_type(),
        _name);
    message.print(R"(Correct Values:)");
    for (auto const &value : _values) {
      message.print(R"( "{}")", value);
    }
    errata.note(S_INFO, message.view());
    return invert_if_applicable(false);
  }
  bool test_success = true;
  if (values.size() != _values.size()) {
    test_success = false;
  } else {
    auto it = values.begin();
    for (auto const &value : _values) {
      if (!_is_nocase && strcmp(value, *it)) {
        test_success = false;
        break;
      }
      if (_is_nocase && strcasecmp(value, *it)) {
        test_success = false;
        break;
      }
      it++;
    }
  }
  if (!test_success) {
    MSG_BUFF message;
    message.print(
        R"({}Equals {}: Different. Key: "{}", {}: "{}", )",
        get_subtype(),
        invert_result(false),
        key,
        target_type(),
        _name);

    message.print(R"(Correct Values:)");
    for (auto const &value : _values) {
      message.print(R"( "{}")", value);
    }
    message.print(R"(, Received Values:)");
    for (auto const &value : values) {
      message.print(R"( "{}")", value);
    }
    errata.note(S_INFO, message.view());
  } else {
    MSG_BUFF message;
    message.print(
        R"({}Equals {}: Key: "{}", {}: "{}", )",
        get_subtype(),
        invert_result(true),
        key,
        target_type(),
        _name);
    if (_is_nocase) {
      message.print(R"(Required Values:)");
      for (auto const &value : _values) {
        message.print(R"( "{}")", value);
      }
      message.print(R"(, Values:)");
      for (auto const &value : values) {
        message.print(R"( "{}")", value);
      }
    } else {
      message.print(R"(Values:)");
      for (auto const &value : values) {
        message.print(R"( "{}")", value);
      }
    }
    errata.note(S_INFO, message.view());
    return invert_if_applicable(true);
  }
  return invert_if_applicable(false);
}

bool
PresenceCheck::test(TextView key, TextView name, TextView value) const
{
  Errata errata;
  if (name.empty()) {
    errata.note(
        S_INFO,
        R"({}Presence {}: Absent. Key: "{}", {}: "{}")",
        get_subtype(),
        invert_result(false),
        key,
        target_type(),
        _name);
    return invert_if_applicable(false);
  }
  errata.note(
      S_INFO,
      R"({}Presence {}: Key: "{}", {}: "{}", Value: "{}")",
      get_subtype(),
      invert_result(true),
      key,
      target_type(),
      _name,
      value);
  return invert_if_applicable(true);
}

bool
PresenceCheck::test(TextView key, TextView name, std::vector<TextView> const &values) const
{
  Errata errata;
  if (name.empty()) {
    errata.note(
        S_INFO,
        R"({}Presence {}: Absent. Key: "{}", {}: "{}")",
        get_subtype(),
        invert_result(false),
        key,
        target_type(),
        _name);
    return invert_if_applicable(false);
  }
  MSG_BUFF message;
  message.print(
      R"({}Presence {}: Key: "{}", {}: "{}", Values:)",
      get_subtype(),
      invert_result(true),
      key,
      target_type(),
      _name);
  for (auto const &value : values) {
    message.print(R"( "{}")", value);
  }
  errata.note(S_INFO, message.view());
  return invert_if_applicable(true);
}

bool
AbsenceCheck::test(TextView key, TextView name, TextView value) const
{
  Errata errata;
  if (!name.empty()) {
    errata.note(
        S_INFO,
        R"({}Absence {}: Present. Key: "{}", {}: "{}", Value: "{}")",
        get_subtype(),
        invert_result(false),
        key,
        target_type(),
        _name,
        value);
    return invert_if_applicable(false);
  }
  errata.note(
      S_INFO,
      R"({}Absence {}: Key: "{}", {}: "{}")",
      get_subtype(),
      invert_result(true),
      key,
      target_type(),
      _name);
  return invert_if_applicable(true);
}

bool
AbsenceCheck::test(TextView key, TextView name, std::vector<TextView> const &values) const
{
  Errata errata;
  if (!name.empty()) {
    MSG_BUFF message;
    message.print(
        R"({}Absence {}: Present. Key: "{}", {}: "{}", Values:)",
        get_subtype(),
        invert_result(false),
        key,
        target_type(),
        _name);
    for (auto const &value : values) {
      message.print(R"( "{}")", value);
    }
    errata.note(S_INFO, message.view());
    return invert_if_applicable(false);
  }
  errata.note(
      S_INFO,
      R"({}Absence {}: Key: "{}", {}: "{}")",
      get_subtype(),
      invert_result(true),
      key,
      target_type(),
      _name);
  return invert_if_applicable(true);
}

bool
SubstrCheck::test(TextView key, TextView name, TextView value) const
{
  Errata errata;
  if (name.empty()) {
    errata.note(
        S_INFO,
        R"({}{} {}: Absent. Key: "{}", {}: "{}", Required Value: "{}")",
        get_subtype(),
        get_test_name(),
        invert_result(false),
        key,
        target_type(),
        _name,
        _value);
  } else if (test_tv(value, _value)) {
    errata.note(
        S_INFO,
        R"({}{} {}: Not Found. Key: "{}", {}: "{}", Required Value: "{}", Actual Value: "{}")",
        get_subtype(),
        get_test_name(),
        invert_result(false),
        key,
        target_type(),
        _name,
        _value,
        value);
  } else {
    errata.note(
        S_INFO,
        R"({}{} {}: Key: "{}", {}: "{}", Required Value: "{}", Value: "{}")",
        get_subtype(),
        get_test_name(),
        invert_result(true),
        key,
        target_type(),
        _name,
        _value,
        value);
    return invert_if_applicable(true);
  }
  return invert_if_applicable(false);
}

bool
SubstrCheck::test(TextView key, TextView name, std::vector<TextView> const &values) const
{
  Errata errata;
  if (name.empty() || values.size() != _values.size()) {
    MSG_BUFF message;
    message.print(
        R"({}{} {}: Absent/Mismatched. Key: "{}", {}: "{}", )",
        get_subtype(),
        get_test_name(),
        invert_result(false),
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
    errata.note(S_INFO, message.view());
    return invert_if_applicable(false);
  }
  auto value_it = values.begin();
  auto test_it = _values.begin();
  while (value_it != values.end()) {
    if (test_tv(*value_it, *test_it)) {
      MSG_BUFF message;
      message.print(
          R"({}{} {}: Not Found. Key: "{}", {}: "{}", )",
          get_subtype(),
          get_test_name(),
          invert_result(false),
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
      errata.note(S_INFO, message.view());
      return invert_if_applicable(false);
    }
    ++value_it;
    ++test_it;
  }
  MSG_BUFF message;
  message.print(
      R"({}{} {}: Key: "{}", {}: "{}", )",
      get_subtype(),
      get_test_name(),
      invert_result(true),
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
  errata.note(S_INFO, message.view());
  return invert_if_applicable(true);
}

// Return true for failure, false for success
bool
ContainsCheck::test_tv(TextView value, TextView test) const
{
  auto const test_length = test.length();
  if (test_length > value.length()) {
    return invert_if_applicable(true);
  }
  if (_is_nocase) {
    auto spot =
        std::search(value.begin(), value.end(), test.begin(), test.end(), [](char lhs, char rhs) {
          return tolower(lhs) == tolower(rhs);
        });
    return spot == value.end();
  } else {
    return value.find(test) == std::string::npos;
  }
}

bool
PrefixCheck::test_tv(TextView value, TextView test) const
{
  auto const test_length = test.length();
  if (test_length > value.length()) {
    return true;
  }
  if (_is_nocase) {
    auto spot = std::search(
        value.begin(),
        value.begin() + test_length,
        test.begin(),
        test.end(),
        [](char lhs, char rhs) { return tolower(lhs) == tolower(rhs); });
    return spot == value.begin() + test_length;
  } else {
    return !value.starts_with(test);
  }
}

bool
SuffixCheck::test_tv(TextView value, TextView test) const
{
  auto const test_length = test.length();
  if (test_length > value.length()) {
    return true;
  }
  if (_is_nocase) {
    auto spot = std::search(
        value.end() - test_length,
        value.end(),
        test.begin(),
        test.end(),
        [](char lhs, char rhs) { return tolower(lhs) == tolower(rhs); });
    return spot == value.end();
  } else {
    return !value.ends_with(test);
  }
}
