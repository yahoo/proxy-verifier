/** @file
 * Definition of YamlParser.
 *
 * Copyright 2021, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "core/YamlParser.h"
#include "core/ProxyVerifier.h"
#include "core/verification.h"

#include "core/Localizer.h"
#include "core/yaml_util.h"

#include <cassert>
#include <dirent.h>
#include <thread>
#include <vector>

#include "swoc/bwf_ex.h"
#include "swoc/bwf_ip.h"
#include "swoc/bwf_std.h"
#include "swoc/bwf_std.h"

using swoc::Errata;
using swoc::TextView;
using namespace swoc::literals;
using namespace std::literals;

using std::chrono::duration_cast;
using std::chrono::seconds;
using std::chrono::milliseconds;
using std::chrono::microseconds;
using std::chrono::nanoseconds;
using ClockType = std::chrono::system_clock;
using TimePoint = std::chrono::time_point<ClockType, nanoseconds>;

TimePoint YamlParser::_parsing_start_time{};

swoc::Rv<microseconds>
interpret_delay_string(TextView src)
{
  auto delay = src;
  delay = delay.trim_if(&isspace);
  auto delay_digits = delay.clip_prefix_of(&isdigit);
  if (delay_digits.empty()) {
    return {0us, Errata().error(R"(No digits found for delay specification: "{}")", src)};
  }
  auto const raw_delay_number = swoc::svtou(delay_digits);

  // The digits prefix was clipped from delay above via clip_prefix_of.
  auto delay_suffix = delay;
  delay_suffix = delay_suffix.trim_if(&isspace);
  if (delay_suffix.empty()) {
    return {0us, Errata().error(R"(No unit found for delay specification: "{}")", src)};
  }

  if (delay_suffix == MICROSECONDS_SUFFIX) {
    return microseconds{raw_delay_number};
  } else if (delay_suffix == MILLISECONDS_SUFFIX) {
    return duration_cast<microseconds>(milliseconds{raw_delay_number});
  } else if (delay_suffix == SECONDS_SUFFIX) {
    return duration_cast<microseconds>(seconds{raw_delay_number});
  }
  return {
      0us,
      Errata()
          .error(R"(Unrecognized unit, "{}", for delay specification: "{}")", delay_suffix, src)};
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

Errata
YamlParser::populate_http_message(YAML::Node const &node, HttpHeader &message)
{
  Errata errata;

  if (node[YAML_HTTP_VERSION_KEY]) {
    message._http_version = Localizer::localize_lower(node[YAML_HTTP_VERSION_KEY].Scalar());
  } else {
    message._http_version = "1.1";
  }
  if (node[YAML_HTTP2_KEY]) {
    auto http2_node{node[YAML_HTTP2_KEY]};
    if (http2_node.IsMap()) {
      if (http2_node[YAML_HTTP_STREAM_ID_KEY]) {
        auto http_stream_id_node{http2_node[YAML_HTTP_STREAM_ID_KEY]};
        if (http_stream_id_node.IsScalar()) {
          TextView text{http_stream_id_node.Scalar()};
          TextView parsed;
          auto n = swoc::svtou(text, &parsed);
          if (parsed.size() == text.size() && 0 < n) {
            message._stream_id = n;
          } else {
            errata.error(
                R"("{}" value "{}" at {} must be a positive integer.)",
                YAML_HTTP_STREAM_ID_KEY,
                text,
                http_stream_id_node.Mark());
          }
        } else {
          errata.error(
              R"("{}" at {} must be a positive integer.)",
              YAML_HTTP_STREAM_ID_KEY,
              http_stream_id_node.Mark());
        }
      }
    } else {
      errata.error(
          R"("{}" value at {} must be a map of HTTP/2 values.)",
          YAML_HTTP2_KEY,
          http2_node.Mark());
    }
  }

  if (node[YAML_HTTP_STATUS_KEY]) {
    message._is_response = true;
    auto status_node{node[YAML_HTTP_STATUS_KEY]};
    if (status_node.IsScalar()) {
      TextView text{status_node.Scalar()};
      TextView parsed;
      auto n = swoc::svtou(text, &parsed);
      if (parsed.size() == text.size() && 0 < n && n <= 599) {
        message._status = n;
        message._status_string = std::to_string(message._status);
      } else {
        errata.error(
            R"("{}" value "{}" at {} must be an integer in the range [1..599].)",
            YAML_HTTP_STATUS_KEY,
            text,
            status_node.Mark());
      }
    } else {
      errata.error(
          R"("{}" value at {} must be an integer in the range [1..599].)",
          YAML_HTTP_STATUS_KEY,
          status_node.Mark());
    }
  }

  if (node[YAML_HTTP_REASON_KEY]) {
    auto reason_node{node[YAML_HTTP_REASON_KEY]};
    if (reason_node.IsScalar()) {
      message._reason = Localizer::localize(reason_node.Scalar());
    } else {
      errata.error(
          R"("{}" value at {} must be a string.)",
          YAML_HTTP_REASON_KEY,
          reason_node.Mark());
    }
  }

  if (node[YAML_HTTP_METHOD_KEY]) {
    auto method_node{node[YAML_HTTP_METHOD_KEY]};
    if (method_node.IsScalar()) {
      message._method = Localizer::localize(method_node.Scalar());
      message._is_request = true;
    } else {
      errata.error(
          R"("{}" value at {} must be a string.)",
          YAML_HTTP_REASON_KEY,
          method_node.Mark());
    }
  }

  if (node[YAML_HTTP_URL_KEY]) {
    auto url_node{node[YAML_HTTP_URL_KEY]};
    if (url_node.IsScalar()) {
      message._url = Localizer::localize(url_node.Scalar());
      message.parse_url(message._url);
    } else if (url_node.IsSequence()) {
      errata.note(parse_url_rules(url_node, *message._fields_rules, message._verify_strictly));
    } else {
      errata.error(
          R"("{}" value at {} must be a string or sequence.)",
          YAML_HTTP_URL_KEY,
          url_node.Mark());
    }
  }

  if (node[YAML_HTTP_SCHEME_KEY]) {
    auto scheme_node{node[YAML_HTTP_SCHEME_KEY]};
    if (scheme_node.IsScalar()) {
      message._scheme = Localizer::localize(scheme_node.Scalar());
    } else {
      errata.error(
          R"("{}" value at {} must be a string.)",
          YAML_HTTP_SCHEME_KEY,
          scheme_node.Mark());
    }
  }

  if (node[YAML_HDR_KEY]) {
    auto hdr_node{node[YAML_HDR_KEY]};
    if (hdr_node[YAML_FIELDS_KEY]) {
      auto field_list_node{hdr_node[YAML_FIELDS_KEY]};
      Errata result =
          parse_fields_and_rules(field_list_node, *message._fields_rules, message._verify_strictly);
      if (result.is_ok()) {
        errata.note(message.update_content_length(message._method));
        errata.note(message.update_transfer_encoding());
      } else {
        errata.error("Failed to parse response at {}", node.Mark());
        errata.note(std::move(result));
      }
    }
  }

  errata.note(process_pseudo_headers(node, message));

  if (!message._method.empty() && message._authority.empty()) {
    // The URL didn't have the authority. Get it from the Host header if it
    // exists.
    auto const it = message._fields_rules->_fields.find(FIELD_HOST);
    if (it != message._fields_rules->_fields.end()) {
      message._authority = it->second;
    }
  }

  // Do this after parsing fields so it can override transfer encoding.
  if (auto content_node{node[YAML_CONTENT_KEY]}; content_node) {
    if (content_node.IsMap()) {
      if (auto xf_node{content_node[YAML_CONTENT_TRANSFER_KEY]}; xf_node) {
        TextView xf{xf_node.Scalar()};
        if (0 == strcasecmp("chunked"_tv, xf)) {
          message._chunked_p = true;
        } else if (0 == strcasecmp("plain"_tv, xf)) {
          message._chunked_p = false;
        } else {
          errata.error(
              R"(Invalid value "{}" for "{}" key at {} in "{}" node at {})",
              xf,
              YAML_CONTENT_TRANSFER_KEY,
              xf_node.Mark(),
              YAML_CONTENT_KEY,
              content_node.Mark());
        }
      }
      if (auto data_node{content_node[YAML_CONTENT_DATA_KEY]}; data_node) {
        Localizer::Encoding enc{Localizer::Encoding::TEXT};
        if (auto enc_node{content_node[YAML_CONTENT_ENCODING_KEY]}; enc_node) {
          TextView text{enc_node.Scalar()};
          if (0 == strcasecmp("uri"_tv, text)) {
            enc = Localizer::Encoding::URI;
          } else if (0 == strcasecmp("plain"_tv, text)) {
            enc = Localizer::Encoding::TEXT;
          } else {
            errata.error(R"(Unknown encoding "{}" at {}.)", text, enc_node.Mark());
          }
        }
        TextView content{Localizer::localize(data_node.Scalar(), enc)};
        message._content_data = content.data();
        const size_t content_size = content.size();
        message._recorded_content_size = content_size;
        // Cross check against previously read content-length header, if any.
        if (message._content_length_p) {
          if (message._content_size != content_size) {
            errata.diag(
                R"(Conflicting sizes for "Content-Length", sending header value {} instead of data value {}.)",
                message._content_size,
                content_size);
            // _content_size will be the value of the Content-Length header.
          }
        } else {
          message._content_size = content_size;
        }
      } else if (auto size_node{content_node[YAML_CONTENT_SIZE_KEY]}; size_node) {
        const size_t content_size = swoc::svtou(size_node.Scalar());
        message._recorded_content_size = content_size;
        // Cross check against previously read content-length header, if any.
        if (message._content_length_p) {
          if (message._content_size != content_size) {
            errata.diag(
                R"(Conflicting sizes for "Content-Length", sending header value {} instead of rule value {}.)",
                message._content_size,
                content_size);
            // _content_size will be the value of the Content-Length header.
          }
        } else {
          message._content_size = content_size;
        }
      } else {
        errata.error(
            R"("{}" node at {} does not have a "{}" or "{}" key as required.)",
            YAML_CONTENT_KEY,
            node.Mark(),
            YAML_CONTENT_SIZE_KEY,
            YAML_CONTENT_DATA_KEY);
      }
    } else {
      errata.error(R"("{}" node at {} is not a map.)", YAML_CONTENT_KEY, content_node.Mark());
    }
  }

  // After everything has been read, there should be enough information now to
  // derive a key.
  message.derive_key();

  return errata;
}

Errata
YamlParser::parse_global_rules(YAML::Node const &node, HttpFields &fields)
{
  Errata errata;

  if (auto rules_node{node[YAML_FIELDS_KEY]}; rules_node) {
    if (rules_node.IsSequence()) {
      if (rules_node.size() > 0) {
        auto result{parse_fields_and_rules(rules_node, fields, !ASSUME_EQUALITY_RULE)};
        if (!result.is_ok()) {
          errata.error("Failed to parse fields and rules at {}", node.Mark());
          errata.note(std::move(result));
        }
      } else {
        errata.info(R"(Fields and rules node at {} is an empty list.)", rules_node.Mark());
      }
    } else {
      errata.info(R"(Fields and rules node at {} is not a sequence.)", rules_node.Mark());
    }
  } else {
    errata.info(R"(Node at {} is missing a fields node.)", node.Mark());
  }
  return errata;
}

Errata
YamlParser::parse_url_rules(
    YAML::Node const &url_rules_node,
    HttpFields &fields,
    bool assume_equality_rule)
{
  Errata errata;

  for (auto const &node : url_rules_node) {
    if (!node.IsSequence()) {
      errata.error("URL rule at {} is not a sequence as required.", node.Mark());
      continue;
    }
    const auto node_size = node.size();
    if (node_size != 2 && node_size != 3) {
      errata.error(
          "URL rule node at {} is not a sequence of length 2 "
          "or 3 as required.",
          node.Mark());
      continue;
    }

    TextView part_name{Localizer::localize_lower(node[YAML_RULE_KEY_INDEX].Scalar())};
    UrlPart part_id = HttpHeader::parse_url_part(part_name);
    if (part_id == UrlPart::Error) {
      errata.error("URL rule node at {} has an invalid URL part.", node.Mark());
      continue;
    }
    const YAML::Node ValueNode{node[YAML_RULE_VALUE_INDEX]};
    if (ValueNode.IsScalar()) {
      // There's only a single value associated with this URL part.
      TextView value{Localizer::localize(node[YAML_RULE_VALUE_INDEX].Scalar())};
      if (node_size == 2 && assume_equality_rule) {
        fields._url_rules[static_cast<size_t>(part_id)].push_back(
            RuleCheck::make_equality(part_id, value));
      } else if (node_size == 3) {
        // Contains a verification rule.
        TextView rule_type{node[YAML_RULE_TYPE_INDEX].Scalar()};
        std::shared_ptr<RuleCheck> tester = RuleCheck::make_rule_check(part_id, value, rule_type);
        if (!tester) {
          errata.error(
              "URL rule node at {} does not have a valid directive ({})",
              node.Mark(),
              rule_type);
          continue;
        } else {
          fields._url_rules[static_cast<size_t>(part_id)].push_back(tester);
        }
      }
      // No error reported if incorrect length
    } else if (ValueNode.IsMap()) {
      // Verification is specified as a map, such as:
      // - [ path, { value: config/settings.yaml, as: equal } ]
      TextView value;
      if (auto const url_value_node{ValueNode[YAML_RULE_VALUE_MAP_KEY]}; url_value_node) {
        value = Localizer::localize(url_value_node.Scalar());
      }
      if (!ValueNode[YAML_RULE_TYPE_MAP_KEY]) {
        // No verification directive was specified.
        if (assume_equality_rule) {
          fields._url_rules[static_cast<size_t>(part_id)].push_back(
              RuleCheck::make_equality(part_id, value));
        }
        continue;
      }
      TextView rule_type{ValueNode[YAML_RULE_TYPE_MAP_KEY].Scalar()};
      std::shared_ptr<RuleCheck> tester = RuleCheck::make_rule_check(part_id, value, rule_type);
      if (!tester) {
        errata.error(
            "URL rule node at {} does not have a valid directive ({})",
            node.Mark(),
            rule_type);
        continue;
      } else {
        fields._url_rules[static_cast<size_t>(part_id)].push_back(tester);
      }
    } else if (ValueNode.IsSequence()) {
      errata.error("URL rule node at {} has multiple values, which is not allowed.", node.Mark());
      continue;
    }
  }
  return errata;
}

Errata
YamlParser::parse_fields_and_rules(
    YAML::Node const &fields_rules_node,
    HttpFields &fields,
    bool assume_equality_rule)
{
  Errata errata;

  for (auto const &node : fields_rules_node) {
    if (!node.IsSequence()) {
      errata.error("Field or rule at {} is not a sequence as required.", node.Mark());
      continue;
    }
    auto const node_size = node.size();
    if (node_size != 2 && node_size != 3) {
      errata.error(
          "Field or rule node at {} is not a sequence of length 2 "
          "or 3 as required.",
          node.Mark());
      continue;
    }

    TextView name{Localizer::localize_lower(node[YAML_RULE_KEY_INDEX].Scalar())};
    const YAML::Node ValueNode{node[YAML_RULE_VALUE_INDEX]};
    if (ValueNode.IsScalar()) {
      // There's only a single value associated with this field name.
      TextView value{Localizer::localize(node[YAML_RULE_VALUE_INDEX].Scalar())};
      fields.add_field(name, value);
      if (node_size == 2 && assume_equality_rule) {
        fields._rules.emplace(name, RuleCheck::make_equality(name, value));
      } else if (node_size == 3) {
        // Contains a verification rule.
        // -[ Host, example.com, equal ]
        TextView rule_type{node[YAML_RULE_TYPE_INDEX].Scalar()};
        std::shared_ptr<RuleCheck> tester = RuleCheck::make_rule_check(name, value, rule_type);
        if (!tester) {
          errata.error(
              "Field rule at {} does not have a valid directive ({})",
              node.Mark(),
              rule_type);
          continue;
        } else {
          fields._rules.emplace(name, tester);
        }
      }
    } else if (ValueNode.IsSequence()) {
      // There's a list of values associated with this field. This
      // indicates duplicate fields for the same field name.
      std::vector<TextView> values;
      values.reserve(ValueNode.size());
      for (auto const &value : ValueNode) {
        TextView localized_value{Localizer::localize(value.Scalar())};
        values.emplace_back(localized_value);
        fields.add_field(name, localized_value);
      }
      if (node_size == 2 && assume_equality_rule) {
        fields._rules.emplace(name, RuleCheck::make_equality(name, std::move(values)));
      } else if (node_size == 3) {
        // Contains a verification rule.
        // -[ set-cookie, [ first-cookie, second-cookie ], present ]
        TextView rule_type{node[YAML_RULE_TYPE_INDEX].Scalar()};
        std::shared_ptr<RuleCheck> tester =
            RuleCheck::make_rule_check(name, std::move(values), rule_type);
        if (!tester) {
          errata.error(
              "Field rule at {} does not have a valid directive ({})",
              node.Mark(),
              rule_type);
          continue;
        } else {
          fields._rules.emplace(name, tester);
        }
      }
    } else if (ValueNode.IsMap()) {
      // Verification is specified as a map, such as:
      // -[ Host, { value: example.com, as: equal } ]
      TextView value;
      if (auto const field_value_node{ValueNode[YAML_RULE_VALUE_MAP_KEY]}; field_value_node) {
        if (field_value_node.IsScalar()) {
          value = Localizer::localize(field_value_node.Scalar());
          fields.add_field(name, value);
        } else if (field_value_node.IsSequence()) {
          // Verification is for duplicate fields:
          // -[ set-cookie, { value: [ cookiea, cookieb], as: equal } ]
          std::vector<TextView> values;
          values.reserve(ValueNode.size());
          for (auto const &value : field_value_node) {
            TextView localized_value{Localizer::localize(value.Scalar())};
            values.emplace_back(localized_value);
            fields.add_field(name, localized_value);
          }
          if (auto const rule_type_node{ValueNode[YAML_RULE_TYPE_MAP_KEY]}; rule_type_node) {
            TextView rule_type{rule_type_node.Scalar()};
            std::shared_ptr<RuleCheck> tester =
                RuleCheck::make_rule_check(name, std::move(values), rule_type);
            if (!tester) {
              errata.error(
                  "Field rule at {} does not have a valid directive ({})",
                  node.Mark(),
                  rule_type);
              continue;
            } else {
              fields._rules.emplace(name, tester);
            }
          } else {
            // No verification directive was specified.
            if (assume_equality_rule) {
              fields._rules.emplace(name, RuleCheck::make_equality(name, std::move(values)));
            }
          }
          continue;
        }
      }
      if (auto const rule_type_node{ValueNode[YAML_RULE_TYPE_MAP_KEY]}; rule_type_node) {
        TextView rule_type{rule_type_node.Scalar()};
        std::shared_ptr<RuleCheck> tester = RuleCheck::make_rule_check(name, value, rule_type);
        if (!tester) {
          errata.error(
              "Field rule at {} does not have a valid directive ({})",
              node.Mark(),
              rule_type);
          continue;
        } else {
          fields._rules.emplace(name, tester);
        }
      } else {
        // No verification directive was specified.
        if (assume_equality_rule) {
          fields._rules.emplace(name, RuleCheck::make_equality(name, value));
        }
        continue;
      }
    }
  }
  return errata;
}

Errata
YamlParser::parsing_is_started()
{
  _parsing_start_time = ClockType::now();
  return {};
}

Errata
YamlParser::parsing_is_done()
{
  // Localization should only be done during the YAML parsing stages. Any
  // localization done after this point (such as during the parsing of bytes
  // off the wire) would be a logic error.
  Localizer::freeze_localization();

  Errata errata;
  auto parsing_duration = ClockType::now() - _parsing_start_time;
  if (parsing_duration > 10s) {
    errata.info(
        "Replay file parsing took: {} seconds.",
        duration_cast<seconds>(parsing_duration).count());
  } else {
    errata.info(
        "Replay file parsing took: {} milliseconds.",
        duration_cast<milliseconds>(parsing_duration).count());
  }
  return errata;
}

Errata
YamlParser::process_pseudo_headers(YAML::Node const &node, HttpHeader &message)
{
  Errata errata;
  auto number_of_pseudo_headers = 0;
  auto pseudo_it = message._fields_rules->_fields.find(YAML_HTTP2_PSEUDO_METHOD_KEY);
  if (pseudo_it != message._fields_rules->_fields.end()) {
    if (!message._method.empty()) {
      errata.error(
          "The {} node is not compatible with the {} pseudo header: {}",
          YAML_HTTP_METHOD_KEY,
          YAML_HTTP2_PSEUDO_METHOD_KEY,
          node.Mark());
    }
    message._method = pseudo_it->second;
    ++number_of_pseudo_headers;
    message._is_request = true;
  }
  pseudo_it = message._fields_rules->_fields.find(YAML_HTTP2_PSEUDO_SCHEME_KEY);
  if (pseudo_it != message._fields_rules->_fields.end()) {
    if (!message._scheme.empty()) {
      errata.error(
          "The {} node is not compatible with the {} pseudo header: {}",
          YAML_HTTP_SCHEME_KEY,
          YAML_HTTP2_PSEUDO_SCHEME_KEY,
          node.Mark());
    }
    message._scheme = pseudo_it->second;
    ++number_of_pseudo_headers;
    message._is_request = true;
  }
  pseudo_it = message._fields_rules->_fields.find(YAML_HTTP2_PSEUDO_AUTHORITY_KEY);
  if (pseudo_it != message._fields_rules->_fields.end()) {
    auto const host_it = message._fields_rules->_fields.find(FIELD_HOST);
    if (host_it != message._fields_rules->_fields.end()) {
      // We intentionally allow this, even though contrary to spec, to allow the use
      // of Proxy Verifier to test proxy's handling of this.
      errata.info(
          "Contrary to spec, a transaction is specified with both {} and {} header fields: {}",
          YAML_HTTP2_PSEUDO_AUTHORITY_KEY,
          FIELD_HOST,
          node.Mark());
    } else if (!message._authority.empty()) {
      errata.error(
          "The {} node is not compatible with the {} pseudo header: {}",
          YAML_HTTP_URL_KEY,
          YAML_HTTP2_PSEUDO_AUTHORITY_KEY,
          node.Mark());
    }
    message._authority = pseudo_it->second;
    ++number_of_pseudo_headers;
    message._is_request = true;
  }
  pseudo_it = message._fields_rules->_fields.find(YAML_HTTP2_PSEUDO_PATH_KEY);
  if (pseudo_it != message._fields_rules->_fields.end()) {
    if (!message._path.empty()) {
      errata.error(
          "The {} node is not compatible with the {} pseudo header: {}",
          YAML_HTTP_URL_KEY,
          YAML_HTTP2_PSEUDO_PATH_KEY,
          node.Mark());
    }
    message._path = pseudo_it->second;
    ++number_of_pseudo_headers;
    message._is_request = true;
  }
  pseudo_it = message._fields_rules->_fields.find(YAML_HTTP2_PSEUDO_STATUS_KEY);
  if (pseudo_it != message._fields_rules->_fields.end()) {
    if (message._status != 0) {
      errata.error(
          "The {} node is not compatible with the {} pseudo header: {}",
          YAML_HTTP_STATUS_KEY,
          YAML_HTTP2_PSEUDO_STATUS_KEY,
          node.Mark());
    }
    auto const &status_field_value = pseudo_it->second;
    TextView parsed;
    auto n = swoc::svtou(status_field_value, &parsed);
    if (parsed.size() == status_field_value.size() && 0 < n && n <= 599) {
      message._status = n;
      message._status_string = std::to_string(message._status);
    } else {
      errata.error(
          R"("{}" pseudo header value "{}" at {} must be an integer in the range [1..599].)",
          YAML_HTTP2_PSEUDO_STATUS_KEY,
          status_field_value,
          node.Mark());
    }
    ++number_of_pseudo_headers;
    message._is_response = true;
  }
  if (number_of_pseudo_headers > 0) {
    // Do some sanity checking on the user's pseudo headers, if provided.
    if (message._is_response && number_of_pseudo_headers != 1) {
      errata.error("Found a mixture of request and response pseudo header fields: {}", node.Mark());
    }
    if (message._is_request && number_of_pseudo_headers != 4) {
      errata.error(
          "Did not find all four required pseudo header fields "
          "(:method, :scheme, :authority, :path): {}",
          node.Mark());
    }
    // Pseudo header fields currently implies HTTP/2.
    message._http_version = "2";
    message._contains_pseudo_headers_in_fields_array = true;
  }
  return errata;
}

swoc::Rv<YAML::Node const>
ReplayFileHandler::parse_for_protocol_node(
    YAML::Node const &protocol_node,
    std::string_view protocol_name)
{
  swoc::Rv<YAML::Node const> desired_node = YAML::Node{YAML::NodeType::Undefined};
  if (!protocol_node.IsSequence()) {
    desired_node.error("Protocol node at {} is not a sequence as required.", protocol_node.Mark());
    return desired_node;
  }
  if (protocol_node.size() == 0) {
    desired_node.error("Protocol node at {} is an empty sequence.", protocol_node.Mark());
    return desired_node;
  }
  for (auto const &protocol_element : protocol_node) {
    if (!protocol_element.IsMap()) {
      desired_node.error("Protocol element at {} is not a map.", protocol_element.Mark());
      return desired_node;
    }
    if (!protocol_element[YAML_SSN_PROTOCOL_NAME]) {
      desired_node.error(
          R"(Protocol element at {} does not have a "{}" element.)",
          protocol_element.Mark(),
          YAML_SSN_PROTOCOL_NAME);
      return desired_node;
    }
    if (protocol_element[YAML_SSN_PROTOCOL_NAME].Scalar() != protocol_name) {
      continue;
    }
    return swoc::Rv<YAML::Node const>{protocol_element};
  }
  return desired_node;
}

swoc::Rv<std::string>
ReplayFileHandler::parse_sni(YAML::Node const &tls_node)
{
  swoc::Rv<std::string> sni;
  if (auto sni_node{tls_node[YAML_SSN_TLS_SNI_KEY]}; sni_node) {
    if (sni_node.IsScalar()) {
      sni.result() = sni_node.Scalar();
    } else {
      sni.error(
          R"(Session has a value for key "{}" that is not a scalar as required.)",
          YAML_SSN_TLS_SNI_KEY);
    }
  }
  return sni;
}

swoc::Rv<int>
ReplayFileHandler::parse_verify_mode(YAML::Node const &tls_node)
{
  swoc::Rv<int> verify_mode{-1};
  if (auto tls_verify_mode{tls_node[YAML_SSN_TLS_VERIFY_MODE_KEY]}; tls_verify_mode) {
    if (tls_verify_mode.IsScalar()) {
      verify_mode = std::stoi(tls_verify_mode.Scalar());
    } else {
      verify_mode.error(
          R"(Session has a value for key "{}" that is not a scalar as required.)",
          YAML_SSN_TLS_SNI_KEY);
    }
  }
  return verify_mode;
}

swoc::Rv<std::string>
ReplayFileHandler::parse_alpn_protocols_node(YAML::Node const &tls_node)
{
  swoc::Rv<std::string> alpn_protocol_string;
  if (auto alpn_protocols_node{tls_node[YAML_SSN_TLS_ALPN_PROTOCOLS_KEY]}; alpn_protocols_node) {
    if (!alpn_protocols_node.IsSequence()) {
      alpn_protocol_string.error(
          R"(Session has a value for key "{}" that is not a sequence as required.)",
          YAML_SSN_TLS_ALPN_PROTOCOLS_KEY);
      return alpn_protocol_string;
    }
    for (auto const &protocol : alpn_protocols_node) {
      std::string_view protocol_view{protocol.Scalar()};
      alpn_protocol_string.result().append(1, (char)protocol_view.size());
      alpn_protocol_string.result().append(protocol_view);
    }
  }
  return alpn_protocol_string;
}

/** RAII for managing the handler's file. */
struct HandlerOpener
{
public:
  Errata errata;

public:
  HandlerOpener(ReplayFileHandler &handler, swoc::file::path const &path) : _handler(handler)
  {
    errata.note(_handler.file_open(path));
  }
  ~HandlerOpener()
  {
    errata.note(_handler.file_close());
  }

private:
  ReplayFileHandler &_handler;
};

Errata
YamlParser::load_replay_file(swoc::file::path const &path, ReplayFileHandler &handler)
{
  HandlerOpener opener(handler, path);
  auto errata = opener.errata;
  if (!errata.is_ok()) {
    return errata;
  }
  std::error_code ec;
  std::string content{swoc::file::load(path, ec)};
  if (ec.value()) {
    errata.error(R"(Error loading "{}": {})", path, ec);
    return errata;
  }
  YAML::Node root;
  auto global_fields_rules = std::make_shared<HttpFields>();
  try {
    root = YAML::Load(content);
    yaml_merge(root);
  } catch (std::exception const &ex) {
    errata.error(R"(Exception: {} in "{}".)", ex.what(), path);
  }
  if (!errata.is_ok()) {
    return errata;
  }
  if (root[YAML_META_KEY]) {
    auto meta_node{root[YAML_META_KEY]};
    if (meta_node[YAML_GLOBALS_KEY]) {
      auto globals_node{meta_node[YAML_GLOBALS_KEY]};
      // Path not passed to later calls than Load_Replay_File.
      errata.note(YamlParser::parse_global_rules(globals_node, *global_fields_rules));
    }
  } else {
    errata.info(R"(No meta node ("{}") at "{}":{}.)", YAML_META_KEY, path, root.Mark().line);
  }
  handler.global_config = VerificationConfig{global_fields_rules};
  if (!root[YAML_SSN_KEY]) {
    errata.error(R"(No sessions list ("{}") at "{}":{}.)", YAML_META_KEY, path, root.Mark().line);
    return errata;
  }
  auto ssn_list_node{root[YAML_SSN_KEY]};
  if (!ssn_list_node.IsSequence()) {
    errata.error(
        R"("{}" value at "{}":{} is not a sequence.)",
        YAML_SSN_KEY,
        path,
        ssn_list_node.Mark());
    return errata;
  }
  if (ssn_list_node.size() == 0) {
    errata.diag(R"(Session list at "{}":{} is an empty list.)", path, ssn_list_node.Mark().line);
    return errata;
  }
  for (auto const &ssn_node : ssn_list_node) {
    // HeaderRules ssn_rules = global_rules;
    auto session_errata{handler.ssn_open(ssn_node)};
    if (!session_errata.is_ok()) {
      errata.note(std::move(session_errata));
      errata.error(R"(Failure opening session at "{}":{}.)", path, ssn_node.Mark().line);
      continue;
    }
    if (!ssn_node[YAML_TXN_KEY]) {
      errata.error(
          R"(Session at "{}":{} has no "{}" key.)",
          path,
          ssn_node.Mark().line,
          YAML_TXN_KEY);
      continue;
    }
    auto txn_list_node{ssn_node[YAML_TXN_KEY]};
    if (!txn_list_node.IsSequence()) {
      session_errata.error(
          R"(Transaction list at {} in session at {} in "{}" is not a list.)",
          txn_list_node.Mark(),
          ssn_node.Mark(),
          path);
    }
    if (txn_list_node.size() == 0) {
      session_errata.info(
          R"(Transaction list at {} in session at {} in "{}" is an empty list.)",
          txn_list_node.Mark(),
          ssn_node.Mark(),
          path);
    }
    for (auto const &txn_node : txn_list_node) {
      // HeaderRules txn_rules = ssn_rules;
      auto txn_errata = handler.txn_open(txn_node);
      if (!txn_errata.is_ok()) {
        session_errata.error(R"(Could not open transaction at {} in "{}".)", txn_node.Mark(), path);
      }
      HttpFields all_fields;
      if (auto all_node{txn_node[YAML_ALL_MESSAGES_KEY]}; all_node) {
        if (auto headers_node{all_node[YAML_HDR_KEY]}; headers_node) {
          txn_errata.note(YamlParser::parse_global_rules(headers_node, all_fields));
        }
      }
      if (auto creq_node{txn_node[YAML_CLIENT_REQ_KEY]}; creq_node) {
        txn_errata.note(handler.client_request(creq_node));
      }
      if (auto preq_node{txn_node[YAML_PROXY_REQ_KEY]}; preq_node) { // global_rules appears to be
                                                                     // being copied
        txn_errata.note(handler.proxy_request(preq_node));
      }
      if (auto ursp_node{txn_node[YAML_SERVER_RSP_KEY]}; ursp_node) {
        txn_errata.note(handler.server_response(ursp_node));
      }
      if (auto prsp_node{txn_node[YAML_PROXY_RSP_KEY]}; prsp_node) {
        txn_errata.note(handler.proxy_response(prsp_node));
      }
      if (!all_fields._fields.empty()) {
        txn_errata.note(handler.apply_to_all_messages(all_fields));
      }
      txn_errata.note(handler.txn_close());
      if (!txn_errata.is_ok()) {
        txn_errata.error(R"(Failure with transaction at {} in "{}".)", txn_node.Mark(), path);
      }
      session_errata.note(std::move(txn_errata));
    }
    session_errata.note(handler.ssn_close());
    errata.note(std::move(session_errata));
  }
  return errata;
}

Errata
YamlParser::load_replay_files(swoc::file::path const &path, loader_t loader, int n_threads)
{
  Errata errata;
  errata.note(parsing_is_started());
  std::mutex local_mutex;
  std::error_code ec;

  dirent **elements = nullptr;

  auto stat{swoc::file::status(path, ec)};
  if (ec) {
    errata.error(R"(Invalid test directory "{}": [{}])", path, ec);
    errata.note(parsing_is_done());
    return errata;
  } else if (swoc::file::is_regular_file(stat)) {
    errata.note(loader(path));
    errata.note(parsing_is_done());
    return errata;
  } else if (!swoc::file::is_dir(stat)) {
    errata.error(R"("{}" is not a file or a directory.)", path);
    errata.note(parsing_is_done());
    return errata;
  }

  if (0 == chdir(path.c_str())) {
    int n_sessions = scandir(
        ".",
        &elements,
        [](dirent const *entry) -> int {
          auto extension = swoc::TextView{entry->d_name, strlen(entry->d_name)}.suffix_at('.');
          return 0 == strcasecmp(extension, "json") || 0 == strcasecmp(extension, "yaml");
        },
        &alphasort);
    if (n_sessions > 0) {
      std::atomic<int> idx{0};
      swoc::MemSpan<dirent *> entries{elements, static_cast<size_t>(n_sessions)};

      // Lambda suitable to spawn in a thread to load files.
      auto load_wrapper = [&]() -> void {
        size_t k = 0;
        while ((k = idx++) < entries.count()) {
          auto result = loader(swoc::file::path{entries[k]->d_name});
          std::lock_guard<std::mutex> lock(local_mutex);
          errata.note(result);
        }
      };

      errata.info("Loading {} replay files.", n_sessions);
      std::vector<std::thread> threads;
      threads.reserve(n_threads);
      for (int tidx = 0; tidx < n_threads; ++tidx) {
        threads.emplace_back(load_wrapper);
      }
      for (std::thread &thread : threads) {
        thread.join();
      }
      for (int i = 0; i < n_sessions; i++) {
        free(elements[i]);
      }
      free(elements);

    } else {
      errata.error(R"(No replay files found in "{}".)", path);
    }
  } else {
    errata.error(R"(Failed to access directory "{}": {}.)", path, swoc::bwf::Errno{});
  }
  errata.note(parsing_is_done());
  return errata;
}
