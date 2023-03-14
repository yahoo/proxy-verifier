/** @file
 * Definition of YamlParser.
 *
 * Copyright 2022, Verizon Media
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
    return {0us, Errata(S_ERROR, R"(No digits found for delay specification: "{}")", src)};
  }
  auto const raw_delay_number = swoc::svtou(delay_digits);

  // The digits prefix was clipped from delay above via clip_prefix_of.
  auto delay_suffix = delay;
  delay_suffix = delay_suffix.trim_if(&isspace);
  if (delay_suffix.empty()) {
    return {0us, Errata(S_ERROR, R"(No unit found for delay specification: "{}")", src)};
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
      Errata(
          S_ERROR,
          R"(Unrecognized unit, "{}", for delay specification: "{}")",
          delay_suffix,
          src)};
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
      zret.note(S_ERROR, R"("{}" key that is not a scalar.)", YAML_TIME_DELAY_KEY);
    }
  }
  return zret;
}

Errata
YamlParser::populate_http_message(YAML::Node const &node, HttpHeader &message)
{
  Errata errata;

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
            errata.note(
                S_ERROR,
                R"("{}" value "{}" at {} must be a positive integer.)",
                YAML_HTTP_STREAM_ID_KEY,
                text,
                http_stream_id_node.Mark());
          }
        } else {
          errata.note(
              S_ERROR,
              R"("{}" at {} must be a positive integer.)",
              YAML_HTTP_STREAM_ID_KEY,
              http_stream_id_node.Mark());
        }
      }
    } else {
      errata.note(
          S_ERROR,
          R"("{}" value at {} must be a map of HTTP/2 values.)",
          YAML_HTTP2_KEY,
          http2_node.Mark());
    }
  }

  if (auto const &await{node[YAML_HTTP_AWAIT_KEY]}; await) {
    if (await.IsScalar()) {
      message._keys_to_await.emplace_back(await.Scalar());
    } else if (await.IsSequence()) {
      for (auto const &key : await) {
        if (key.IsScalar()) {
          message._keys_to_await.emplace_back(key.Scalar());
        } else {
          errata.note(
              S_ERROR,
              R"("{}" value at {} must be a scalar or a sequence of scalars.)",
              YAML_HTTP_AWAIT_KEY,
              key.Mark());
        }
      }
    } else {
      errata.note(
          S_ERROR,
          R"("{}" at {} must be a scalar or sequence.)",
          YAML_HTTP_AWAIT_KEY,
          await.Mark());
    }
  }

  YAML::Node headers_frame;
  YAML::Node data_frame;
  YAML::Node rst_stream_frame;
  YAML::Node goaway_frame;
  int rst_stream_index = -1;
  int goaway_index = -1;
  if (node[YAML_FRAMES_KEY]) {
    auto frames_node{node[YAML_FRAMES_KEY]};
    if (frames_node.IsSequence()) {
      for (const auto &frame : frames_node) {
        for (const auto &&[key, value] : frame) {
          auto frame_name = Localizer::localize_upper(key.as<std::string>());
          switch (H2FrameNames[frame_name]) {
          case H2Frame::HEADERS:
            headers_frame = value;
            break;
          case H2Frame::DATA:
            data_frame = value;
            break;
          case H2Frame::RST_STREAM:
            rst_stream_frame = value;
            rst_stream_index = message._h2_frame_sequence.size();
            if (goaway_index != -1) {
              errata.note(S_ERROR, "GOAWAY frame has already been specified.");
            }
            break;
          case H2Frame::GOAWAY:
            goaway_frame = value;
            goaway_index = message._h2_frame_sequence.size();
            if (rst_stream_index != -1) {
              errata.note(S_ERROR, "RST_STREAM frame has already been specified.");
            }
            break;
          default:
            errata.note(
                S_ERROR,
                R"("{}" at {} is an invalid HTTP/2 frame name.)",
                key.as<std::string>(),
                frames_node.Mark());
            continue;
          }
          message._h2_frame_sequence.push_back(H2FrameNames[frame_name]);
        }
      }
    } else {
      errata.note(
          S_ERROR,
          R"("{}" at {} must be a sequence of frames.)",
          YAML_FRAMES_KEY,
          frames_node.Mark());
    }
  }

  // If frame elements didn't set the headers and data frames, set them from
  // the top level node.
  if (headers_frame.IsNull()) {
    headers_frame = node;
  }
  if (data_frame.IsNull()) {
    data_frame = node;
  }

  if (headers_frame[YAML_HTTP_STATUS_KEY]) {
    message.set_is_response();
    auto status_node{headers_frame[YAML_HTTP_STATUS_KEY]};
    if (status_node.IsScalar()) {
      TextView text{status_node.Scalar()};
      TextView parsed;
      auto n = swoc::svtou(text, &parsed);
      if (parsed.size() == text.size() && ((0 < n && n <= 599) || n == 999)) {
        message._status = n;
        message._status_string = std::to_string(message._status);
      } else {
        errata.note(
            S_ERROR,
            R"("{}" value "{}" at {} must be an integer in the range [1..599] or 999.)",
            YAML_HTTP_STATUS_KEY,
            text,
            status_node.Mark());
      }
    } else {
      errata.note(
          S_ERROR,
          R"("{}" value at {} must be an integer in the range [1..599] or 999.)",
          YAML_HTTP_STATUS_KEY,
          status_node.Mark());
    }
  }

  if (headers_frame[YAML_HTTP_REASON_KEY]) {
    auto reason_node{headers_frame[YAML_HTTP_REASON_KEY]};
    if (reason_node.IsScalar()) {
      message._reason = Localizer::localize(reason_node.Scalar());
    } else {
      errata.note(
          S_ERROR,
          R"("{}" value at {} must be a string.)",
          YAML_HTTP_REASON_KEY,
          reason_node.Mark());
    }
  }

  if (headers_frame[YAML_HTTP_METHOD_KEY]) {
    auto method_node{headers_frame[YAML_HTTP_METHOD_KEY]};
    if (method_node.IsScalar()) {
      message._method = Localizer::localize(method_node.Scalar());
      message.set_is_request();
    } else {
      errata.note(
          S_ERROR,
          R"("{}" value at {} must be a string.)",
          YAML_HTTP_METHOD_KEY,
          method_node.Mark());
    }
  }

  if (headers_frame[YAML_HTTP_URL_KEY]) {
    auto url_node{headers_frame[YAML_HTTP_URL_KEY]};
    if (url_node.IsScalar()) {
      message._url = Localizer::localize(url_node.Scalar());
      message.parse_url(message._url);
    } else if (url_node.IsSequence()) {
      errata.note(parse_url_rules(url_node, *message._fields_rules, message._verify_strictly));
    } else {
      errata.note(
          S_ERROR,
          R"("{}" value at {} must be a string or sequence.)",
          YAML_HTTP_URL_KEY,
          url_node.Mark());
    }
  }

  if (headers_frame[YAML_HTTP_SCHEME_KEY]) {
    auto scheme_node{headers_frame[YAML_HTTP_SCHEME_KEY]};
    if (scheme_node.IsScalar()) {
      message._scheme = Localizer::localize(scheme_node.Scalar());
    } else {
      errata.note(
          S_ERROR,
          R"("{}" value at {} must be a string.)",
          YAML_HTTP_SCHEME_KEY,
          scheme_node.Mark());
    }
  }

  if (auto const &version_node{headers_frame[YAML_HTTP_VERSION_KEY]}; version_node) {
    if (version_node.IsScalar()) {
      message._http_version = Localizer::localize(version_node.Scalar());
      // The message._http_protocol will already, by default, be HTTP_1. For
      // HTTP/2 and HTTP/3, it is the responsibility of session-parsing (as
      // opposed to this transaction parsing) to set the _http_protocol
      // correctly via set_is_http2() or set_is_http3().
      assert(message.is_http1());
    } else {
      errata.note(
          S_ERROR,
          R"("{}" value at {} must be a string.)",
          YAML_HTTP_VERSION_KEY,
          version_node.Mark());
    }
  }

  if (headers_frame[YAML_HDR_KEY]) {
    auto hdr_node{headers_frame[YAML_HDR_KEY]};
    if (hdr_node[YAML_FIELDS_KEY]) {
      auto field_list_node{hdr_node[YAML_FIELDS_KEY]};
      Errata result =
          parse_fields_and_rules(field_list_node, *message._fields_rules, message._verify_strictly);
      if (result.is_ok()) {
        errata.note(message.update_content_length(message._method));
        errata.note(message.update_transfer_encoding());
      } else {
        errata.note(S_ERROR, "Failed to parse response at {}", node.Mark());
        errata.note(std::move(result));
      }
    }
  }

  errata.note(process_pseudo_headers(headers_frame, message));

  if (!rst_stream_frame.IsNull()) {
    if (rst_stream_index > 0) {
      auto error_code_node{rst_stream_frame[YAML_ERROR_CODE_KEY]};
      if (error_code_node.IsScalar()) {
        auto error_code = Localizer::localize_upper(error_code_node.Scalar());
        auto abort_error = H2ErrorCodeNames[error_code];
        auto abort_frame = message._h2_frame_sequence[rst_stream_index - 1];
        if (abort_error != H2ErrorCode::INVALID && message.is_request()) {
          message._client_rst_stream_after = static_cast<int>(abort_frame);
          message._client_rst_stream_error = static_cast<int>(abort_error);
        } else if (abort_error != H2ErrorCode::INVALID && message.is_response()) {
          message._server_rst_stream_after = static_cast<int>(abort_frame);
          message._server_rst_stream_error = static_cast<int>(abort_error);
        } else {
          errata.note(
              S_ERROR,
              R"("{}" is not a valid error code.)",
              Localizer::localize_upper(error_code_node.Scalar()));
        }
      } else {
        errata.note(
            S_ERROR,
            R"("{}" value at {} must be a string.)",
            YAML_ERROR_CODE_KEY,
            error_code_node.Mark());
      }
    } else {
      errata.note(S_ERROR, "The RST_STREAM frame node must NOT be the first in the frame sequence");
    }
  }

  if (!goaway_frame.IsNull()) {
    if (goaway_index > 0) {
      auto error_code_node{goaway_frame[YAML_ERROR_CODE_KEY]};
      if (error_code_node.IsScalar()) {
        auto error_code = Localizer::localize_upper(error_code_node.Scalar());
        auto abort_error = H2ErrorCodeNames[error_code];
        auto abort_frame = message._h2_frame_sequence[goaway_index - 1];
        if (abort_error != H2ErrorCode::INVALID && message.is_request()) {
          message._client_goaway_after = static_cast<int>(abort_frame);
          message._client_goaway_error = static_cast<int>(abort_error);
        } else if (abort_error != H2ErrorCode::INVALID && message.is_response()) {
          message._server_goaway_after = static_cast<int>(abort_frame);
          message._server_goaway_error = static_cast<int>(abort_error);
        } else {
          errata.note(
              S_ERROR,
              R"("{}" is not a valid error code.)",
              Localizer::localize_upper(error_code_node.Scalar()));
        }
      } else {
        errata.note(
            S_ERROR,
            R"("{}" value at {} must be a string.)",
            YAML_ERROR_CODE_KEY,
            error_code_node.Mark());
      }
    } else {
      errata.note(S_ERROR, "The GOAWAY frame node must NOT be the first in the frame sequence");
    }
  }

  if (!message._method.empty() && message._authority.empty()) {
    // The URL didn't have the authority. Get it from the Host header if it
    // exists.
    auto const it = message._fields_rules->_fields.find(FIELD_HOST);
    if (it != message._fields_rules->_fields.end()) {
      message._authority = it->second;
    }
  }

  // Do this after parsing fields so it can override transfer encoding.
  if (auto content_node{data_frame[YAML_CONTENT_KEY]}; content_node) {
    if (content_node.IsMap()) {
      if (auto xf_node{content_node[YAML_CONTENT_TRANSFER_KEY]}; xf_node) {
        TextView xf{xf_node.Scalar()};
        if (0 == strcasecmp("chunked"_tv, xf)) {
          message._chunked_p = true;
        } else if (0 == strcasecmp("plain"_tv, xf)) {
          // The user may be specifying raw chunk body content (i.e.,
          // specifying the chunk header with CRLF's, etc.). We set this to
          // false so that later, when the body is written, we don't
          // automagically try to frame the body as chunked for the user.
          message._chunked_p = false;
        } else {
          errata.note(
              S_ERROR,
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
            errata.note(S_ERROR, R"(Unknown encoding "{}" at {}.)", text, enc_node.Mark());
          }
        }
        TextView content{Localizer::localize(data_node.Scalar(), enc)};
        message._content_data = content.data();
        const size_t content_size = content.size();
        message._recorded_content_size = content_size;
        // Cross check against previously read content-length header, if any.
        if (message._content_length_p) {
          if (message._content_size != content_size) {
            errata.note(
                S_DIAG,
                R"(Conflicting sizes for "Content-Length", sending header value {} instead of data value {}.)",
                message._content_size,
                content_size);
            // _content_size will be the value of the Content-Length header.
          }
        } else {
          message._content_size = content_size;
        }

        if (auto verify_node(content_node[YAML_CONTENT_VERIFY_KEY]); verify_node) {
          if (verify_node.IsMap()) {
            // Verification is specified as a map, such as:
            // verify: {value: test, as: equal, case: ignore }
            errata.note(parse_body_verification(
                verify_node,
                message._content_rule,
                message._verify_strictly,
                content));
          }
        }
      } else if (auto size_node{content_node[YAML_CONTENT_SIZE_KEY]}; size_node) {
        const size_t content_size = swoc::svtou(size_node.Scalar());
        message._recorded_content_size = content_size;
        // Cross check against previously read content-length header, if any.
        if (message._content_length_p) {
          if (message._content_size != content_size) {
            errata.note(
                S_DIAG,
                R"(Conflicting sizes for "Content-Length", sending header value {} instead of rule value {}.)",
                message._content_size,
                content_size);
            // _content_size will be the value of the Content-Length header.
          }
        } else {
          message._content_size = content_size;
        }
        if (auto verify_node(content_node[YAML_CONTENT_VERIFY_KEY]); verify_node) {
          if (verify_node.IsMap()) {
            // Verification is specified as a map, such as:
            // verify: {value: test, as: equal, case: ignore }
            errata.note(parse_body_verification(
                verify_node,
                message._content_rule,
                message._verify_strictly));
          }
        }
      } else if (auto verify_node(content_node[YAML_CONTENT_VERIFY_KEY]); verify_node) {
        if (verify_node.IsMap()) {
          // Verification is specified as a map, such as:
          // verify: {value: test, as: equal, case: ignore }
          errata.note(parse_body_verification(
              verify_node,
              message._content_rule,
              message._verify_strictly));
        }
      } else {
        errata.note(
            S_ERROR,
            R"("{}" node at {} does not have a "{}", "{}" or "{}" key as required.)",
            YAML_CONTENT_KEY,
            node.Mark(),
            YAML_CONTENT_SIZE_KEY,
            YAML_CONTENT_DATA_KEY,
            YAML_CONTENT_VERIFY_KEY);
      }
    } else {
      errata
          .note(S_ERROR, R"("{}" node at {} is not a map.)", YAML_CONTENT_KEY, content_node.Mark());
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
          errata.note(S_ERROR, "Failed to parse fields and rules at {}", node.Mark());
          errata.note(std::move(result));
        }
      } else {
        errata.note(S_INFO, R"(Fields and rules node at {} is an empty list.)", rules_node.Mark());
      }
    } else {
      errata.note(S_INFO, R"(Fields and rules node at {} is not a sequence.)", rules_node.Mark());
    }
  } else {
    errata.note(S_INFO, R"(Node at {} is missing a fields node.)", node.Mark());
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
      errata.note(S_ERROR, "URL rule at {} is not a sequence as required.", node.Mark());
      continue;
    }
    const auto node_size = node.size();
    if (node_size != 2 && node_size != 3) {
      errata.note(
          S_ERROR,
          "URL rule at {} is not a sequence of length 2 "
          "or 3 as required.",
          node.Mark());
      continue;
    }

    TextView part_name{Localizer::localize_lower(node[YAML_RULE_KEY_INDEX].Scalar())};
    UrlPart part_id = HttpHeader::parse_url_part(part_name);
    if (part_id == UrlPart::Error) {
      errata.note(S_ERROR, "URL rule at {} has an invalid URL part.", node.Mark());
      continue;
    }
    const YAML::Node ValueNode{node[YAML_RULE_VALUE_INDEX]};
    if (ValueNode.IsScalar()) {
      // Legacy support for non-map nodes, not/nocase unsupported
      // URL part verification rules can't support multiple values,
      // so there's no IsSequence() case
      TextView value{Localizer::localize(node[YAML_RULE_VALUE_INDEX].Scalar())};
      if (node_size == 2 && assume_equality_rule) {
        fields._url_rules[static_cast<size_t>(part_id)].push_back(
            RuleCheck::make_equality(part_id, value));
      } else if (node_size == 3) {
        // Contains a verification rule.
        TextView rule_type{node[YAML_RULE_TYPE_INDEX].Scalar()};
        std::shared_ptr<RuleCheck> tester = RuleCheck::make_rule_check(part_id, value, rule_type);
        if (!tester) {
          errata.note(
              S_ERROR,
              "URL rule at {} does not have a valid directive ({})",
              node.Mark(),
              rule_type);
          continue;
        } else {
          fields._url_rules[static_cast<size_t>(part_id)].push_back(tester);
        }
      }
    } else if (ValueNode.IsMap()) {
      // Verification is specified as a map, such as:
      // - [ path, { value: config/settings.yaml, as: equal } ]

      // Get case setting (default false)
      auto const rule_case_node{ValueNode[YAML_RULE_CASE_MAP_KEY]};
      bool is_nocase = false;
      if (rule_case_node && rule_case_node.IsScalar()) {
        TextView case_str = Localizer::localize(rule_case_node.Scalar());
        if (case_str == VERIFICATION_DIRECTIVE_IGNORE) {
          is_nocase = true;
        }
      }

      // Get rule type for "as: equal" structure, or "not: equal" if "as" fails
      TextView rule_type;
      bool is_inverted = false;
      if (auto const rule_type_node_as = ValueNode[YAML_RULE_TYPE_MAP_KEY]; rule_type_node_as) {
        rule_type = rule_type_node_as.Scalar();
      } else if (auto const rule_type_node_not = ValueNode[YAML_RULE_TYPE_MAP_KEY_NOT];
                 rule_type_node_not)
      {
        rule_type = rule_type_node_not.Scalar();
        is_inverted = true;
      } else if (assume_equality_rule) {
        rule_type = VERIFICATION_DIRECTIVE_EQUALS;
      } else {
        errata.note(
            S_INFO,
            "URL rule at {} invalid: no directive, and equality is not assumed.",
            node.Mark());
        // Can continue because all URL maps are verification rules, unlike field rules
        continue;
      }

      TextView value;
      auto const url_value_node{ValueNode[YAML_RULE_VALUE_MAP_KEY]};
      if (url_value_node) {
        if (url_value_node.IsScalar()) {
          // Single value
          value = Localizer::localize(url_value_node.Scalar());
        } else if (url_value_node.IsSequence()) {
          errata.note(
              S_ERROR,
              "URL rule at {} has multiple values, which is not allowed.",
              node.Mark());
          continue;
        }
      }
      std::shared_ptr<RuleCheck> tester =
          RuleCheck::make_rule_check(part_id, value, rule_type, is_inverted, is_nocase);

      if (!tester) {
        errata.note(
            S_ERROR,
            "URL rule at {} does not have a valid directive ({}).",
            node.Mark(),
            rule_type);
      } else {
        fields._url_rules[static_cast<size_t>(part_id)].push_back(tester);
      }
    } else if (ValueNode.IsSequence()) {
      errata.note(
          S_ERROR,
          "URL rule at {} has multiple values, which is not allowed.",
          node.Mark());
    } else {
      errata.note(S_ERROR, "URL rule at {} is null or malformed.", node.Mark());
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
      errata.note(S_ERROR, "Field or rule at {} is not a sequence as required.", node.Mark());
      continue;
    }
    auto const node_size = node.size();
    if (node_size != 2 && node_size != 3) {
      errata.note(
          S_ERROR,
          "Field or rule at {} is not a sequence of length 2 "
          "or 3 as required.",
          node.Mark());
      continue;
    }

    // Get name of header being tested
    TextView name{Localizer::localize_lower(node[YAML_RULE_KEY_INDEX].Scalar())};
    const YAML::Node ValueNode{node[YAML_RULE_VALUE_INDEX]};
    if (ValueNode.IsScalar()) {
      // Legacy support for non-map nodes, not/nocase unsupported
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
          errata.note(
              S_ERROR,
              "Field rule at {} does not have a valid directive ({})",
              node.Mark(),
              rule_type);
          continue;
        } else {
          fields._rules.emplace(name, tester);
        }
      }
    } else if (ValueNode.IsSequence()) {
      // Legacy support for non-map nodes, not/nocase unsupported
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
          errata.note(
              S_ERROR,
              "Field rule at {} does not have a valid directive ({})",
              node.Mark(),
              rule_type);
          continue;
        } else {
          fields._rules.emplace(name, tester);
        }
      }
    } else if (ValueNode.IsMap()) {
      // Extensible format for future features added
      // Verification is specified as a map, such as:
      // -[ Host, { value: example.com, as: equal } ]

      // Get case setting (default false)
      auto const rule_case_node{ValueNode[YAML_RULE_CASE_MAP_KEY]};
      bool is_nocase = false;
      if (rule_case_node && rule_case_node.IsScalar()) {
        TextView case_str = Localizer::localize(rule_case_node.Scalar());
        if (case_str == VERIFICATION_DIRECTIVE_IGNORE) {
          is_nocase = true;
        }
      }

      // Get rule type for "as: equal" structure, or "not: equal" if "as" fails
      TextView rule_type;
      bool is_inverted = false;
      if (auto const rule_type_node_as = ValueNode[YAML_RULE_TYPE_MAP_KEY]; rule_type_node_as) {
        rule_type = rule_type_node_as.Scalar();
      } else if (auto const rule_type_node_not = ValueNode[YAML_RULE_TYPE_MAP_KEY_NOT];
                 rule_type_node_not)
      {
        rule_type = rule_type_node_not.Scalar();
        is_inverted = true;
      } else if (assume_equality_rule) {
        rule_type = VERIFICATION_DIRECTIVE_EQUALS;
      } else {
        errata.note(
            S_INFO,
            "Field rule at {} invalid: no directive, and equality is not assumed.",
            node.Mark());
        // Cannot use continue statement because of client request/server response
      }

      std::shared_ptr<RuleCheck> tester;
      TextView value;
      auto const field_value_node{ValueNode[YAML_RULE_VALUE_MAP_KEY]};
      if (field_value_node) {
        if (field_value_node.IsScalar()) {
          // Single value
          value = Localizer::localize(field_value_node.Scalar());
          fields.add_field(name, value);
          tester = RuleCheck::make_rule_check(name, value, rule_type, is_inverted, is_nocase);
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
          tester = RuleCheck::make_rule_check(
              name,
              std::move(values),
              rule_type,
              is_inverted,
              is_nocase);
        }
      } else {
        // Attempt to create check with empty value; if failure, next if will catch
        tester = RuleCheck::make_rule_check(name, value, rule_type, is_inverted, is_nocase);
      }

      if (tester) {
        fields._rules.emplace(name, tester);
      } else if (!rule_type.empty()) {
        // Do not report error if no rule because of client request/server response
        errata.note(
            S_ERROR,
            "Field rule at {} has an invalid directive ({}).",
            node.Mark(),
            rule_type);
      }
    } else {
      errata.note(S_ERROR, "Field or rule at {} is null or malformed.", node.Mark());
    }
  }
  return errata;
}

Errata
YamlParser::parse_body_verification(
    YAML::Node const &node,
    std::shared_ptr<RuleCheck> &rule_check,
    bool assume_equality_rule,
    TextView content)
{
  Errata errata;

  // Get case setting (default false)
  auto const rule_case_node{node[YAML_RULE_CASE_MAP_KEY]};
  bool is_nocase = false;
  if (rule_case_node && rule_case_node.IsScalar()) {
    TextView case_str = Localizer::localize(rule_case_node.Scalar());
    if (case_str == VERIFICATION_DIRECTIVE_IGNORE) {
      is_nocase = true;
    }
  }

  // Get rule type for "as: equal" structure, or "not: equal" if "as" fails
  TextView rule_type;
  bool is_inverted = false;
  if (auto const rule_type_node_as = node[YAML_RULE_TYPE_MAP_KEY]; rule_type_node_as) {
    rule_type = rule_type_node_as.Scalar();
  } else if (auto const rule_type_node_not = node[YAML_RULE_TYPE_MAP_KEY_NOT]; rule_type_node_not) {
    rule_type = rule_type_node_not.Scalar();
    is_inverted = true;
  } else if (assume_equality_rule) {
    rule_type = VERIFICATION_DIRECTIVE_EQUALS;
  } else {
    errata.note(
        S_INFO,
        "Body rule at {} invalid: no directive, and equality is not assumed.",
        node.Mark());
  }

  std::shared_ptr<RuleCheck> tester;
  auto const body_value_node{node[YAML_RULE_VALUE_MAP_KEY]};
  if (body_value_node) {
    if (body_value_node.IsScalar()) {
      // Single value
      TextView value = Localizer::localize(body_value_node.Scalar());
      tester = RuleCheck::make_rule_check("body", value, rule_type, is_inverted, is_nocase, true);
    } else if (body_value_node.IsSequence()) {
      errata.note(
          S_ERROR,
          "Body rule at {} has multiple values, which is not allowed.",
          node.Mark());
    }
  } else {
    tester = RuleCheck::make_rule_check("body", content, rule_type, is_inverted, is_nocase, true);
  }

  if (!tester) {
    errata.note(
        S_ERROR,
        "Body rule at {} does not have a valid directive ({}).",
        node.Mark(),
        rule_type);
  } else {
    rule_check = tester;
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
    errata.note(
        S_INFO,
        "Replay file parsing took: {} seconds.",
        duration_cast<seconds>(parsing_duration).count());
  } else {
    errata.note(
        S_INFO,
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
      errata.note(
          S_ERROR,
          "The {} node is not compatible with the {} pseudo header: {}",
          YAML_HTTP_METHOD_KEY,
          YAML_HTTP2_PSEUDO_METHOD_KEY,
          node.Mark());
    }
    message._method = pseudo_it->second;
    ++number_of_pseudo_headers;
    message.set_is_request();
  }
  pseudo_it = message._fields_rules->_fields.find(YAML_HTTP2_PSEUDO_SCHEME_KEY);
  if (pseudo_it != message._fields_rules->_fields.end()) {
    if (!message._scheme.empty()) {
      errata.note(
          S_ERROR,
          "The {} node is not compatible with the {} pseudo header: {}",
          YAML_HTTP_SCHEME_KEY,
          YAML_HTTP2_PSEUDO_SCHEME_KEY,
          node.Mark());
    }
    message._scheme = pseudo_it->second;
    ++number_of_pseudo_headers;
    message.set_is_request();
  }
  pseudo_it = message._fields_rules->_fields.find(YAML_HTTP2_PSEUDO_AUTHORITY_KEY);
  if (pseudo_it != message._fields_rules->_fields.end()) {
    auto const host_it = message._fields_rules->_fields.find(FIELD_HOST);
    if (host_it != message._fields_rules->_fields.end()) {
      // We intentionally allow this, even though contrary to spec, to allow the use
      // of Proxy Verifier to test proxy's handling of this.
      errata.note(
          S_INFO,
          "Contrary to spec, a transaction is specified with both {} and {} header fields: {}",
          YAML_HTTP2_PSEUDO_AUTHORITY_KEY,
          FIELD_HOST,
          node.Mark());
    } else if (!message._authority.empty()) {
      errata.note(
          S_ERROR,
          "The {} node is not compatible with the {} pseudo header: {}",
          YAML_HTTP_URL_KEY,
          YAML_HTTP2_PSEUDO_AUTHORITY_KEY,
          node.Mark());
    }
    message._authority = pseudo_it->second;
    ++number_of_pseudo_headers;
    message.set_is_request();
  }
  pseudo_it = message._fields_rules->_fields.find(YAML_HTTP2_PSEUDO_PATH_KEY);
  if (pseudo_it != message._fields_rules->_fields.end()) {
    if (!message._path.empty()) {
      errata.note(
          S_ERROR,
          "The {} node is not compatible with the {} pseudo header: {}",
          YAML_HTTP_URL_KEY,
          YAML_HTTP2_PSEUDO_PATH_KEY,
          node.Mark());
    }
    message._path = pseudo_it->second;
    ++number_of_pseudo_headers;
    message.set_is_request();
  }
  pseudo_it = message._fields_rules->_fields.find(YAML_HTTP2_PSEUDO_STATUS_KEY);
  if (pseudo_it != message._fields_rules->_fields.end()) {
    if (message._status != 0) {
      errata.note(
          S_ERROR,
          "The {} node is not compatible with the {} pseudo header: {}",
          YAML_HTTP_STATUS_KEY,
          YAML_HTTP2_PSEUDO_STATUS_KEY,
          node.Mark());
    }
    auto const &status_field_value = pseudo_it->second;
    TextView parsed;
    auto n = swoc::svtou(status_field_value, &parsed);
    if (parsed.size() == status_field_value.size() && ((0 < n && n <= 599) || n == 999)) {
      message._status = n;
      message._status_string = std::to_string(message._status);
    } else {
      errata.note(
          S_ERROR,
          R"("{}" pseudo header value "{}" at {} must be an integer in the range [1..599] or 999.)",
          YAML_HTTP2_PSEUDO_STATUS_KEY,
          status_field_value,
          node.Mark());
    }
    ++number_of_pseudo_headers;
    message.set_is_response();
  }
  if (number_of_pseudo_headers > 0) {
    // Do some sanity checking on the user's pseudo headers, if provided.
    if (message.is_response() && number_of_pseudo_headers != 1) {
      errata.note(
          S_ERROR,
          "Found a mixture of request and response pseudo header fields: {}",
          node.Mark());
    }
    if (message.is_request() && number_of_pseudo_headers != 4) {
      errata.note(
          S_ERROR,
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
    desired_node.note(
        S_ERROR,
        "Protocol node at {} is not a sequence as required.",
        protocol_node.Mark());
    return desired_node;
  }
  if (protocol_node.size() == 0) {
    desired_node.note(S_ERROR, "Protocol node at {} is an empty sequence.", protocol_node.Mark());
    return desired_node;
  }
  for (auto const &protocol_element : protocol_node) {
    if (!protocol_element.IsMap()) {
      desired_node.note(S_ERROR, "Protocol element at {} is not a map.", protocol_element.Mark());
      return desired_node;
    }
    if (!protocol_element[YAML_SSN_PROTOCOL_NAME]) {
      desired_node.note(
          S_ERROR,
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
      sni.note(
          S_ERROR,
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
      verify_mode.note(
          S_ERROR,
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
      alpn_protocol_string.note(
          S_ERROR,
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
  auto errata = std::move(opener.errata);
  if (!errata.is_ok()) {
    return errata;
  }
  std::error_code ec;
  std::string content{swoc::file::load(path, ec)};
  if (ec.value()) {
    errata.note(S_ERROR, R"(Error loading "{}": {})", path, ec);
    return errata;
  }
  YAML::Node root;
  auto global_fields_rules = std::make_shared<HttpFields>();
  try {
    root = YAML::Load(content);
    yaml_merge(root);
  } catch (std::exception const &ex) {
    errata.note(S_ERROR, R"(Exception: {} in "{}".)", ex.what(), path);
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
    errata
        .note(S_INFO, R"(No meta node ("{}") at "{}":{}.)", YAML_META_KEY, path, root.Mark().line);
  }
  handler.global_config = VerificationConfig{global_fields_rules};
  if (!root[YAML_SSN_KEY]) {
    errata.note(
        S_ERROR,
        R"(No sessions list ("{}") at "{}":{}.)",
        YAML_META_KEY,
        path,
        root.Mark().line);
    return errata;
  }
  auto ssn_list_node{root[YAML_SSN_KEY]};
  if (!ssn_list_node.IsSequence()) {
    errata.note(
        S_ERROR,
        R"("{}" value at "{}":{} is not a sequence.)",
        YAML_SSN_KEY,
        path,
        ssn_list_node.Mark());
    return errata;
  }
  if (ssn_list_node.size() == 0) {
    errata.note(
        S_DIAG,
        R"(Session list at "{}":{} is an empty list.)",
        path,
        ssn_list_node.Mark().line);
    return errata;
  }
  for (auto const &ssn_node : ssn_list_node) {
    // HeaderRules ssn_rules = global_rules;
    auto session_errata{handler.ssn_open(ssn_node)};
    if (!session_errata.is_ok()) {
      errata.note(std::move(session_errata));
      errata.note(S_ERROR, R"(Failure opening session at "{}":{}.)", path, ssn_node.Mark().line);
      continue;
    }
    if (!ssn_node[YAML_TXN_KEY]) {
      errata.note(
          S_ERROR,
          R"(Session at "{}":{} has no "{}" key.)",
          path,
          ssn_node.Mark().line,
          YAML_TXN_KEY);
      continue;
    }
    auto txn_list_node{ssn_node[YAML_TXN_KEY]};
    if (!txn_list_node.IsSequence()) {
      session_errata.note(
          S_ERROR,
          R"(Transaction list at {} in session at {} in "{}" is not a list.)",
          txn_list_node.Mark(),
          ssn_node.Mark(),
          path);
    }
    if (txn_list_node.size() == 0) {
      session_errata.note(
          S_INFO,
          R"(Transaction list at {} in session at {} in "{}" is an empty list.)",
          txn_list_node.Mark(),
          ssn_node.Mark(),
          path);
    }
    for (auto const &txn_node : txn_list_node) {
      // HeaderRules txn_rules = ssn_rules;
      auto txn_errata = handler.txn_open(txn_node);
      if (!txn_errata.is_ok()) {
        session_errata
            .note(S_ERROR, R"(Could not open transaction at {} in "{}".)", txn_node.Mark(), path);
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
        txn_errata
            .note(S_ERROR, R"(Failure with transaction at {} in "{}".)", txn_node.Mark(), path);
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
    errata.note(S_ERROR, R"(Invalid test directory "{}": [{}])", path, ec);
    errata.note(parsing_is_done());
    return errata;
  } else if (swoc::file::is_regular_file(stat)) {
    errata.note(loader(path));
    errata.note(parsing_is_done());
    return errata;
  } else if (!swoc::file::is_dir(stat)) {
    errata.note(S_ERROR, R"("{}" is not a file or a directory.)", path);
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

      errata.note(S_INFO, "Loading {} replay files.", n_sessions);
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
      errata.note(S_ERROR, R"(No replay files found in "{}".)", path);
    }
  } else {
    errata.note(S_ERROR, R"(Failed to access directory "{}": {}.)", path, swoc::bwf::Errno{});
  }
  errata.note(parsing_is_done());
  return errata;
}
