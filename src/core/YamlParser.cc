/** @file
 * Definition of YamlParser.
 *
 * Copyright 2026, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "core/YamlParser.h"
#include "core/ProxyVerifier.h"
#include "core/verification.h"

#include "core/Localizer.h"
#include "core/yaml_util.h"

#include <cassert>
#include <dirent.h>
#include <mutex>
#include <thread>
#include <type_traits>
#include <vector>

#include "swoc/Errata.h"
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
using ClockType = std::chrono::steady_clock;
using TimePoint = std::chrono::time_point<ClockType, nanoseconds>;

namespace
{
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

/** Shared data between file readers and file content parsers. */
class ReadFileQueue
{
public:
  /** Push read file content into the queue.
   *
   * File reader threads use this to push their read content into the queue.
   *
   * @param[in] file_content The content of the file to push into the queue.
   */
  void
  push(swoc::file::path const &path, std::string &&file_content)
  {
    {
      std::lock_guard<std::mutex> lock(_queue_mutex);
      _queue.emplace(FileInformation{path, std::move(file_content)});
    }
    _queue_cv.notify_one();
  }

  /** Pull out file content from the queue.
   *
   * File parser threads use this to pull file content from the queue for
   * parsing.
   *
   * @param[out] file_content The content of the file to pull from the queue.
   * @return True if there is content to pull, false otherwise.
   */
  bool
  pop(swoc::file::path &path, std::string &file_content)
  {
    std::unique_lock<std::mutex> lock(_queue_mutex);
    _queue_cv.wait(lock, [this]() { return !_queue.empty() || _done_reading_files; });
    // Note that we check empty rather than _done_reading_files because reader
    // threads generally finish before parsing threads.
    if (_queue.empty()) {
      return false;
    }
    auto const &file_info = _queue.front();
    path = std::move(file_info.file_name);
    file_content = std::move(file_info.content);
    _queue.pop();
    return true;
  }

  /** Indicate that all the readers should stop reading files.
   *
   * This can be done set either because all the files have been read
   * successfully, or because there was an error reading the files and the
   * readers should stop now that there was an error.
   */
  void
  set_is_done_reading_files()
  {
    {
      std::lock_guard<std::mutex> lock(_queue_mutex);
      _done_reading_files = true;
    }
    // All parsing threads should be woken up to parse any remaining files.
    _queue_cv.notify_all();
  }

  /** Stop reading the files.
   *
   * Either all the files have been read or there was an error reading one and
   * the other the reader threads should abort.
   */
  bool
  is_done_reading_files() const
  {
    std::lock_guard<std::mutex> lock(_queue_mutex);
    return _done_reading_files;
  }

private:
  struct FileInformation
  {
    swoc::file::path file_name;
    std::string content;
  };

  /** The container for fully read files. */
  std::queue<FileInformation> _queue;
  mutable std::mutex _queue_mutex;
  std::condition_variable _queue_cv;
  bool _done_reading_files = false;
};

/** The thread's logic for parsing file content and placing it in the queue. */
Errata
reader_thread(
    bool &shutdown_flag,
    ReadFileQueue &queue,
    const std::vector<swoc::file::path> &files,
    std::atomic<size_t> &index)
{
  Errata errata;
  while (!shutdown_flag && !queue.is_done_reading_files()) {
    size_t i = index++;
    if (i >= files.size()) {
      // All files are read.
      break;
    }
    std::error_code ec;
    const auto &file_path = files[i];
    std::string content{swoc::file::load(file_path, ec)};
    if (ec.value()) {
      errata.note(S_ERROR, R"(Error loading "{}": {})", file_path, ec);
      return errata;
    }
    queue.push(file_path, std::move(content));
  }
  return errata;
}

Errata
parser_thread(bool &shutdown_flag, ReadFileQueue &queue, YamlParser::loader_t &loader)
{
  Errata errata;
  swoc::file::path path;
  std::string content;
  while (!shutdown_flag && queue.pop(path, content)) {
    errata.note(loader(path, content));
  }
  return errata;
}

/** Spawn up and wait for the threads to read and parse the replay files.
 * @param[in] files The list of files to read and parse.
 * @param[in] handler The handler for each parsed content.
 * @param[in] n_reader_threads The number of reader threads to spawn.
 * @param[in] n_parser_threads The number of parser threads to spawn.
 * @return The status of reading and parsing the files.
 */
Errata
read_and_parse_files(
    std::vector<swoc::file::path> const &files,
    YamlParser::loader_t &loader,
    bool &shutdown_flag,
    int n_reader_threads,
    int n_parser_threads)
{
  Errata errata;
  std::mutex errata_mutex;
  ReadFileQueue queue;
  std::atomic<size_t> index(0);

  errata.note(S_INFO, "Loading {} replay files.", files.size());

  // -------------------------
  // Start reader threads.
  // -------------------------
  std::vector<std::thread> readers;
  // Create a wrapper, mostly to handle the returned Errata.
  auto reader_wrapper = [&errata, &shutdown_flag, &queue, &files, &index, &errata_mutex]() -> void {
    auto this_errata = reader_thread(shutdown_flag, queue, files, index);
    if (!this_errata.is_ok()) {
      queue.set_is_done_reading_files();
    }
    std::lock_guard<std::mutex> lock(errata_mutex);
    errata.note(this_errata);
  };
  for (int i = 0; i < n_reader_threads; ++i) {
    readers.emplace_back(reader_wrapper);
  }

  // -------------------------
  // Start parser threads.
  // -------------------------
  std::vector<std::thread> parsers;
  auto parser_wrapper = [&errata, &shutdown_flag, &queue, &loader, &errata_mutex]() -> void {
    auto this_errata = parser_thread(shutdown_flag, queue, loader);
    if (!this_errata.is_ok()) {
      queue.set_is_done_reading_files();
    }
    std::lock_guard<std::mutex> lock(errata_mutex);
    errata.note(this_errata);
  };
  for (int i = 0; i < n_parser_threads; ++i) {
    parsers.emplace_back(parser_wrapper);
  }

  // ---------------------------
  // Wait for threads to finish.
  // ---------------------------
  for (auto &reader : readers) {
    reader.join();
  }

  // Tell the parsing threads they no longer should expect more read files.
  queue.set_is_done_reading_files();

  // Now wait for the parser threads to finish.
  for (auto &parser : parsers) {
    parser.join();
  }

  return errata;
}
} // Anonymous namespace

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

swoc::Rv<Txn::ConnectAction>
get_on_connect_action(YAML::Node const &node)
{
  swoc::Rv<Txn::ConnectAction> zret{Txn::ConnectAction::ACCEPT};
  auto on_connect_node{node[YAML_HTTP_ON_CONNECT_KEY]};
  if (!on_connect_node) {
    return zret;
  }
  if (!on_connect_node.IsScalar()) {
    zret.note(S_ERROR, R"("{}" key that is not a scalar.)", YAML_HTTP_ON_CONNECT_KEY);
    return zret;
  }

  auto const action = on_connect_node.Scalar();
  if (action == "accept") {
    zret = Txn::ConnectAction::ACCEPT;
  } else if (action == "refuse") {
    zret = Txn::ConnectAction::REFUSE;
  } else if (action == "reset") {
    zret = Txn::ConnectAction::RESET;
  } else {
    zret.note(
        S_ERROR,
        R"(Unrecognized "{}" value "{}". Expected one of: accept, refuse, reset.)",
        YAML_HTTP_ON_CONNECT_KEY,
        action);
  }
  return zret;
}

Errata
validate_psuedo_headers(const HttpHeader &hdr, int number_of_pseudo_headers)
{
  Errata errata;
  if (hdr.is_response()) {
    if (number_of_pseudo_headers != 1 || hdr._status == 0) {
      // The response should contain and only contain the :status pseudo-header
      // field per RFC9113 section 8.3.2.
      errata.note(S_ERROR, "The response must include only the :status pseudo-header field.");
    }
    return errata;
  }
  // This is a request header.
  if (hdr._method == "CONNECT") {
    // CONNECT requests have some special rules for pseudo-headers. Refer to
    // RFC9113 section 8.5 for more details.
    if (!hdr._scheme.empty() || !hdr._path.empty()) {
      errata.note(
          S_ERROR,
          "The :scheme and :path pseudo-header fields must be omitted in a CONNECT request.");
    }
    if (hdr._authority.empty()) {
      errata.note(
          S_ERROR,
          "The :authority pseudo-header field must be included in a CONNECT request.");
    }
  } else if (hdr._method.empty() || hdr._scheme.empty() || hdr._path.empty()) {
    // Missing required pseudo-header fields for non-CONNECT requests. See
    // RFC9113 section 8.3.1.
    errata.note(
        S_ERROR,
        "Did not find all the required pseudo-header fields "
        "(:method, :scheme, :path)");
  }
  return errata;
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
  YAML::Node rst_stream_frame;
  YAML::Node goaway_frame;
  std::deque<YAML::Node> data_frames;

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
            data_frames.push_back(value);
            break;
          case H2Frame::RST_STREAM:
            if (!rst_stream_frame.IsNull()) {
              errata.note(S_ERROR, "RST_STREAM frame has already been specified.");
            } else if (!goaway_frame.IsNull()) {
              errata.note(S_ERROR, "GOAWAY frame has already been specified.");
            } else {
              rst_stream_frame = value;
            }
            break;
          case H2Frame::GOAWAY:
            if (!rst_stream_frame.IsNull()) {
              errata.note(S_ERROR, "RST_STREAM frame has already been specified.");
            } else if (!goaway_frame.IsNull()) {
              errata.note(S_ERROR, "GOAWAY frame has already been specified.");
            } else {
              goaway_frame = value;
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
  if (data_frames.empty()) {
    data_frames.push_back(node);
  }
  if (data_frames.size() > 1) {
    message._content_data_list.resize(data_frames.size());
    message._content_size_list.resize(data_frames.size());
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
  // Parse the trailer.
  if (node[YAML_TRAILER_KEY]) {
    auto hdr_node{node[YAML_TRAILER_KEY]};
    if (hdr_node[YAML_FIELDS_KEY]) {
      auto field_list_node{hdr_node[YAML_FIELDS_KEY]};
      Errata result = parse_fields_and_rules(
          field_list_node,
          *message._trailer_fields_rules,
          message._verify_strictly);
      if (!result.is_ok()) {
        errata.note(S_ERROR, "Failed to parse trailer at {}", node.Mark());
        errata.note(std::move(result));
      }
    }
  }
  errata.note(process_pseudo_headers(headers_frame, message));

  if (!rst_stream_frame.IsNull()) {
    auto error_code_node{rst_stream_frame[YAML_ERROR_CODE_KEY]};
    if (error_code_node.IsScalar()) {
      auto error_code = Localizer::localize_upper(error_code_node.Scalar());
      auto abort_error = H2ErrorCodeNames[error_code];
      if (abort_error != H2ErrorCode::INVALID && message.is_request()) {
        message._client_rst_stream_error = static_cast<int>(abort_error);
      } else if (abort_error != H2ErrorCode::INVALID && message.is_response()) {
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
  }

  if (!goaway_frame.IsNull()) {
    auto error_code_node{goaway_frame[YAML_ERROR_CODE_KEY]};
    if (error_code_node.IsScalar()) {
      auto error_code = Localizer::localize_upper(error_code_node.Scalar());
      auto abort_error = H2ErrorCodeNames[error_code];
      if (abort_error != H2ErrorCode::INVALID && message.is_request()) {
        message._client_goaway_error = static_cast<int>(abort_error);
      } else if (abort_error != H2ErrorCode::INVALID && message.is_response()) {
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
  }

  if (!message._h2_frame_sequence.empty()) {
    size_t data_frame_idx = 0;
    for (const auto &frame : message._h2_frame_sequence) {
      YAML::Node temp_node;
      switch (frame) {
      case H2Frame::HEADERS:
        temp_node = headers_frame;
        break;
      case H2Frame::DATA:
        temp_node = data_frames.at(data_frame_idx++);
        break;
      case H2Frame::RST_STREAM:
        temp_node = rst_stream_frame;
        break;
      case H2Frame::GOAWAY:
        temp_node = goaway_frame;
        break;
      default:
        break;
      }
      if (!temp_node.IsNull() && temp_node[YAML_TIME_DELAY_KEY]) {
        auto &&[delay_time, delay_errata] = get_delay_time(temp_node);
        if (!delay_errata.is_ok()) {
          errata.note(std::move(delay_errata));
          errata.note(
              S_ERROR,
              R"({} has a bad "{}" key value.)",
              temp_node.Mark(),
              YAML_TIME_DELAY_KEY);
        } else {
          if (message.is_request()) {
            if (auto search = message._client_frame_delay.find(frame);
                search == message._client_frame_delay.end())
            {
              message._client_frame_delay[frame] =
                  std::deque<std::chrono::microseconds>{delay_time};
            } else {
              message._client_frame_delay[frame].push_back(delay_time);
            }
          } else if (message.is_response()) {
            if (auto search = message._server_frame_delay.find(frame);
                search == message._server_frame_delay.end())
            {
              message._server_frame_delay[frame] =
                  std::deque<std::chrono::microseconds>{delay_time};
            } else {
              message._server_frame_delay[frame].push_back(delay_time);
            }
          }
        }
      }
    }
  }
  auto const it = message._fields_rules->_fields.find(FIELD_EXPECT);
  if (it != message._fields_rules->_fields.end()) {
    TextView value{it->second};
    if (0 == strcasecmp("100-continue"_tv, value)) {
      message.set_is_request_with_expect_100_continue();
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

  for (size_t i = 0; i < data_frames.size(); ++i) {
    // Do this after parsing fields so it can override transfer encoding.
    if (auto content_node{data_frames.at(i)[YAML_CONTENT_KEY]}; content_node) {
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
          message._content_data_list.at(i) = content.data();
          const size_t content_size = content.size();
          message._content_size_list.at(i) = content_size;
          message._recorded_content_size += content_size;
          // Cross check against previously read content-length header, if any.
          if (message._content_length_p) {
            if (message._content_length != message._recorded_content_size) {
              errata.note(
                  S_DIAG,
                  R"(Conflicting sizes for "Content-Length", sending header value {} instead of data value {}.)",
                  message._content_length,
                  message._recorded_content_size);
              // _content_length will be the value of the Content-Length header.
            }
          } else {
            message._content_length += content_size;
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
          message._content_size_list.at(i) = content_size;
          message._recorded_content_size += content_size;
          // Cross check against previously read content-length header, if any.
          if (message._content_length_p) {
            if (message._content_length != message._recorded_content_size) {
              errata.note(
                  S_DIAG,
                  R"(Conflicting sizes for "Content-Length", sending header value {} instead of rule value {}.)",
                  message._content_length,
                  message._recorded_content_size);
              // _content_length will be the value of the Content-Length header.
            }
          } else {
            message._content_length += content_size;
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
        errata.note(
            S_ERROR,
            R"("{}" node at {} is not a map.)",
            YAML_CONTENT_KEY,
            content_node.Mark());
      }
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
    auto psuedo_header_validation_errata =
        validate_psuedo_headers(message, number_of_pseudo_headers);
    if (!psuedo_header_validation_errata.is_ok()) {
      errata.note(S_ERROR, "Invalid pseudo-headers detected at {}.", node.Mark());
      errata.note(std::move(psuedo_header_validation_errata));
    }
    // Pseudo header fields currently implies HTTP/2.
    message._http_version = "2";
    message._contains_pseudo_headers_in_fields_array = true;
  }
  return errata;
}

ReplayFileHandler::ParsedProtocolNode::ParsedProtocolNode(YAML::Node const &protocol_node)
{
  parse_node(protocol_node);
}

bool
ReplayFileHandler::ParsedProtocolNode::is_valid() const
{
  return _errata.is_ok();
}

swoc::Errata const &
ReplayFileHandler::ParsedProtocolNode::errata() const
{
  return _errata;
}

ReplayFileHandler::HttpProtocol
ReplayFileHandler::ParsedProtocolNode::get_http_protocol() const
{
  return _http_protocol;
}

bool
ReplayFileHandler::ParsedProtocolNode::is_tls() const
{
  return _http_protocol == HttpProtocol::HTTPS || _http_protocol == HttpProtocol::HTTP2 ||
         _http_protocol == HttpProtocol::HTTP3 || _is_tls;
}

std::optional<std::string> const &
ReplayFileHandler::ParsedProtocolNode::get_tls_sni_name() const
{
  return _tls_sni_name;
}

std::optional<int> const &
ReplayFileHandler::ParsedProtocolNode::get_tls_verify_mode() const
{
  return _tls_verify_mode;
}

std::optional<bool> const &
ReplayFileHandler::ParsedProtocolNode::should_request_certificate() const
{
  return _should_request_certificate;
}

std::optional<bool> const &
ReplayFileHandler::ParsedProtocolNode::proxy_provided_certificate() const
{
  return _proxy_provided_certificate;
}

std::optional<std::string> const &
ReplayFileHandler::ParsedProtocolNode::get_tls_alpn_protocols_string() const
{
  return _tls_alpn_protocols_string;
}

std::optional<int> const &
ReplayFileHandler::ParsedProtocolNode::get_proxy_protocol_version() const
{
  return _proxy_protocol_version;
}

std::optional<std::string> const &
ReplayFileHandler::ParsedProtocolNode::get_proxy_protocol_src_addr() const
{
  return _proxy_protocol_src_addr;
}

std::optional<std::string> const &
ReplayFileHandler::ParsedProtocolNode::get_proxy_protocol_dst_addr() const
{
  return _proxy_protocol_dst_addr;
}

void
ReplayFileHandler::ParsedProtocolNode::parse_node(YAML::Node const &protocol_node)
{
  if (protocol_node.IsSequence()) {
    parse_verbose_sequence(protocol_node);
  } else if (protocol_node.IsMap()) {
    parse_concise_map(protocol_node);
  } else {
    _errata.note(
        S_ERROR,
        "Protocol node at {} is not a sequence or map as required.",
        protocol_node.Mark());
  }

  if (_errata.is_ok()) {
    finalize_http_protocol();
  }
}

void
ReplayFileHandler::ParsedProtocolNode::parse_verbose_sequence(YAML::Node const &protocol_node)
{
  if (protocol_node.size() == 0) {
    _errata.note(S_ERROR, "Protocol node at {} is an empty sequence.", protocol_node.Mark());
    return;
  }

  for (auto const &protocol_element : protocol_node) {
    parse_verbose_protocol_element(protocol_element);
    if (!_errata.is_ok()) {
      return;
    }
  }
}

void
ReplayFileHandler::ParsedProtocolNode::parse_verbose_protocol_element(
    YAML::Node const &protocol_element)
{
  if (!protocol_element.IsMap()) {
    _errata.note(S_ERROR, "Protocol element at {} is not a map.", protocol_element.Mark());
    return;
  }

  auto const name_node = protocol_element[YAML_SSN_PROTOCOL_NAME];
  if (!name_node) {
    _errata.note(
        S_ERROR,
        R"(Protocol element at {} does not have a "{}" element.)",
        protocol_element.Mark(),
        YAML_SSN_PROTOCOL_NAME);
    return;
  }

  if (!name_node.IsScalar()) {
    _errata.note(
        S_ERROR,
        R"(Protocol element "{}" at {} is not a scalar.)",
        YAML_SSN_PROTOCOL_NAME,
        name_node.Mark());
    return;
  }

  auto const protocol_name = name_node.Scalar();
  if (protocol_name == YAML_SSN_PROTOCOL_HTTP_NAME) {
    if (!_has_http_details) {
      parse_http_node(protocol_element, false);
    }
  } else if (protocol_name == YAML_SSN_PROTOCOL_TLS_NAME) {
    if (!_has_tls_details) {
      parse_tls_node(protocol_element);
    }
  } else if (protocol_name == YAML_SSN_PROTOCOL_PP_NAME) {
    if (!_has_proxy_protocol_details) {
      parse_proxy_protocol_node(protocol_element, false);
    }
  } else if (
      protocol_name == YAML_SSN_PROTOCOL_TCP_NAME || protocol_name == YAML_SSN_PROTOCOL_IP_NAME)
  {
    validate_transport_node(protocol_element, protocol_name);
  }
}

void
ReplayFileHandler::ParsedProtocolNode::parse_concise_map(YAML::Node const &protocol_node)
{
  bool saw_protocol_entry = false;
  for (auto const &[key, value] : protocol_node) {
    static_cast<void>(value);
    auto const key_name = key.Scalar();
    if (!is_supported_map_key(key_name)) {
      _errata.note(
          S_ERROR,
          R"(Protocol map at {} has unsupported key "{}".)",
          protocol_node.Mark(),
          key_name);
    } else {
      saw_protocol_entry = true;
    }
  }
  if (!_errata.is_ok()) {
    return;
  }

  if (protocol_node[YAML_SSN_PROTOCOL_STACK_KEY] && protocol_node[YAML_SSN_PROTOCOL_HTTP_NAME]) {
    _errata.note(
        S_ERROR,
        R"(Protocol map at {} cannot specify both "{}" and "{}".)",
        protocol_node.Mark(),
        YAML_SSN_PROTOCOL_STACK_KEY,
        YAML_SSN_PROTOCOL_HTTP_NAME);
    return;
  }

  parse_stack_value(protocol_node);
  if (!_errata.is_ok()) {
    return;
  }

  if (auto const http_node{protocol_node[YAML_SSN_PROTOCOL_HTTP_NAME]}; http_node) {
    parse_http_node(http_node, true);
    if (!_errata.is_ok()) {
      return;
    }
  }

  if (auto const explicit_tls_node{protocol_node[YAML_SSN_PROTOCOL_TLS_NAME]}; explicit_tls_node) {
    auto const stack_node = protocol_node[YAML_SSN_PROTOCOL_STACK_KEY];
    if (stack_node && stack_node.IsScalar() && stack_node.Scalar() == YAML_SSN_STACK_HTTP) {
      _errata.note(
          S_ERROR,
          R"(Protocol map at {} cannot specify TLS options when "{}" is "{}". Did you mean "{}: {}"?)",
          protocol_node.Mark(),
          YAML_SSN_PROTOCOL_STACK_KEY,
          YAML_SSN_STACK_HTTP,
          YAML_SSN_PROTOCOL_STACK_KEY,
          YAML_SSN_STACK_HTTPS);
      return;
    }
    parse_tls_node(explicit_tls_node);
    if (!_errata.is_ok()) {
      return;
    }
  }

  if (auto const pp_node{protocol_node[YAML_SSN_PROTOCOL_PP_NAME]}; pp_node) {
    parse_proxy_protocol_node(pp_node, true);
    if (!_errata.is_ok()) {
      return;
    }
  }

  for (auto const *transport_name : {&YAML_SSN_PROTOCOL_TCP_NAME, &YAML_SSN_PROTOCOL_IP_NAME}) {
    if (auto const transport_node{protocol_node[*transport_name]}; transport_node) {
      validate_transport_node(transport_node, *transport_name);
      if (!_errata.is_ok()) {
        return;
      }
    }
  }

  if (!saw_protocol_entry) {
    _errata.note(S_ERROR, "Protocol node at {} is an empty map.", protocol_node.Mark());
  }
}

bool
ReplayFileHandler::ParsedProtocolNode::is_supported_map_key(std::string_view key_name) const
{
  return key_name == YAML_SSN_PROTOCOL_STACK_KEY || key_name == YAML_SSN_PROTOCOL_HTTP_NAME ||
         key_name == YAML_SSN_PROTOCOL_TLS_NAME || key_name == YAML_SSN_PROTOCOL_PP_NAME ||
         key_name == YAML_SSN_PROTOCOL_TCP_NAME || key_name == YAML_SSN_PROTOCOL_IP_NAME;
}

void
ReplayFileHandler::ParsedProtocolNode::parse_stack_value(YAML::Node const &protocol_node)
{
  auto const stack_node = protocol_node[YAML_SSN_PROTOCOL_STACK_KEY];
  if (!stack_node) {
    return;
  }

  if (!stack_node.IsScalar()) {
    _errata.note(
        S_ERROR,
        R"("{}" value at {} must be a scalar.)",
        YAML_SSN_PROTOCOL_STACK_KEY,
        stack_node.Mark());
    return;
  }

  auto const stack = stack_node.Scalar();
  _has_http_details = true;
  if (stack == YAML_SSN_STACK_HTTP) {
    _http_version = "1.1";
  } else if (stack == YAML_SSN_STACK_HTTPS) {
    _http_version = "1.1";
    _is_tls = true;
  } else if (stack == YAML_SSN_STACK_HTTP2) {
    _http_version = "2";
  } else if (stack == YAML_SSN_STACK_HTTP3) {
    _http_version = "3";
  } else {
    _errata.note(
        S_ERROR,
        R"(Unsupported "{}" value "{}" at {}. Expected one of: {}, {}, {}, {}.)",
        YAML_SSN_PROTOCOL_STACK_KEY,
        stack,
        stack_node.Mark(),
        YAML_SSN_STACK_HTTP,
        YAML_SSN_STACK_HTTPS,
        YAML_SSN_STACK_HTTP2,
        YAML_SSN_STACK_HTTP3);
  }
}

void
ReplayFileHandler::ParsedProtocolNode::parse_http_node(
    YAML::Node const &http_node,
    bool allow_scalar_version)
{
  if (http_node.IsScalar()) {
    if (!allow_scalar_version) {
      _errata.note(
          S_ERROR,
          R"("{}" value at {} must be a map.)",
          YAML_SSN_PROTOCOL_HTTP_NAME,
          http_node.Mark());
      return;
    }
    _has_http_details = true;
    parse_http_version_node(http_node);
    return;
  }

  if (!http_node.IsMap()) {
    _errata.note(
        S_ERROR,
        R"("{}" value at {} must be a map{}.)",
        YAML_SSN_PROTOCOL_HTTP_NAME,
        http_node.Mark(),
        allow_scalar_version ? " or scalar" : "");
    return;
  }

  _has_http_details = true;
  if (auto const version_node{http_node[YAML_SSN_PROTOCOL_VERSION]}; version_node) {
    parse_http_version_node(version_node);
  }
}

void
ReplayFileHandler::ParsedProtocolNode::parse_http_version_node(YAML::Node const &version_node)
{
  if (!version_node.IsScalar()) {
    _errata.note(
        S_ERROR,
        R"(Protocol "{}" value at {} must be a scalar.)",
        YAML_SSN_PROTOCOL_VERSION,
        version_node.Mark());
    return;
  }

  _http_version = version_node.Scalar();
}

void
ReplayFileHandler::ParsedProtocolNode::parse_tls_node(YAML::Node const &tls_node)
{
  if (!tls_node.IsMap()) {
    _errata.note(
        S_ERROR,
        R"("{}" value at {} must be a map.)",
        YAML_SSN_PROTOCOL_TLS_NAME,
        tls_node.Mark());
    return;
  }

  _is_tls = true;
  _has_tls_details = true;
  parse_scalar_string_node(tls_node, YAML_SSN_TLS_SNI_KEY, _tls_sni_name);
  if (!_errata.is_ok()) {
    return;
  }

  parse_scalar_integer_node(tls_node, YAML_SSN_TLS_VERIFY_MODE_KEY, _tls_verify_mode);
  if (!_errata.is_ok()) {
    return;
  }

  parse_boolean_directive(
      tls_node,
      YAML_SSN_TLS_REQUEST_CERTIFICATE_KEY,
      _should_request_certificate);
  if (!_errata.is_ok()) {
    return;
  }

  parse_boolean_directive(
      tls_node,
      YAML_SSN_TLS_PROXY_PROVIDED_CERTIFICATE_KEY,
      _proxy_provided_certificate);
  if (!_errata.is_ok()) {
    return;
  }

  if (auto const alpn_protocols_node{tls_node[YAML_SSN_TLS_ALPN_PROTOCOLS_KEY]};
      alpn_protocols_node) {
    if (!alpn_protocols_node.IsSequence()) {
      _errata.note(
          S_ERROR,
          R"(Session has a value for key "{}" that is not a sequence as required.)",
          YAML_SSN_TLS_ALPN_PROTOCOLS_KEY);
      return;
    }
    for (auto const &protocol : alpn_protocols_node) {
      if (!protocol.IsScalar()) {
        _errata.note(
            S_ERROR,
            R"(Session has a non-scalar entry in "{}" at {}.)",
            YAML_SSN_TLS_ALPN_PROTOCOLS_KEY,
            protocol.Mark());
        return;
      }
      std::string_view protocol_view{protocol.Scalar()};
      if (!_tls_alpn_protocols_string.has_value()) {
        _tls_alpn_protocols_string = std::string{};
      }
      _tls_alpn_protocols_string->append(1, static_cast<char>(protocol_view.size()));
      _tls_alpn_protocols_string->append(protocol_view);
    }
  }
}

void
ReplayFileHandler::ParsedProtocolNode::parse_proxy_protocol_node(
    YAML::Node const &proxy_protocol_node,
    bool allow_scalar_version)
{
  if (proxy_protocol_node.IsScalar()) {
    if (!allow_scalar_version) {
      _errata.note(
          S_ERROR,
          R"("{}" value at {} must be a map.)",
          YAML_SSN_PROTOCOL_PP_NAME,
          proxy_protocol_node.Mark());
      return;
    }
    _has_proxy_protocol_details = true;
    parse_proxy_protocol_version_node(proxy_protocol_node);
    return;
  }

  if (!proxy_protocol_node.IsMap()) {
    _errata.note(
        S_ERROR,
        R"("{}" value at {} must be a map{}.)",
        YAML_SSN_PROTOCOL_PP_NAME,
        proxy_protocol_node.Mark(),
        allow_scalar_version ? " or scalar" : "");
    return;
  }

  _has_proxy_protocol_details = true;
  auto const version_node = proxy_protocol_node[YAML_SSN_PROTOCOL_VERSION];
  if (!version_node) {
    _errata.note(
        S_ERROR,
        R"(Invalid PROXY protocol version specified in session at {}.)",
        proxy_protocol_node.Mark());
    return;
  }
  parse_proxy_protocol_version_node(version_node);
  if (!_errata.is_ok()) {
    return;
  }

  parse_scalar_string_node(proxy_protocol_node, YAML_SSN_PP_SRC_ADDR_KEY, _proxy_protocol_src_addr);
  if (!_errata.is_ok()) {
    return;
  }
  parse_scalar_string_node(proxy_protocol_node, YAML_SSN_PP_DST_ADDR_KEY, _proxy_protocol_dst_addr);
  if (!_errata.is_ok()) {
    return;
  }

  if (_proxy_protocol_src_addr.has_value() != _proxy_protocol_dst_addr.has_value()) {
    _errata.note(
        S_ERROR,
        R"(Invalid PROXY protocol address specification detected at {} - Need to specify none or both of the source and destination addresses.)",
        proxy_protocol_node.Mark());
  }
}

void
ReplayFileHandler::ParsedProtocolNode::parse_proxy_protocol_version_node(
    YAML::Node const &version_node)
{
  if (!version_node.IsScalar()) {
    _errata.note(
        S_ERROR,
        R"(Protocol "{}" value at {} must be a scalar.)",
        YAML_SSN_PROTOCOL_VERSION,
        version_node.Mark());
    return;
  }

  auto const version = version_node.Scalar();
  if (version == "1") {
    _proxy_protocol_version = 1;
  } else if (version == "2") {
    _proxy_protocol_version = 2;
  } else {
    _errata.note(
        S_ERROR,
        R"(Invalid PROXY protocol version specified in session at {}.)",
        version_node.Mark());
  }
}

void
ReplayFileHandler::ParsedProtocolNode::validate_transport_node(
    YAML::Node const &transport_node,
    std::string_view transport_name)
{
  if (!transport_node.IsMap()) {
    _errata
        .note(S_ERROR, R"("{}" value at {} must be a map.)", transport_name, transport_node.Mark());
  }
}

void
ReplayFileHandler::ParsedProtocolNode::parse_scalar_string_node(
    YAML::Node const &parent_node,
    std::string_view key_name,
    std::optional<std::string> &target)
{
  if (auto const child_node{parent_node[std::string{key_name}]}; child_node) {
    if (!child_node.IsScalar()) {
      _errata.note(
          S_ERROR,
          R"(Session has a value for key "{}" that is not a scalar as required.)",
          key_name);
      return;
    }
    target = child_node.Scalar();
  }
}

void
ReplayFileHandler::ParsedProtocolNode::parse_scalar_integer_node(
    YAML::Node const &parent_node,
    std::string_view key_name,
    std::optional<int> &target)
{
  if (auto const child_node{parent_node[std::string{key_name}]}; child_node) {
    if (!child_node.IsScalar()) {
      _errata.note(
          S_ERROR,
          R"(Session has a value for key "{}" that is not a scalar as required.)",
          key_name);
      return;
    }

    swoc::TextView const value{child_node.Scalar()};
    swoc::TextView parsed;
    auto const parsed_value = swoc::svtou(value, &parsed);
    if (parsed.size() != value.size()) {
      _errata.note(
          S_ERROR,
          R"(Session has an invalid integer value "{}" for key "{}".)",
          value,
          key_name);
      return;
    }
    target = static_cast<int>(parsed_value);
  }
}

void
ReplayFileHandler::ParsedProtocolNode::finalize_http_protocol()
{
  if (_http_version == "2") {
    _http_protocol = HttpProtocol::HTTP2;
  } else if (_http_version == "3") {
    _http_protocol = HttpProtocol::HTTP3;
  } else if (_is_tls) {
    _http_protocol = HttpProtocol::HTTPS;
  } else {
    _http_protocol = HttpProtocol::HTTP;
  }
}

void
ReplayFileHandler::ParsedProtocolNode::parse_boolean_directive(
    YAML::Node const &parent_node,
    std::string_view key_name,
    std::optional<bool> &target)
{
  if (auto const child_node{parent_node[std::string{key_name}]}; child_node) {
    if (!child_node.IsScalar()) {
      _errata.note(
          S_ERROR,
          R"(Session has a value for key "{}" that is not a scalar as required.)",
          key_name);
      return;
    }
    try {
      target = child_node.as<bool>();
    } catch (std::exception const &) {
      _errata.note(
          S_ERROR,
          R"(Session has an invalid boolean value "{}" for key "{}".)",
          child_node.Scalar(),
          key_name);
    }
  }
}

swoc::Rv<ReplayFileHandler::ParsedProtocolNode>
ReplayFileHandler::parse_protocol_node(YAML::Node const &protocol_node)
{
  swoc::Rv<ParsedProtocolNode> parsed_protocol{ParsedProtocolNode{protocol_node}};
  if (!parsed_protocol.result().is_valid()) {
    parsed_protocol.note(parsed_protocol.result().errata());
  }
  return parsed_protocol;
}

Errata
YamlParser::load_replay_file(
    swoc::file::path const &path,
    std::string const &content,
    ReplayFileHandler &handler)
{
  HandlerOpener opener(handler, path);
  auto errata = std::move(opener.errata);
  if (!errata.is_ok()) {
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
      continue;
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
        txn_errata
            .note(S_ERROR, R"(Could not open transaction at {} in "{}".)", txn_node.Mark(), path);
        session_errata.note(std::move(txn_errata));
        continue;
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
YamlParser::load_replay_files(
    swoc::file::path const &path,
    loader_t loader,
    bool &shutdown_flag,
    int n_reader_threads,
    int n_parser_threads)
{
  Errata errata;
  errata.note(parsing_is_started());
  std::error_code ec;

  auto stat{swoc::file::status(path, ec)};
  if (ec) {
    errata.note(S_ERROR, R"(Invalid test directory "{}": [{}])", path, ec);
    errata.note(parsing_is_done());
    return errata;
  } else if (swoc::file::is_regular_file(stat)) {
    std::string content = swoc::file::load(path, ec);
    if (ec.value()) {
      errata.note(S_ERROR, R"(Error loading "{}": {})", path, ec);
      return errata;
    }
    errata.note(loader(path, content));
    errata.note(parsing_is_done());
    return errata;
  } else if (!swoc::file::is_dir(stat)) {
    errata.note(S_ERROR, R"("{}" is not a file or a directory.)", path);
    errata.note(parsing_is_done());
    return errata;
  }

  if (0 == chdir(path.c_str())) {
    dirent **elements = nullptr;
    int n_sessions = ::scandir(
        ".",
        &elements,
        [](dirent const *entry) -> int {
          auto extension = swoc::TextView{entry->d_name, strlen(entry->d_name)}.suffix_at('.');
          return 0 == strcasecmp(extension, "json") || 0 == strcasecmp(extension, "yaml");
        },
        &alphasort);
    if (n_sessions > 0) {
      // Working with swoc::file::path is more conventient than dirent.
      std::vector<swoc::file::path> files;
      for (int i = 0; i < n_sessions; i++) {
        files.emplace_back(swoc::file::path{elements[i]->d_name});
      }
      for (int i = 0; i < n_sessions; i++) {
        free(elements[i]);
      }
      free(elements);

      errata.note(
          read_and_parse_files(files, loader, shutdown_flag, n_reader_threads, n_parser_threads));

    } else {
      errata.note(S_ERROR, R"(No replay files found in "{}".)", path);
    }
  } else {
    errata.note(S_ERROR, R"(Failed to access directory "{}": {}.)", path, swoc::bwf::Errno{});
  }
  errata.note(parsing_is_done());
  return errata;
}
