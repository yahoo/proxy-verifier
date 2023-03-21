/** @file
 * Common data structures and definitions for Proxy Verifier tools.
 *
 * Copyright 2022, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "case_insensitive_utils.h"

#include <chrono>
#include <list>
#include <deque>
#include <map>
#include <unordered_map>
#include <nghttp2/nghttp2.h>
#include <nghttp3/nghttp3.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <string>
#include <vector>

#include "core/proxy_protocol_util.h"

#include "swoc/BufferWriter.h"
#include "swoc/Errata.h"
#include "swoc/Lexicon.h"
#include "swoc/MemArena.h"
#include "swoc/swoc_file.h"
#include "swoc/swoc_ip.h"
#include "swoc/TextView.h"

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

// This should be in the same order as "nghttp2_frame_type".
enum class H2Frame {
  DATA = 0x00,
  HEADERS = 0x01,
  PRIORITY = 0x02,
  RST_STREAM = 0x03,
  SETTINGS = 0x04,
  PUSH_PROMISE = 0x05,
  PING = 0x06,
  GOAWAY = 0x07,
  WINDOW_UPDATE = 0x08,
  CONTINUATION = 0x09,
  ALTSVC = 0x0a,
  ORIGIN = 0x0c,
  INVALID = -0x01
};

static const std::string H2_FRAME_DATA{"DATA"};
static const std::string H2_FRAME_HEADERS{"HEADERS"};
static const std::string H2_FRAME_PRIORITY{"PRIORITY"};
static const std::string H2_FRAME_RST_STREAM{"RST_STREAM"};
static const std::string H2_FRAME_SETTINGS{"SETTINGS"};
static const std::string H2_FRAME_PUSH_PROMISE{"PUSH_PROMISE"};
static const std::string H2_FRAME_PING{"PING"};
static const std::string H2_FRAME_GOAWAY{"GOAWAY"};
static const std::string H2_FRAME_WINDOW_UPDATE{"WINDOW_UPDATE"};
static const std::string H2_FRAME_CONTINUATION{"CONTINUATION"};
static const std::string H2_FRAME_ALTSVC{"ALTSVC"};
static const std::string H2_FRAME_ORIGIN{"ORIGIN"};

static const swoc::Lexicon<H2Frame> H2FrameNames{
    {{H2Frame::DATA, H2_FRAME_DATA},
     {H2Frame::HEADERS, H2_FRAME_HEADERS},
     {H2Frame::PRIORITY, H2_FRAME_PRIORITY},
     {H2Frame::RST_STREAM, H2_FRAME_RST_STREAM},
     {H2Frame::SETTINGS, H2_FRAME_SETTINGS},
     {H2Frame::PUSH_PROMISE, H2_FRAME_PUSH_PROMISE},
     {H2Frame::PING, H2_FRAME_PING},
     {H2Frame::GOAWAY, H2_FRAME_GOAWAY},
     {H2Frame::WINDOW_UPDATE, H2_FRAME_WINDOW_UPDATE},
     {H2Frame::CONTINUATION, H2_FRAME_CONTINUATION},
     {H2Frame::ALTSVC, H2_FRAME_ALTSVC},
     {H2Frame::ORIGIN, H2_FRAME_ORIGIN}},
    "INVALID_FRAME",
    H2Frame::INVALID};

// The status codes for the RST_STREAM and GOAWAY frames.
enum class H2ErrorCode {
  NO_ERROR = 0x00,
  PROTOCOL_ERROR = 0x01,
  INTERNAL_ERROR = 0x02,
  FLOW_CONTROL_ERROR = 0x03,
  SETTINGS_TIMEOUT = 0x04,
  STREAM_CLOSED = 0x05,
  FRAME_SIZE_ERROR = 0x06,
  REFUSED_STREAM = 0x07,
  CANCEL = 0x08,
  COMPRESSION_ERROR = 0x09,
  CONNECT_ERROR = 0x0a,
  ENHANCE_YOUR_CALM = 0x0b,
  INADEQUATE_SECURITY = 0x0c,
  HTTP_1_1_REQUIRED = 0x0d,
  INVALID = -0x01
};

static const std::string H2_ERROR_CODE_NO_ERROR{"NO_ERROR"};
static const std::string H2_ERROR_CODE_PROTOCOL_ERROR{"PROTOCOL_ERROR"};
static const std::string H2_ERROR_CODE_INTERNAL_ERROR{"INTERNAL_ERROR"};
static const std::string H2_ERROR_CODE_FLOW_CONTROL_ERROR{"FLOW_CONTROL_ERROR"};
static const std::string H2_ERROR_CODE_SETTINGS_TIMEOUT{"SETTINGS_TIMEOUT"};
static const std::string H2_ERROR_CODE_STREAM_CLOSED{"STREAM_CLOSED"};
static const std::string H2_ERROR_CODE_FRAME_SIZE_ERROR{"FRAME_SIZE_ERROR"};
static const std::string H2_ERROR_CODE_REFUSED_STREAM{"REFUSED_STREAM"};
static const std::string H2_ERROR_CODE_CANCEL{"CANCEL"};
static const std::string H2_ERROR_CODE_COMPRESSION_ERROR{"COMPRESSION_ERROR"};
static const std::string H2_ERROR_CODE_CONNECT_ERROR{"CONNECT_ERROR"};
static const std::string H2_ERROR_CODE_ENHANCE_YOUR_CALM{"ENHANCE_YOUR_CALM"};
static const std::string H2_ERROR_CODE_INADEQUATE_SECURITY{"INADEQUATE_SECURITY"};
static const std::string H2_ERROR_CODE_HTTP_1_1_REQUIRED{"HTTP_1_1_REQUIRED"};

static const swoc::Lexicon<H2ErrorCode> H2ErrorCodeNames{
    {{H2ErrorCode::NO_ERROR, H2_ERROR_CODE_NO_ERROR},
     {H2ErrorCode::PROTOCOL_ERROR, H2_ERROR_CODE_PROTOCOL_ERROR},
     {H2ErrorCode::INTERNAL_ERROR, H2_ERROR_CODE_INTERNAL_ERROR},
     {H2ErrorCode::FLOW_CONTROL_ERROR, H2_ERROR_CODE_FLOW_CONTROL_ERROR},
     {H2ErrorCode::SETTINGS_TIMEOUT, H2_ERROR_CODE_SETTINGS_TIMEOUT},
     {H2ErrorCode::STREAM_CLOSED, H2_ERROR_CODE_STREAM_CLOSED},
     {H2ErrorCode::FRAME_SIZE_ERROR, H2_ERROR_CODE_FRAME_SIZE_ERROR},
     {H2ErrorCode::REFUSED_STREAM, H2_ERROR_CODE_REFUSED_STREAM},
     {H2ErrorCode::CANCEL, H2_ERROR_CODE_CANCEL},
     {H2ErrorCode::COMPRESSION_ERROR, H2_ERROR_CODE_COMPRESSION_ERROR},
     {H2ErrorCode::CONNECT_ERROR, H2_ERROR_CODE_CONNECT_ERROR},
     {H2ErrorCode::ENHANCE_YOUR_CALM, H2_ERROR_CODE_ENHANCE_YOUR_CALM},
     {H2ErrorCode::INADEQUATE_SECURITY, H2_ERROR_CODE_INADEQUATE_SECURITY},
     {H2ErrorCode::HTTP_1_1_REQUIRED, H2_ERROR_CODE_HTTP_1_1_REQUIRED}},
    "INVALID_ERROR_CODE",
    H2ErrorCode::INVALID};

static constexpr size_t MAX_HDR_SIZE = 131072; // The max ATS is configured for.
static constexpr size_t MAX_DRAIN_BUFFER_SIZE = 1 << 20;
/// HTTP end of line.
static constexpr swoc::TextView HTTP_EOL{"\r\n"};
/// HTTP end of header.
static constexpr swoc::TextView HTTP_EOH{"\r\n\r\n"};

class HttpHeader;
class RuleCheck;
struct Txn;
class ProxyProtocolMsg;

constexpr auto Transaction_Delay_Cutoff = std::chrono::seconds{10};
constexpr auto Poll_Timeout = std::chrono::seconds{5};

namespace swoc
{
inline namespace SWOC_VERSION_NS
{
BufferWriter &bwformat(BufferWriter &w, bwf::Spec const &spec, HttpHeader const &h);

/** Formatter for ProxyProtocolMsg which pretty-prints the proxy protocol in
 * the human-readable v1 format
 * @param[out] w The BufferWriter to write to.
 * @param[in] spec Format specifier for output.
 * @param[in] h The ProxyProtocolMsg to print out.
 * @return w The BufferWriter passed in.
 */
BufferWriter &bwformat(BufferWriter &w, bwf::Spec const &spec, ProxyProtocolMsg const &h);
} // namespace SWOC_VERSION_NS
} // namespace swoc

using memoized_ip_endpoints_t =
    std::unordered_map<std::string_view, std::unordered_map<int, swoc::IPEndpoint>>;

/** Provide the ability to concert an interface name into an IPEndpoint.
 *
 * This provides RAII for the struct ifaddrs allocated via getifaddrs().
 */
class InterfaceNameToEndpoint
{
public:
  /**
   * @param[in] expected_interface The name of the interface to look for.
   * @param[in] expected_family The IP family the interface should belong to.
   */
  InterfaceNameToEndpoint(swoc::TextView expected_interface, int expected_family);

  ~InterfaceNameToEndpoint();

  /** Find the endpoint with constructed expectations.
   */
  swoc::Rv<swoc::IPEndpoint> find_ip_endpoint();

private:
  /** A helper function to loop through the interfaces and find one that
   * matches the specified interface name and family.
   */
  swoc::Rv<struct ifaddrs *> find_matching_interface();

private:
  struct ifaddrs *_ifaddr_list_head = nullptr;
  const std::string _expected_interface;
  const int _expected_family;

  /// Save previously derived IPEndpoints for efficiency.
  static memoized_ip_endpoints_t memoized_ip_endpoints;
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

  /** Convert _fields into nghttp2_nv and add them to the provided vector.
   *
   * This assumes that the pseudo header fields are handled separately.  If
   * such fields are in the _fields container they are not added here to the
   * nghttp2_nv vector.
   *
   * @param[out] l vector of nghttp2_nv structs to populate from _fields.
   */
  void add_fields_to_ngnva(nghttp2_nv *l) const;

  /** Convert _fields into nghttp3_nv and add them to the provided vector.
   *
   * This assumes that the pseudo header fields are handled separately.  If
   * such fields are in the _fields container they are not added here to the
   * nghttp3_nv vector.
   *
   * @param[out] l vector of nghttp3_nv structs to populate from _fields.
   */
  void add_fields_to_ngnva(nghttp3_nv *l) const;

  friend class HttpHeader;
};

/// An enumeration of the various protocol types.
enum class HTTP_PROTOCOL_TYPE {
  HTTP_1,
  HTTP_2,
  HTTP_3,
};

// TODO: rename to HttpMessage?
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

  /// Get the HTTP protocol type of this message.
  HTTP_PROTOCOL_TYPE get_http_protocol() const;

  /// Set the HTTP protocol type for this message.
  void set_http_protocol(HTTP_PROTOCOL_TYPE protocol);

  /// Set that this is an HTTP/1.x message.
  void set_is_http1();

  /// Return whether this is an HTTP/1.x message.
  bool is_http1() const;

  /// Set that this is an HTTP/2 message.
  void set_is_http2();

  /// Return whether this is an HTTP/2 message.
  bool is_http2() const;

  /// Set that this is an HTTP/3 message.
  void set_is_http3();

  /// Return whether this is an HTTP/3 message.
  bool is_http3() const;

  /// Set this to be state for an HTTP request while also specifying the HTTP
  /// protocol.
  void set_is_request(HTTP_PROTOCOL_TYPE protocol);

  /// Set this to be state for an HTTP request.
  void set_is_request();

  /// Return whether this is an HTTP request.
  bool is_request() const;

  /// Set this to be state for an HTTP response while also specifying the HTTP
  /// protocol.
  void set_is_response(HTTP_PROTOCOL_TYPE protocol);

  /// Set this to be state for an HTTP response.
  void set_is_response();

  /// Return whether this is an HTTP response.
  bool is_response() const;

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

  std::shared_ptr<RuleCheck> _content_rule;

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

  std::deque<H2Frame> _h2_frame_sequence;

  // Note that _client_rst_stream_after will only be set for Verifier clients, and
  // _server_rst_stream_after will only be set for verifier servers.
  int _client_rst_stream_after = -1;
  int _client_rst_stream_error = -1;
  int _server_rst_stream_after = -1;
  int _server_rst_stream_error = -1;

  int _client_goaway_after = -1;
  int _client_goaway_error = -1;
  int _server_goaway_after = -1;
  int _server_goaway_error = -1;

  /// Body is chunked.
  bool _chunked_p = false;
  /// Whether there is a "Transfer-Encoding: chunked" HTTP header field in this
  /// message.
  bool _has_transfer_encoding_chunked = false;
  /// No Content-Length - close after sending body.
  bool _content_length_p = false;

  /// The parsed headers contain "Connection: close" header.
  bool _contains_connection_close = false;

  /// Format string to generate a key from a transaction.
  static std::string _key_format;

  static void set_max_content_length(size_t n);

  static void global_init();

  /// Precomputed content buffer.
  static swoc::MemSpan<char> _content;

  bool _verify_strictly;

  /** The keys upon which to await a response before running this transaction.
   *
   * Since HTTP/1 transactions are serialized anyway, this has no impact there.
   * But for HTTP/2 and HTTP/3 transactions, this can be helpful.
   */
  std::vector<std::string> _keys_to_await;

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

  /// The HTTP protocol this message represents.
  HTTP_PROTOCOL_TYPE _http_protocol = HTTP_PROTOCOL_TYPE::HTTP_1;

  /// Whether this is an HTTP request.
  bool _is_request = false;
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
  bool is_h3 = false;
  /// The PROXY protocol message to send in this session. nullptr if no PROXY
  /// protocol message is to be sent.
  std::unique_ptr<ProxyProtocolMsg> _pp_msg;
  swoc::Errata post_process_transactions();
};

/** A session reader.
 * This is essentially a wrapper around a socket to support use of @c poll on
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

  /** Peeks at the socket for PROXY header data. Consume from the session socket
   * and parse it if it detects a valid header.
   */
  virtual swoc::Errata read_and_parse_proxy_hdr();

  /** Send the PROXY header to the target as the connection is established.
   *
   * @param[in] pp_msg The PROXY message to send.
   */
  virtual swoc::Errata send_proxy_msg(ProxyProtocolMsg const &pp_msg);

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
  virtual swoc::Rv<size_t> drain_body(
      HttpHeader const &hdr,
      size_t expected_content_size,
      swoc::TextView bytes_read,
      std::shared_ptr<RuleCheck> rule_check = nullptr);

  /// the pp_msg is passed in as non-const because the source and destination
  /// addresses can be set in the function using the socket addresses if they
  /// are not already(aka addresses not specified in the replay file).
  virtual swoc::Errata do_connect(
      swoc::TextView interface,
      swoc::IPEndpoint const *real_target,
      ProxyProtocolMsg *pp_msg = nullptr);

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
      swoc::TextView interface,
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

  /** Read from the stream's socket into span, without actually consuming it.
   *
   * @param[in] span The destination for the bytes read from the socket.
   *
   * @return The number of bytes read and an errata with any messaging.
   */
  virtual swoc::Rv<ssize_t> peek(swoc::MemSpan<char> span);

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

public:
  /** The content of a zero-sized chunk, which is the final chunk that is sent.
   */
  static constexpr swoc::TextView ZERO_CHUNK{"0\r\n\r\n"};

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
