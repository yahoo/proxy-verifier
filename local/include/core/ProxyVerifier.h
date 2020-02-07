/** @file
 * Common data structures and definitions for Proxy Verifier tools.
 *
 * Copyright 2020, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <string>
#include <unordered_set>

#include <condition_variable>
#include <deque>
#include <memory>
#include <nghttp2/nghttp2.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <thread>
#include <unistd.h>

#include "yaml-cpp/yaml.h"

#include "swoc/BufferWriter.h"
#include "swoc/Errata.h"
#include "swoc/MemArena.h"
#include "swoc/TextView.h"
#include "swoc/bwf_base.h"
#include "swoc/ext/HashFNV.h"
#include "swoc/swoc_file.h"
#include "swoc/swoc_ip.h"

// Definitions of keys in the CONFIG files.
// These need to be @c std::string or the node look up will construct a @c
// std::string.
static const std::string YAML_META_KEY{"meta"};
static const std::string YAML_GLOBALS_KEY{"global-field-rules"};
static const std::string YAML_SSN_KEY{"sessions"};
static const std::string YAML_SSN_PROTOCOL_KEY{"protocol"};
static const std::string YAML_SSN_START_KEY{"connection-time"};
static const std::string YAML_SSN_TLS_KEY{"tls"};
static const std::string YAML_SSN_TLS_CLIENT_SNI_KEY{"client-sni"};
static const std::string YAML_SSN_TLS_PROXY_SNI_KEY{"proxy-sni"};
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
static const std::string YAML_HTTP_URL_KEY{"url"};
static const std::string YAML_CONTENT_KEY{"content"};
static const std::string YAML_CONTENT_LENGTH_KEY{"size"};
static const std::string YAML_CONTENT_DATA_KEY{"data"};
static const std::string YAML_CONTENT_ENCODING_KEY{"encoding"};
static const std::string YAML_CONTENT_TRANSFER_KEY{"transfer"};

static constexpr size_t YAML_RULE_NAME_KEY{0};
static constexpr size_t YAML_RULE_DATA_KEY{1};
static constexpr size_t YAML_RULE_TYPE_KEY{2};

static const std::string YAML_RULE_EQUALS{"equal"};
static const std::string YAML_RULE_PRESENCE{"present"};
static const std::string YAML_RULE_ABSENCE{"absent"};

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

namespace swoc {
BufferWriter &bwformat(BufferWriter &w, bwf::Spec const &spec,
                       HttpHeader const &h);

namespace bwf {
/** Format wrapper for @c errno.
 * This stores a copy of the argument or @c errno if an argument isn't provided.
 * The output is then formatted with the short, long, and numeric value of @c
 * errno. If the format specifier is type 'd' then just the numeric value is
 * printed.
 */
struct SSLError {
  unsigned long _e;
  explicit SSLError(int e = ERR_peek_last_error()) : _e(e) {}
};
} // namespace bwf

BufferWriter &bwformat(BufferWriter &w, bwf::Spec const &spec,
                       bwf::SSLError const &error);
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
struct Hash {
  swoc::Hash64FNV1a::value_type operator()(swoc::TextView view) const {
    return swoc::Hash64FNV1a{}.hash_immediate(
        swoc::transform_view_of(&tolower, view));
  }
  bool operator()(swoc::TextView const &lhs, swoc::TextView const &rhs) const {
    return 0 == strcasecmp(lhs, rhs);
  }
};

class RuleCheck {
  /// References the make_* functions below.
  using RuleFunction =
      std::function<std::shared_ptr<RuleCheck>(swoc::TextView, swoc::TextView)>;
  using RuleOptions =
      std::unordered_map<swoc::TextView, RuleFunction, Hash, Hash>;

  static RuleOptions
      options; ///< Returns function to construct a RuleCheck child class for a
               ///< given rule type ("equals", "presence", or "absence")

protected:
  swoc::TextView
      _name; ///< All rules have a name of the field that needs to be checked

public:
  virtual ~RuleCheck() {}

  /** Initialize options with std::functions for creating RuleChecks.
   *
   */
  static void options_init();

  /** Generate @a RuleCheck with @a node with factory pattern.
   *
   * @param name TextView holding the name of the field. This should be
   * localized.
   * @param value TextView holding the value of the field. This should be
   * localized.
   * @param rule_type TextView holding the verification rule value from the
   * node. This need not be localized.
   * @return A pointer to the RuleCheck instance generated, holding a key (and
   * potentially value) TextView for the rule to compare inputs to
   */
  static std::shared_ptr<RuleCheck> find(swoc::TextView localized_name,
                                         swoc::TextView localized_value,
                                         swoc::TextView rule_type);

  /** Generate @a EqualityCheck, invoked by the factory function when the
   * "equals" flag is present.
   *
   * @param node TextView holding the name of the target field
   * @param name TextView holding the associated value with the target field,
   * that is used with strcasecmp comparisons
   * @return A pointer to the EqualityCheck instance generated, holding key and
   * value TextViews for the rule to compare inputs to
   */
  static std::shared_ptr<RuleCheck> make_equality(swoc::TextView name,
                                                  swoc::TextView value);

  /** Generate @a PresenceCheck, invoked by the factory function when the
   * "absence" flag is present.
   *
   * @param name TextView holding the name of the target field
   * @param value TextView (unused) in order to have the same signature as
   * make_equality
   * @return A pointer to the Presence instance generated, holding a name
   * TextView for the rule to compare inputs to
   */
  static std::shared_ptr<RuleCheck> make_presence(swoc::TextView name,
                                                  swoc::TextView value);

  /** Generate @a AbsenceCheck, invoked by the factory function when the
   * "absence" flag is present.
   *
   * @param name TextView holding the name of the target field
   * @param value TextView (unused) in order to have the same signature as
   * make_equality
   * @return A pointer to the AbsenceCheck instance generated, holding a name
   * TextView for the rule to compare inputs to
   */
  static std::shared_ptr<RuleCheck> make_absence(swoc::TextView name,
                                                 swoc::TextView value);

  /** Pure virtual function to test whether the input name and value fulfill the
   * rules for the test
   *
   * @param key TextView The identifying transaction key.
   * @param name TextView holding the name of the target field (null if not
   * found)
   * @param value TextView holding the value of the target field (null if not
   * found)
   * @return Whether the check was successful or not
   */
  virtual bool test(swoc::TextView key, swoc::TextView name,
                    swoc::TextView value) const = 0;
};

class EqualityCheck : public RuleCheck {
  swoc::TextView _value; ///< Only EqualityChecks require value comparisons.

public:
  ~EqualityCheck() {}

  /** Construct @a EqualityCheck with a given name and value.
   *
   * @param name TextView holding the name of the target field
   * @param value TextView holding the associated value with the target field,
   * that is used with strcasecmp comparisons
   */
  EqualityCheck(swoc::TextView name, swoc::TextView value);

  /** Test whether the name and value both match the expected name and value
   * per the values instantiated in construction.
   *
   * Reports errors in verbose mode.
   *
   * @param key TextView The identifying transaction key.
   * @param name TextView holding the name of the target field (null if not
   * found)
   * @param value TextView holding the value of the target field (null if not
   * found)
   * @return Whether the check was successful or not
   */
  bool test(swoc::TextView key, swoc::TextView name,
            swoc::TextView value) const override;
};

class PresenceCheck : public RuleCheck {
public:
  /** Construct @a PresenceCheck with a given name.
   *
   * @param name TextView holding the name of the target field
   */
  PresenceCheck(swoc::TextView name);

  /** Test whether the name matches the expected name. Reports errors in verbose
   * mode.
   *
   * @param key TextView The identifying transaction key.
   * @param name TextView holding the name of the target field (null if not
   * found)
   * @param value TextView (unused) holding the value of the target field (null
   * if not found)
   * @return Whether the check was successful or not
   */
  bool test(swoc::TextView key, swoc::TextView name,
            swoc::TextView value) const override;
};

class AbsenceCheck : public RuleCheck {
public:
  /** Construct @a AbsenceCheck with a given name.
   *
   * @param name TextView holding the name of the target field
   */
  AbsenceCheck(swoc::TextView name);

  /** Test whether the name is null (does not match the expected name). Reports
   * errors in verbose mode.
   *
   * @param key TextView The identifying transaction key.
   * @param name TextView holding the name of the target field (null if not
   * found)
   * @param value TextView (unused) holding the value of the target field (null
   * if not found)
   * @return Whether the check was successful or not
   */
  bool test(swoc::TextView key, swoc::TextView name,
            swoc::TextView value) const override;
};

class HttpFields {
  using self_type = HttpFields;
  /// std::unordered_map that returns RuleChecks for given field names
  using Rules = std::unordered_map<swoc::TextView, std::shared_ptr<RuleCheck>,
                                   Hash, Hash>;
  using Fields =
      std::unordered_multimap<swoc::TextView, std::string, Hash, Hash>;

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
  swoc::Errata parse_fields_and_rules(YAML::Node const &node,
                                      bool assume_equality_rule);
  static constexpr bool ASSUME_EQUALITY_RULE = true;

  /** Convert _fields into nghttp2_nv and add them to the vector provided
   *
   * @param[out] l vector of nghttp2_nv structs to populate from _fields.
   */
  void add_fields_to_ngnva(nghttp2_nv *l) const;

  friend class HttpHeader;
};

struct VerificationConfig {
  std::shared_ptr<HttpFields> txn_rules;
};

class HttpHeader {
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

  /** Iterate over the rules and check that the fields are in line using the
   * stored RuleChecks, and report any errors.
   *
   * @param rules_ HeaderRules to iterate over, contains RuleCheck objects
   * @return Whether any rules were violated
   */
  bool verify_headers(swoc::TextView key, const HttpFields &rules_) const;

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
  unsigned _chunked_p : 1;
  /// No Content-Length - close after sending body.
  unsigned _content_length_p : 1;

  /// Format string to generate a key from a transaction.
  static TextView _key_format;

  /// String localization frozen?
  static bool _frozen;

  static void set_max_content_length(size_t n);

  static void global_init();

  /// Precomputed content buffer.
  static swoc::MemSpan<char> _content;

protected:
  class Binding : public swoc::bwf::NameBinding {
    using BufferWriter = swoc::BufferWriter;

  public:
    Binding(HttpHeader const &hdr) : _hdr(hdr) {}
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
    BufferWriter &operator()(BufferWriter &w,
                             const swoc::bwf::Spec &spec) const override;

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

struct Txn {
  Txn(bool verify_strictly) : _req{verify_strictly}, _rsp{verify_strictly} {}

  HttpHeader _req; ///< Request to send.
  HttpHeader _rsp; ///< Rules for response to expect.
};

struct Ssn {
  std::list<Txn> _transactions;
  swoc::file::path _path;
  unsigned _line_no = 0;
  uint64_t _start; ///< Start time in HR ticks.
  swoc::TextView _client_sni;
  bool is_tls = false;
  bool is_h2 = false;
};

/** A session reader.
 * This is essentially a wrapper around a socket to support use of @c epoll on
 * the socket. The goal is to enable a read operation that waits for data but
 * returns as soon as any data is available.
 */
class Session {
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
  virtual swoc::Errata accept() { return swoc::Errata{}; }

  /** Initiate the security layer handshakes.
   *
   * Sub classes can override this to implement a presentation layer handshake.
   *
   * @return Any relevant messaging.
   */
  virtual swoc::Errata connect();

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
   * @param[in] initial The body already read from the socket.
   *
   * @return The number of bytes drained and an errata with messaging.
   */
  virtual swoc::Rv<size_t> drain_body(HttpHeader const &hdr,
                                      swoc::TextView initial);

  virtual swoc::Errata do_connect(const swoc::IPEndpoint *real_target);

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

  static swoc::Errata init();

  virtual swoc::Errata run_transactions(const std::list<Txn> &txn,
                                        const swoc::IPEndpoint *real_target);
  virtual swoc::Errata run_transaction(const Txn &txn);

private:
  int _fd = -1; ///< Socket.
};

inline int Session::get_fd() const { return _fd; }
inline bool Session::is_closed() const { return _fd < 0; }

class TLSSession : public Session {
public:
  using super_type = Session;

  /** @see Session::read */
  swoc::Rv<ssize_t> read(swoc::MemSpan<char> span) override;
  /** @see Session::write */
  swoc::Rv<ssize_t> write(swoc::TextView data) override;
  TLSSession() = default;
  TLSSession(swoc::TextView const &client_sni) : _client_sni(client_sni) {}
  ~TLSSession() override {
    if (_ssl)
      SSL_free(_ssl);
  }

  /** @see Session::close */
  void close() override;
  /** @see Session::accept */
  swoc::Errata accept() override;
  /** @see Session::connect */
  swoc::Errata connect() override;
  swoc::Errata connect(SSL_CTX *ctx);
  static swoc::Errata init(SSL_CTX *&srv_ctx, SSL_CTX *&clt_ctx);
  static swoc::Errata init() {
    return TLSSession::init(server_ctx, client_ctx);
  }
  static swoc::file::path certificate_file;
  static swoc::file::path privatekey_file;

  SSL *get_ssl() { return _ssl; }

protected:
  SSL *_ssl = nullptr;
  swoc::TextView _client_sni;
  static SSL_CTX *server_ctx;
  static SSL_CTX *client_ctx;
};

class H2StreamState {
public:
  H2StreamState() {}
  H2StreamState(int32_t stream_id) : _stream_id(stream_id) {}
  H2StreamState(int32_t stream_id, char *send_body, int send_body_length)
      : _stream_id(stream_id), _send_body(send_body),
        _send_body_length(send_body_length) {}
  int32_t _stream_id = 0;
  int _data_to_recv = 0;
  size_t _send_body_offset = 0;
  const char *_send_body = nullptr;
  size_t _send_body_length = 0;
  const HttpHeader *_req = nullptr;
  const HttpHeader *_resp = nullptr;
  bool _wait_for_continue = false;
};

class H2Session : public TLSSession {
public:
  using super_type = TLSSession;
  H2Session();
  swoc::Rv<ssize_t> read(swoc::MemSpan<char> span) override;
  swoc::Rv<ssize_t> write(swoc::TextView data) override;
  virtual swoc::Rv<ssize_t> write(HttpHeader const &hdr);
  ~H2Session() override = default;

  swoc::Errata connect() override;
  static swoc::Errata init(SSL_CTX *&srv_ctx, SSL_CTX *&clt_ctx);
  static swoc::Errata init() {
    return H2Session::init(h2_server_ctx, h2_client_ctx);
  }
  swoc::Errata session_init();
  swoc::Errata send_client_connection_header();
  swoc::Errata run_transactions(const std::list<Txn> &txn,
                                const swoc::IPEndpoint *real_target) override;
  swoc::Errata run_transaction(const Txn &txn) override;

  nghttp2_session *get_session() { return _session; }

  std::map<int32_t, H2StreamState *> _stream_map;

protected:
  nghttp2_session *_session;
  nghttp2_session_callbacks *callbacks;

  static SSL_CTX *h2_server_ctx;
  static SSL_CTX *h2_client_ctx;

private:
  swoc::Errata pack_headers(HttpHeader const &hdr, nghttp2_nv *&nv_hdr,
                            int &hdr_count);
  nghttp2_nv tv_to_nv(const char *name, swoc::TextView v);
};

class ChunkCodex {
public:
  /// The callback when a chunk is decoded.
  /// @param chunk Data for the chunk in the provided view.
  /// @param offset The offset from the full chunk for @a chunk.
  /// @param size The size of the full chunk.
  /// Because the data provided might not contain the entire chunk, a chunk can
  /// come back piecemeal in the callbacks. The @a offset and @a size specify
  /// where in the actual chunk the particular piece in @a chunk is placed.
  using ChunkCallback =
      std::function<bool(swoc::TextView chunk, size_t offset, size_t size)>;
  enum Result { CONTINUE, DONE, ERROR };

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
  size_t _off =
      0; ///< Number of bytes in the current chunk already sent to the callback.
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
namespace swoc {
inline BufferWriter &bwformat(BufferWriter &w, bwf::Spec const &spec,
                              YAML::Mark const &mark) {
  return w.print("line {}", mark.line);
}
} // namespace swoc

/** Protocol class for loading a replay file.
 * The client and server are expected subclass this an provide an
 * implementation.
 */
class ReplayFileHandler {
public:
  ReplayFileHandler() = default;
  virtual ~ReplayFileHandler() = default;

  /** The rules associated with YAML_GLOBALS_KEY. */
  VerificationConfig global_config;

  virtual swoc::Errata file_open(swoc::file::path const &path) {
    _path = path.string();
    return {};
  }
  virtual swoc::Errata file_close() { return {}; }
  virtual swoc::Errata ssn_open(YAML::Node const &node) { return {}; }
  virtual swoc::Errata ssn_close() { return {}; }

  /** Open the transaction node.
   *
   * @param node Transaction node.
   * @return Errors, if any.
   *
   * This is required to do any base validation of the transaction such as
   * verifying required keys.
   */
  virtual swoc::Errata txn_open(YAML::Node const &node) { return {}; }

  virtual swoc::Errata txn_close() { return {}; }
  virtual swoc::Errata client_request(YAML::Node const &node) { return {}; }
  virtual swoc::Errata proxy_request(YAML::Node const &node) { return {}; }
  virtual swoc::Errata server_response(YAML::Node const &node) { return {}; }
  virtual swoc::Errata proxy_response(YAML::Node const &node) { return {}; }
  virtual swoc::Errata apply_to_all_messages(HttpFields const &all_headers) {
    return {};
  }

protected:
  /** The replay file associated with this handler.
   */
  swoc::file::path _path;
};

swoc::Errata Load_Replay_File(swoc::file::path const &path,
                              ReplayFileHandler &handler);

swoc::Errata
Load_Replay_Directory(swoc::file::path const &path,
                      swoc::Errata (*loader)(swoc::file::path const &),
                      int n_threads = 10);

swoc::Errata parse_ips(std::string arg, std::deque<swoc::IPEndpoint> &target);
swoc::Errata resolve_ips(std::string arg, std::deque<swoc::IPEndpoint> &target);
swoc::Rv<swoc::IPEndpoint> Resolve_FQDN(swoc::TextView host);

namespace swoc {
inline BufferWriter &bwformat(BufferWriter &w, bwf::Spec const &spec,
                              swoc::file::path const &path) {
  return bwformat(w, spec, path.string());
}
} // namespace swoc

class ThreadInfo {
public:
  std::thread *_thread = nullptr;
  std::condition_variable _cvar;
  std::mutex _mutex;
  virtual bool data_ready() = 0;
};

// This must be a list so that iterators / pointers to elements do not go stale.
class ThreadPool {
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
  const int max_threads = 2000;
};
