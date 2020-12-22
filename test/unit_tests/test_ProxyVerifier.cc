/** @file
 * Unit tests for HttpReplay.h.
 *
 * Copyright 2020, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "catch.hpp"
#include "core/ProxyVerifier.h"

TEST_CASE("ALPN string formatting", "[alpn]")
{
  SECTION("empty alpn")
  {
    const unsigned char no_protos[] = {0};
    CHECK(std::string("") == get_printable_alpn_string({(char *)no_protos, sizeof(no_protos)}));
  }
  SECTION("Single protocol")
  {
    const unsigned char one_protos[] = {2, 'h', '2'};
    CHECK(std::string("h2") == get_printable_alpn_string({(char *)one_protos, sizeof(one_protos)}));
  }
  SECTION("Two protocols")
  {
    const unsigned char two_protos[] = {2, 'h', '2', 7, 'h', 't', 't', 'p', '1', '.', '1'};
    CHECK(
        std::string("h2,http1.1") ==
        get_printable_alpn_string({(char *)two_protos, sizeof(two_protos)}));
  }
}

const std::string key = "1";

// Other parts of new code involve Info calls and reliance on these functions,
// so instead are tested by the test cases in the json folder
TEST_CASE("RuleChecks of non-duplicate fields", "[RuleCheck]")
{
  swoc::TextView test_name("testName");
  swoc::TextView expected_value("testValue");
  RuleCheck::options_init();

  swoc::TextView empty_name;
  swoc::TextView empty_value;

  SECTION("presence checks")
  {
    std::shared_ptr<RuleCheck> present_check =
        RuleCheck::make_rule_check(test_name, expected_value, "present");
    REQUIRE(present_check);

    CHECK_FALSE(present_check->test(key, empty_name, empty_value));
    CHECK_FALSE(present_check->test(key, empty_name, expected_value));
    CHECK(present_check->test(key, test_name, empty_value));
    CHECK(present_check->test(key, test_name, expected_value));
    CHECK(present_check->test(key, test_name, "some non-test value"));
  }

  SECTION("absence checks")
  {
    std::shared_ptr<RuleCheck> absent_check =
        RuleCheck::make_rule_check(test_name, expected_value, "absent");
    REQUIRE(absent_check);

    CHECK(absent_check->test(key, empty_name, empty_value));
    CHECK(absent_check->test(key, empty_name, expected_value));
    CHECK_FALSE(absent_check->test(key, test_name, empty_value));
    CHECK_FALSE(absent_check->test(key, test_name, expected_value));
  }

  SECTION("equal checks")
  {
    std::shared_ptr<RuleCheck> equal_check_not_blank =
        RuleCheck::make_rule_check(test_name, expected_value, "equal");
    REQUIRE(equal_check_not_blank);

    CHECK_FALSE(equal_check_not_blank->test(key, empty_name, empty_value));
    CHECK_FALSE(equal_check_not_blank->test(key, empty_name, expected_value));
    CHECK_FALSE(equal_check_not_blank->test(key, test_name, empty_value));
    CHECK(equal_check_not_blank->test(key, test_name, expected_value));
  }

  SECTION("equal checks with a blank value in the rule")
  {
    swoc::TextView non_empty_value = "some_value";
    std::shared_ptr<RuleCheck> equal_check_blank =
        RuleCheck::make_rule_check(test_name, "", "equal");
    REQUIRE(equal_check_blank);

    CHECK_FALSE(equal_check_blank->test(key, empty_name, empty_value));
    CHECK_FALSE(equal_check_blank->test(key, empty_name, non_empty_value));
    CHECK(equal_check_blank->test(key, test_name, empty_value));
    CHECK_FALSE(equal_check_blank->test(key, test_name, non_empty_value));
  }

  SECTION("contains checks")
  {
    swoc::TextView contained_value("Val");
    std::shared_ptr<RuleCheck> contains_check =
        RuleCheck::make_rule_check(test_name, contained_value, "contains");
    REQUIRE(contains_check);

    CHECK_FALSE(contains_check->test(key, empty_name, empty_value));
    CHECK_FALSE(contains_check->test(key, empty_name, expected_value));
    CHECK_FALSE(contains_check->test(key, empty_name, contained_value));
    CHECK_FALSE(contains_check->test(key, test_name, empty_value));
    CHECK(contains_check->test(key, test_name, expected_value));
    CHECK(contains_check->test(key, test_name, contained_value));
  }

  SECTION("prefix checks")
  {
    swoc::TextView prefix_value("test");
    std::shared_ptr<RuleCheck> prefix_check =
        RuleCheck::make_rule_check(test_name, prefix_value, "prefix");
    REQUIRE(prefix_check);

    CHECK_FALSE(prefix_check->test(key, empty_name, empty_value));
    CHECK_FALSE(prefix_check->test(key, empty_name, expected_value));
    CHECK_FALSE(prefix_check->test(key, empty_name, prefix_value));
    CHECK_FALSE(prefix_check->test(key, test_name, empty_value));
    CHECK(prefix_check->test(key, test_name, expected_value));
    CHECK(prefix_check->test(key, test_name, prefix_value));
  }

  SECTION("suffix checks")
  {
    swoc::TextView suffix_value("alue");
    std::shared_ptr<RuleCheck> suffix_check =
        RuleCheck::make_rule_check(test_name, suffix_value, "suffix");
    REQUIRE(suffix_check);

    CHECK_FALSE(suffix_check->test(key, empty_name, empty_value));
    CHECK_FALSE(suffix_check->test(key, empty_name, expected_value));
    CHECK_FALSE(suffix_check->test(key, empty_name, suffix_value));
    CHECK_FALSE(suffix_check->test(key, test_name, empty_value));
    CHECK(suffix_check->test(key, test_name, expected_value));
    CHECK(suffix_check->test(key, test_name, suffix_value));
  }

  // contains/prefix/suffix rule with blank value would be absurd, so skipped
}

TEST_CASE("RuleChecks of duplicate fields", "[RuleCheck]")
{
  swoc::TextView test_name("testName");
  std::list<swoc::TextView> expected_values_arg{
      "first_value",
      "second_value",
  };
  std::list<swoc::TextView> expected_values{
      "first_value",
      "second_value",
  };
  swoc::TextView empty_name;
  std::list<swoc::TextView> empty_values_arg;
  std::list<swoc::TextView> empty_values;

  RuleCheck::options_init();

  SECTION("presence checks")
  {
    std::shared_ptr<RuleCheck> present_check =
        RuleCheck::make_rule_check(test_name, std::move(expected_values_arg), "present");
    REQUIRE(present_check);

    CHECK_FALSE(present_check->test(key, empty_name, empty_values));
    CHECK_FALSE(present_check->test(key, empty_name, expected_values));
    CHECK(present_check->test(key, test_name, empty_values));
    CHECK(present_check->test(key, test_name, expected_values));
    CHECK(present_check->test(key, test_name, {"some", "non-test", "values"}));
  }

  SECTION("absence checks")
  {
    std::shared_ptr<RuleCheck> absent_check =
        RuleCheck::make_rule_check(test_name, std::move(expected_values_arg), "absent");
    REQUIRE(absent_check);

    CHECK(absent_check->test(key, empty_name, empty_values));
    CHECK(absent_check->test(key, empty_name, expected_values));
    CHECK_FALSE(absent_check->test(key, test_name, empty_values));
    CHECK_FALSE(absent_check->test(key, test_name, expected_values));
  }

  SECTION("equal checks")
  {
    std::shared_ptr<RuleCheck> equal_check_not_blank =
        RuleCheck::make_rule_check(test_name, std::move(expected_values_arg), "equal");
    REQUIRE(equal_check_not_blank);

    CHECK_FALSE(equal_check_not_blank->test(key, empty_name, empty_values));
    CHECK_FALSE(equal_check_not_blank->test(key, empty_name, expected_values));
    CHECK_FALSE(equal_check_not_blank->test(key, test_name, empty_values));
    CHECK(equal_check_not_blank->test(key, test_name, expected_values));

    // Subsets of the expected values are not enough.
    std::list<swoc::TextView> subset_values{
        "first_value",
    };
    CHECK_FALSE(equal_check_not_blank->test(key, test_name, subset_values));

    // Order matters.
    std::list<swoc::TextView> re_arranged_values{
        "second_value",
        "first_value",
    };
    CHECK_FALSE(equal_check_not_blank->test(key, test_name, re_arranged_values));
  }

  SECTION("equal checks with no values in the rule")
  {
    std::shared_ptr<RuleCheck> equal_check_blank =
        RuleCheck::make_rule_check(test_name, std::move(empty_values_arg), "equal");
    REQUIRE(equal_check_blank);

    swoc::TextView non_empty_values = {"some", "values"};
    CHECK_FALSE(equal_check_blank->test(key, empty_name, empty_values));
    CHECK_FALSE(equal_check_blank->test(key, empty_name, non_empty_values));
    CHECK(equal_check_blank->test(key, test_name, empty_values));
    CHECK_FALSE(equal_check_blank->test(key, test_name, non_empty_values));
  }
}

struct ParseUrlTestCase
{
  std::string const description;
  std::string const url_input;

  std::string const expected_scheme;
  std::string const expected_authority;
  std::string const expected_path;

  std::string const expected_uri_scheme;
  std::string const expected_uri_host;
  std::string const expected_uri_port;
  std::string const expected_uri_authority;
  std::string const expected_uri_path;
  std::string const expected_uri_query;
  std::string const expected_uri_fragment;
};

std::initializer_list<ParseUrlTestCase> parse_url_test_cases = {
    {
        .description = "Verify an empty URL can be parsed.",
        .url_input = "",

        .expected_scheme = "",
        .expected_authority = "",
        .expected_path = "",

        .expected_uri_scheme = "",
        .expected_uri_host = "",
        .expected_uri_port = "",
        .expected_uri_authority = "",
        .expected_uri_path = "",
        .expected_uri_query = "",
        .expected_uri_fragment = "",
    },
    {
        .description = "Verify scheme only is parsed correctly.",
        .url_input = "http://",

        .expected_scheme = "http",
        .expected_authority = "",
        .expected_path = "",

        .expected_uri_scheme = "http",
        .expected_uri_host = "",
        .expected_uri_port = "",
        .expected_uri_authority = "",
        .expected_uri_path = "",
        .expected_uri_query = "",
        .expected_uri_fragment = "",
    },
    {
        .description = "Verify a scheme and authority is parsed correctly.",
        .url_input = "https://www.example.com",

        .expected_scheme = "https",
        .expected_authority = "www.example.com",
        .expected_path = "",

        .expected_uri_scheme = "https",
        .expected_uri_host = "www.example.com",
        .expected_uri_port = "",
        .expected_uri_authority = "www.example.com",
        .expected_uri_path = "",
        .expected_uri_query = "",
        .expected_uri_fragment = "",
    },
    {
        .description = "Verify a scheme and authority with port is parsed correctly.",
        .url_input = "https://www.example.com:443",

        .expected_scheme = "https",
        .expected_authority = "www.example.com:443",
        .expected_path = "",

        .expected_uri_scheme = "https",
        .expected_uri_host = "www.example.com",
        .expected_uri_port = "443",
        .expected_uri_authority = "www.example.com:443",
        .expected_uri_path = "",
        .expected_uri_query = "",
        .expected_uri_fragment = "",
    },
    {
        .description = "Verify correct parsing of authority-only targets.",
        .url_input = "www.example.com:443",

        .expected_scheme = "",
        .expected_authority = "www.example.com:443",
        .expected_path = "",

        .expected_uri_scheme = "",
        .expected_uri_host = "www.example.com",
        .expected_uri_port = "443",
        .expected_uri_authority = "www.example.com:443",
        .expected_uri_path = "",
        .expected_uri_query = "",
        .expected_uri_fragment = "",
    },
    {
        .description = "Verify a path can be parsed.",
        .url_input = "/a/path.yaml",

        .expected_scheme = "",
        .expected_authority = "",
        .expected_path = "/a/path.yaml",

        .expected_uri_scheme = "",
        .expected_uri_host = "",
        .expected_uri_port = "",
        .expected_uri_authority = "",
        .expected_uri_path = "/a/path.yaml",
        .expected_uri_query = "",
        .expected_uri_fragment = "",
    },
    {
        .description = "Verify a path with a fragment can be parsed.",
        .url_input = "/a/path.json#Fraggle",

        .expected_scheme = "",
        .expected_authority = "",
        .expected_path = "/a/path.json#Fraggle",

        .expected_uri_scheme = "",
        .expected_uri_host = "",
        .expected_uri_port = "",
        .expected_uri_authority = "",
        .expected_uri_path = "/a/path.json",
        .expected_uri_query = "",
        .expected_uri_fragment = "Fraggle",
    },
    {
        .description = "Verify a path with a query and fragment can be parsed.",
        .url_input = "/a/path?q=q#F",

        .expected_scheme = "",
        .expected_authority = "",
        .expected_path = "/a/path?q=q#F",

        .expected_uri_scheme = "",
        .expected_uri_host = "",
        .expected_uri_port = "",
        .expected_uri_authority = "",
        .expected_uri_path = "/a/path",
        .expected_uri_query = "q=q",
        .expected_uri_fragment = "F",
    },
    {
        .description = "Verify parsing of a URI containing all the URI parts.",
        .url_input = "https://example-ab.candy.com/xy?zab=123456789:98765432#candy?cane",

        .expected_scheme = "https",
        .expected_authority = "example-ab.candy.com",
        .expected_path = "/xy?zab=123456789:98765432#candy?cane",

        .expected_uri_scheme = "https",
        .expected_uri_host = "example-ab.candy.com",
        .expected_uri_port = "",
        .expected_uri_authority = "example-ab.candy.com",
        .expected_uri_path = "/xy",
        .expected_uri_query = "zab=123456789:98765432",
        .expected_uri_fragment = "candy?cane",
    },
    {
        .description = "Verify parsing of a path with a colon.",
        .url_input = "https://example-ab.candy.com/xy/path:.yaml?zab=123456789:98765432#candy?cane",

        .expected_scheme = "https",
        .expected_authority = "example-ab.candy.com",
        .expected_path = "/xy/path:.yaml?zab=123456789:98765432#candy?cane",

        .expected_uri_scheme = "https",
        .expected_uri_host = "example-ab.candy.com",
        .expected_uri_port = "",
        .expected_uri_authority = "example-ab.candy.com",
        .expected_uri_path = "/xy/path:.yaml",
        .expected_uri_query = "zab=123456789:98765432",
        .expected_uri_fragment = "candy?cane",
    },
    {
        .description = "Verify URL parsing with a port.",
        .url_input = "http://example-ab.candy.com:8080/xy/yx?zab=123456789:98765432#Frag",

        .expected_scheme = "http",
        .expected_authority = "example-ab.candy.com:8080",
        .expected_path = "/xy/yx?zab=123456789:98765432#Frag",

        .expected_uri_scheme = "http",
        .expected_uri_host = "example-ab.candy.com",
        .expected_uri_port = "8080",
        .expected_uri_authority = "example-ab.candy.com:8080",
        .expected_uri_path = "/xy/yx",
        .expected_uri_query = "zab=123456789:98765432",
        .expected_uri_fragment = "Frag",
    },
    {
        .description = "Verify an empty path can be parsed.",
        .url_input = "http://example-ab.candy.com:8080?zab=123456789:98765432#Frag",

        .expected_scheme = "http",
        .expected_authority = "example-ab.candy.com:8080",
        .expected_path = "?zab=123456789:98765432#Frag",

        .expected_uri_scheme = "http",
        .expected_uri_host = "example-ab.candy.com",
        .expected_uri_port = "8080",
        .expected_uri_authority = "example-ab.candy.com:8080",
        .expected_uri_path = "",
        .expected_uri_query = "zab=123456789:98765432",
        .expected_uri_fragment = "Frag",
    },
    {
        .description = "Verify an empty path and just a fragment can be parsed.",
        .url_input = "http://example-ab.candy.com:8080#Frag",

        .expected_scheme = "http",
        .expected_authority = "example-ab.candy.com:8080",
        .expected_path = "#Frag",

        .expected_uri_scheme = "http",
        .expected_uri_host = "example-ab.candy.com",
        .expected_uri_port = "8080",
        .expected_uri_authority = "example-ab.candy.com:8080",
        .expected_uri_path = "",
        .expected_uri_query = "",
        .expected_uri_fragment = "Frag",
    },
};

TEST_CASE("Test path parsing", "[ParseUrl]")
{
  auto const &test_case = GENERATE(values(parse_url_test_cases));
  HttpHeader header;
  header.parse_url(test_case.url_input);

  CHECK(header._scheme == test_case.expected_scheme);
  CHECK(header._path == test_case.expected_path);
  CHECK(header._authority == test_case.expected_authority);

  CHECK(header.uri_scheme == test_case.expected_uri_scheme);
  CHECK(header.uri_host == test_case.expected_uri_host);
  CHECK(header.uri_port == test_case.expected_uri_port);
  CHECK(header.uri_authority == test_case.expected_uri_authority);
  CHECK(header.uri_path == test_case.expected_uri_path);
  CHECK(header.uri_query == test_case.expected_uri_query);
  CHECK(header.uri_fragment == test_case.expected_uri_fragment);
}
