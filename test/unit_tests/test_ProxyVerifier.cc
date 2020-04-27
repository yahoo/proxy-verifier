/** @file
 * Unit tests for HttpReplay.h.
 *
 * Copyright 2020, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "catch.hpp"
#include "core/ProxyVerifier.h"

const std::string key = "1";

// Other parts of new code involve Info calls and reliance on these functions,
// so instead are tested by the test cases in the json folder
TEST_CASE("RuleChecks of non-duplicate fields", "[RuleCheck]") {
  swoc::TextView test_name("testName");
  swoc::TextView expected_value("testValue");
  RuleCheck::options_init();

  swoc::TextView empty_name;
  swoc::TextView empty_value;

  SECTION("presence checks") {
    std::shared_ptr<RuleCheck> present_check =
        RuleCheck::make_rule_check(test_name, expected_value, "present");
    REQUIRE(present_check);

    CHECK_FALSE(present_check->test(key, empty_name, empty_value));
    CHECK_FALSE(present_check->test(key, empty_name, expected_value));
    CHECK(present_check->test(key, test_name, empty_value));
    CHECK(present_check->test(key, test_name, expected_value));
    CHECK(present_check->test(key, test_name, "some non-test value"));
  }

  SECTION("absence checks") {
    std::shared_ptr<RuleCheck> absent_check =
        RuleCheck::make_rule_check(test_name, expected_value, "absent");
    REQUIRE(absent_check);

    CHECK(absent_check->test(key, empty_name, empty_value));
    CHECK(absent_check->test(key, empty_name, expected_value));
    CHECK_FALSE(absent_check->test(key, test_name, empty_value));
    CHECK_FALSE(absent_check->test(key, test_name, expected_value));
  }

  SECTION("equal checks") {
    std::shared_ptr<RuleCheck> equal_check_not_blank =
        RuleCheck::make_rule_check(test_name, expected_value, "equal");
    REQUIRE(equal_check_not_blank);

    CHECK_FALSE(equal_check_not_blank->test(key, empty_name, empty_value));
    CHECK_FALSE(equal_check_not_blank->test(key, empty_name, expected_value));
    CHECK_FALSE(equal_check_not_blank->test(key, test_name, empty_value));
    CHECK(equal_check_not_blank->test(key, test_name, expected_value));
  }

  SECTION("equal checks with a blank value in the rule") {
    swoc::TextView non_empty_value = "some_value";
    std::shared_ptr<RuleCheck> equal_check_blank =
        RuleCheck::make_rule_check(test_name, "", "equal");
    REQUIRE(equal_check_blank);

    CHECK_FALSE(equal_check_blank->test(key, empty_name, empty_value));
    CHECK_FALSE(equal_check_blank->test(key, empty_name, non_empty_value));
    CHECK(equal_check_blank->test(key, test_name, empty_value));
    CHECK_FALSE(equal_check_blank->test(key, test_name, non_empty_value));
  }
}

TEST_CASE("RuleChecks of duplicate fields", "[RuleCheck]") {
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

  SECTION("presence checks") {
    std::shared_ptr<RuleCheck> present_check =
        RuleCheck::make_rule_check(test_name, std::move(expected_values_arg), "present");
    REQUIRE(present_check);

    CHECK_FALSE(present_check->test(key, empty_name, empty_values));
    CHECK_FALSE(present_check->test(key, empty_name, expected_values));
    CHECK(present_check->test(key, test_name, empty_values));
    CHECK(present_check->test(key, test_name, expected_values));
    CHECK(present_check->test(key, test_name, {"some", "non-test",  "values"}));
  }

  SECTION("absence checks") {
    std::shared_ptr<RuleCheck> absent_check =
        RuleCheck::make_rule_check(test_name, std::move(expected_values_arg), "absent");
    REQUIRE(absent_check);

    CHECK(absent_check->test(key, empty_name, empty_values));
    CHECK(absent_check->test(key, empty_name, expected_values));
    CHECK_FALSE(absent_check->test(key, test_name, empty_values));
    CHECK_FALSE(absent_check->test(key, test_name, expected_values));
  }

  SECTION("equal checks") {
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

  SECTION("equal checks with no values in the rule") {
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

TEST_CASE("Test path parsing", "[ParseUrl]") {
  HttpHeader header;
  SECTION("Verify a simple path can be parsed") {
    std::string url = "/a/path";
    header.parse_url(url);
    CHECK(header._scheme == "");
    CHECK(header._path == "/a/path");
    CHECK(header._authority == "");
  }
  SECTION("Verify URL parsing") {
    std::string url = "https://example-ab.candy.com/xy?zab=123456789:98765432";
    header.parse_url(url);
    CHECK(header._scheme == "https");
    CHECK(header._path == "/xy?zab=123456789:98765432");
    CHECK(header._authority == "example-ab.candy.com");
  }
  SECTION("Verify URL parsing with a port") {
    std::string url = "http://example-ab.candy.com:8080/xy?zab=123456789:98765432";
    header.parse_url(url);
    CHECK(header._scheme == "http");
    CHECK(header._path == "/xy?zab=123456789:98765432");
    CHECK(header._authority == "example-ab.candy.com");
  }
}
