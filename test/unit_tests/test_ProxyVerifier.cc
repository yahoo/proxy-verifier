/** @file
 * Unit tests for HttpReplay.h.
 *
 * Copyright 2020, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "catch.hpp"
#include "core/ProxyVerifier.h"

// Other parts of new code involve Info calls and reliance on these functions,
// so instead are tested by the test cases in the json folder
TEST_CASE("RuleCheck and Child Classes", "[RCaCC]") {
  swoc::TextView test_name("testName");
  swoc::TextView test_value("testValue");
  RuleCheck::options_init();

  // empty names are not defined, so not tested
  // data field in present and absent is supported but not noted
  YAML::Node yaml_present = YAML::Load("[\"test\", \"e\", \"present\"]");
  YAML::Node yaml_absent = YAML::Load("[\"test\", null, \"absent\"]");
  YAML::Node yaml_equals_not_blank =
      YAML::Load("[\"test\", \"test\", \"equals\"]");
  YAML::Node yaml_equals_blank = YAML::Load("[\"test\", \"\", \"equals\"]");

  std::shared_ptr<RuleCheck> present_check =
      RuleCheck::find(test_name, test_value, "present");
  std::shared_ptr<RuleCheck> absent_check =
      RuleCheck::find(test_name, test_value, "absent");
  std::shared_ptr<RuleCheck> equal_check_not_blank =
      RuleCheck::find(test_name, test_value, "equal");
  std::shared_ptr<RuleCheck> equal_check_blank =
      RuleCheck::find(test_name, "", "equal");

  REQUIRE(present_check);
  REQUIRE(absent_check);
  REQUIRE(equal_check_not_blank);
  REQUIRE(equal_check_blank);

  swoc::TextView key = "1";
  swoc::TextView empty_name;
  swoc::TextView empty_value;

  CHECK_FALSE(present_check->test(key, empty_name, empty_value));
  CHECK_FALSE(present_check->test(key, empty_name, test_value));
  CHECK(present_check->test(key, test_name, empty_value));
  CHECK(present_check->test(key, test_name, test_value));
  CHECK(present_check->test(key, test_name, "some non-test value"));

  CHECK(absent_check->test(key, empty_name, empty_value));
  CHECK(absent_check->test(key, empty_name, test_value));
  CHECK_FALSE(absent_check->test(key, test_name, empty_value));
  CHECK_FALSE(absent_check->test(key, test_name, test_value));

  CHECK_FALSE(equal_check_not_blank->test(key, empty_name, empty_value));
  CHECK_FALSE(equal_check_not_blank->test(key, empty_name, test_value));
  CHECK_FALSE(equal_check_not_blank->test(key, test_name, empty_value));
  CHECK(equal_check_not_blank->test(key, test_name, test_value));

  CHECK_FALSE(equal_check_blank->test(key, empty_name, empty_value));
  CHECK_FALSE(equal_check_blank->test(key, empty_name, test_value));
  CHECK(equal_check_blank->test(key, test_name, empty_value));
  CHECK_FALSE(equal_check_blank->test(key, test_name, test_value));
}
