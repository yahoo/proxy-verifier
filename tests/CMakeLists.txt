# @file
#
# Copyright 2026, Verizon Media SPDX-License-Identifier: Apache-2.0
#

set(PV_URTEST_WRAPPER "${CMAKE_BINARY_DIR}/urtest.sh")
set(PV_URTEST_PROJECT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")

file(MAKE_DIRECTORY "${PV_URTEST_PROJECT_DIRECTORY}")
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/pyproject.toml"
               "${PV_URTEST_PROJECT_DIRECTORY}/pyproject.toml" COPYONLY)
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/uv.lock"
               "${PV_URTEST_PROJECT_DIRECTORY}/uv.lock" COPYONLY)
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/urtest.sh.in"
               "${PV_URTEST_WRAPPER}" @ONLY)

file(
  CHMOD
  "${PV_URTEST_WRAPPER}"
  PERMISSIONS
  OWNER_READ
  OWNER_WRITE
  OWNER_EXECUTE
  GROUP_READ
  GROUP_EXECUTE
  WORLD_READ
  WORLD_EXECUTE)

add_custom_target(
  urtest
  COMMAND "${PV_URTEST_WRAPPER}"
  DEPENDS verifier-client verifier-server
  USES_TERMINAL)
