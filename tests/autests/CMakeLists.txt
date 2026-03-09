# @file
#
# Copyright 2026, Verizon Media SPDX-License-Identifier: Apache-2.0
#

set(PV_AUTEST_WRAPPER "${CMAKE_BINARY_DIR}/autest.sh")

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/autest.sh.in"
               "${PV_AUTEST_WRAPPER}" @ONLY)

file(
  CHMOD
  "${PV_AUTEST_WRAPPER}"
  PERMISSIONS
  OWNER_READ
  OWNER_WRITE
  OWNER_EXECUTE
  GROUP_READ
  GROUP_EXECUTE
  WORLD_READ
  WORLD_EXECUTE)
