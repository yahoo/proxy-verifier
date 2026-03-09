# @file
#
# Copyright 2026, Verizon Media SPDX-License-Identifier: Apache-2.0
#

set(PV_UNIT_TEST_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/test_YamlParser.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/test_chunk_parsing.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/test_http.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/test_https.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/test_verification.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/unit_test_main.cc")

add_executable(proxy-verifier-tests ${PV_UNIT_TEST_SOURCES})

target_compile_definitions(proxy-verifier-tests
                           PRIVATE CATCH_CONFIG_NO_POSIX_SIGNALS)
target_compile_options(proxy-verifier-tests PRIVATE -g)
target_include_directories(proxy-verifier-tests
                           PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(proxy-verifier-tests PRIVATE verifier-core)

if(PV_STATIC_BUILD AND NOT APPLE)
  target_link_options(proxy-verifier-tests PRIVATE -static)
  target_link_libraries(
    proxy-verifier-tests PRIVATE -Wl,--whole-archive pthread
                                 -Wl,--no-whole-archive dl)
endif()

if(PV_EXTERNAL_RPATH_DIRS)
  list(JOIN PV_EXTERNAL_RPATH_DIRS ";" _pv_unit_test_rpath)
  set_target_properties(proxy-verifier-tests
                        PROPERTIES BUILD_RPATH "${_pv_unit_test_rpath}")
endif()

add_test(NAME proxy-verifier-unit-tests COMMAND proxy-verifier-tests)
