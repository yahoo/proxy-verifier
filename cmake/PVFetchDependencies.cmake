# @file
#
# Copyright 2026, Verizon Media SPDX-License-Identifier: Apache-2.0
#

include_guard(GLOBAL)

include(FetchContent)

set(PV_LIBSWOC_TAG "1.5.16")
set(PV_YAML_CPP_TAG "yaml-cpp-0.9.0")

function(pv_fetch_dependencies)
  set(LIBSWOC_INSTALL
      OFF
      CACHE BOOL "" FORCE)
  FetchContent_Declare(
    libswoc
    GIT_REPOSITORY "https://github.com/apache/trafficserver-libswoc.git"
    GIT_TAG "${PV_LIBSWOC_TAG}"
    GIT_SHALLOW TRUE
    SOURCE_SUBDIR code)

  set(YAML_BUILD_SHARED_LIBS
      OFF
      CACHE BOOL "" FORCE)
  set(YAML_CPP_BUILD_TESTS
      OFF
      CACHE BOOL "" FORCE)
  set(YAML_CPP_BUILD_TOOLS
      OFF
      CACHE BOOL "" FORCE)
  set(YAML_CPP_INSTALL
      OFF
      CACHE BOOL "" FORCE)
  FetchContent_Declare(
    yaml_cpp
    GIT_REPOSITORY "https://github.com/jbeder/yaml-cpp.git"
    GIT_TAG "${PV_YAML_CPP_TAG}"
    GIT_SHALLOW TRUE)

  FetchContent_MakeAvailable(libswoc yaml_cpp)
endfunction()
