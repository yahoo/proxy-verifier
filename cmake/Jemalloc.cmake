# @file
#
# Copyright 2026, Verizon Media SPDX-License-Identifier: Apache-2.0
#

include_guard(GLOBAL)

# Replay parsing builds and frees a yaml-cpp node for every YAML element, and
# with glibc malloc about a third of parsing CPU goes to the allocator. Linking
# jemalloc replaces malloc process-wide when it is available.
function(pv_find_jemalloc out_var)
  set(_pv_jemalloc_target "")
  if(PV_ENABLE_JEMALLOC AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(PV_JEMALLOC QUIET IMPORTED_TARGET GLOBAL jemalloc)
    if(PV_JEMALLOC_FOUND AND PV_STATIC_BUILD)
      # pkg-config reports a library name; a static build needs the archive.
      find_library(
        _pv_jemalloc_archive
        NAMES libjemalloc.a libjemalloc_pic.a
        HINTS ${PV_JEMALLOC_LIBRARY_DIRS})
      if(_pv_jemalloc_archive)
        add_library(pv_jemalloc_static STATIC IMPORTED GLOBAL)
        set_target_properties(
          pv_jemalloc_static PROPERTIES IMPORTED_LOCATION
                                        "${_pv_jemalloc_archive}")
        set(_pv_jemalloc_target pv_jemalloc_static)
      else()
        message(
          STATUS "Static builds need libjemalloc.a; using the system allocator")
      endif()
    elseif(PV_JEMALLOC_FOUND)
      set(_pv_jemalloc_target PkgConfig::PV_JEMALLOC)
    endif()
    if(_pv_jemalloc_target)
      message(STATUS "Building with jemalloc as the memory allocator")
    elseif(NOT PV_JEMALLOC_FOUND)
      message(STATUS "jemalloc was not found; using the system allocator")
    endif()
  elseif(PV_ENABLE_JEMALLOC)
    message(
      STATUS
        "jemalloc is only linked on Linux; using the ${CMAKE_SYSTEM_NAME} allocator"
    )
  else()
    message(STATUS "jemalloc support is disabled; using the system allocator")
  endif()

  set(${out_var}
      "${_pv_jemalloc_target}"
      PARENT_SCOPE)
endfunction()
