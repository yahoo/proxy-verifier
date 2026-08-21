# @file
#
# Copyright 2026, Verizon Media SPDX-License-Identifier: Apache-2.0
#

include_guard(GLOBAL)

function(pv_find_io_uring out_var)
  set(_pv_io_uring_target "")
  if(PV_ENABLE_IO_URING AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    if(PV_STATIC_BUILD)
      set(CMAKE_FIND_LIBRARY_SUFFIXES "${CMAKE_STATIC_LIBRARY_SUFFIX}")
    endif()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(PV_LIBURING QUIET IMPORTED_TARGET GLOBAL "liburing>=2.0")
    if(PV_LIBURING_FOUND)
      if(PV_STATIC_BUILD)
        if(NOT PV_LIBURING_LINK_LIBRARIES)
          message(FATAL_ERROR "Static builds require a static liburing archive")
        endif()
        foreach(_pv_io_uring_library IN LISTS PV_LIBURING_LINK_LIBRARIES)
          if(NOT _pv_io_uring_library MATCHES
             "\\${CMAKE_STATIC_LIBRARY_SUFFIX}$")
            message(
              FATAL_ERROR
                "Static builds require a static liburing archive, but pkg-config resolved "
                "${_pv_io_uring_library}")
          endif()
        endforeach()
      endif()
      set(_pv_io_uring_target PkgConfig::PV_LIBURING)
      message(STATUS "Building with io_uring socket readiness support")
    else()
      message(
        STATUS "liburing was not found; using the poll socket readiness backend"
      )
    endif()
  elseif(PV_ENABLE_IO_URING)
    message(
      STATUS "io_uring is not available on ${CMAKE_SYSTEM_NAME}; using poll")
  else()
    message(STATUS "io_uring support is disabled; using poll")
  endif()

  set(${out_var}
      "${_pv_io_uring_target}"
      PARENT_SCOPE)
endfunction()
