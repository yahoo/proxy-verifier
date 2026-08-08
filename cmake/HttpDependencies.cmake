# @file
#
# Copyright 2026, Verizon Media SPDX-License-Identifier: Apache-2.0
#

include_guard(GLOBAL)

include(ExternalProject)
include(ProcessorCount)

set(PV_OPENSSL_TAG "openssl-3.5.7")
set(PV_NGHTTP3_TAG "v1.15.0")
set(PV_NGHTTP2_TAG "v1.68.0")

function(
  _pv_resolve_dependency
  DEPENDENCY_NAME
  EXPLICIT_ROOT
  COMMON_ROOT
  BOOTSTRAP_ROOT
  OUT_ROOT
  OUT_BOOTSTRAP
  OUT_SYSTEM)
  if(EXPLICIT_ROOT)
    set(_pv_root "${EXPLICIT_ROOT}")
    set(_pv_bootstrap FALSE)
    set(_pv_system FALSE)
  elseif(PV_BOOTSTRAP_DEPS)
    if(COMMON_ROOT)
      set(_pv_root "${COMMON_ROOT}/${DEPENDENCY_NAME}")
    else()
      set(_pv_root "${BOOTSTRAP_ROOT}")
    endif()
    set(_pv_bootstrap TRUE)
    set(_pv_system FALSE)
  elseif(COMMON_ROOT AND IS_DIRECTORY "${COMMON_ROOT}/${DEPENDENCY_NAME}")
    set(_pv_root "${COMMON_ROOT}/${DEPENDENCY_NAME}")
    set(_pv_bootstrap FALSE)
    set(_pv_system FALSE)
  else()
    set(_pv_root "")
    set(_pv_bootstrap FALSE)
    set(_pv_system TRUE)
  endif()

  set(${OUT_ROOT}
      "${_pv_root}"
      PARENT_SCOPE)
  set(${OUT_BOOTSTRAP}
      "${_pv_bootstrap}"
      PARENT_SCOPE)
  set(${OUT_SYSTEM}
      "${_pv_system}"
      PARENT_SCOPE)
endfunction()

function(_pv_define_imported_library TARGET_NAME LIBRARY_PATH INCLUDE_DIR)
  set(options)
  set(oneValueArgs)
  set(multiValueArgs DEPENDS INTERFACE_LINK_LIBRARIES)
  cmake_parse_arguments(PV "${options}" "${oneValueArgs}" "${multiValueArgs}"
                        ${ARGN})

  if(NOT TARGET "${TARGET_NAME}")
    add_library("${TARGET_NAME}" UNKNOWN IMPORTED GLOBAL)
  endif()
  set_target_properties(
    "${TARGET_NAME}" PROPERTIES IMPORTED_LOCATION "${LIBRARY_PATH}"
                                INTERFACE_INCLUDE_DIRECTORIES "${INCLUDE_DIR}")
  if(PV_INTERFACE_LINK_LIBRARIES)
    set_property(
      TARGET "${TARGET_NAME}" PROPERTY INTERFACE_LINK_LIBRARIES
                                       "${PV_INTERFACE_LINK_LIBRARIES}")
  endif()
  if(PV_DEPENDS)
    add_dependencies("${TARGET_NAME}" ${PV_DEPENDS})
  endif()
endfunction()

function(_pv_get_library_path ROOT BASENAME OUT_VAR)
  if(PV_STATIC_BUILD)
    set(_pv_library
        "${ROOT}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}${BASENAME}${CMAKE_STATIC_LIBRARY_SUFFIX}"
    )
  else()
    set(_pv_library
        "${ROOT}/lib/${CMAKE_SHARED_LIBRARY_PREFIX}${BASENAME}${CMAKE_SHARED_LIBRARY_SUFFIX}"
    )
    if(NOT EXISTS "${_pv_library}")
      find_library(
        _pv_found_library
        NAMES "${BASENAME}"
        PATHS "${ROOT}/lib"
        NO_DEFAULT_PATH)
      if(_pv_found_library)
        set(_pv_library "${_pv_found_library}")
      endif()
    endif()
  endif()
  set(${OUT_VAR}
      "${_pv_library}"
      PARENT_SCOPE)
endfunction()

function(_pv_assert_external_layout DEPENDENCY_NAME ROOT)
  if(NOT IS_DIRECTORY "${ROOT}")
    message(
      FATAL_ERROR
        "Dependency root for ${DEPENDENCY_NAME} does not exist: ${ROOT}")
  endif()
  foreach(_pv_required_subdir include lib)
    if(NOT IS_DIRECTORY "${ROOT}/${_pv_required_subdir}")
      message(
        FATAL_ERROR
          "Dependency root for ${DEPENDENCY_NAME} is missing ${_pv_required_subdir}: ${ROOT}/${_pv_required_subdir}"
      )
    endif()
  endforeach()
endfunction()

function(_pv_assert_library_exists FRIENDLY_NAME LIBRARY_PATH)
  if(NOT EXISTS "${LIBRARY_PATH}")
    message(
      FATAL_ERROR "${FRIENDLY_NAME} library was not found at ${LIBRARY_PATH}")
  endif()
endfunction()

function(_pv_assert_openssl_35 ROOT)
  set(_pv_version_header "${ROOT}/include/openssl/opensslv.h")
  if(NOT EXISTS "${_pv_version_header}")
    message(
      FATAL_ERROR "OpenSSL version header was not found: ${_pv_version_header}")
  endif()
  file(READ "${_pv_version_header}" _pv_openssl_version_text)
  string(REGEX MATCH "OPENSSL_VERSION_MAJOR[ \t]+([0-9]+)" _pv_major_match
               "${_pv_openssl_version_text}")
  set(_pv_major "${CMAKE_MATCH_1}")
  string(REGEX MATCH "OPENSSL_VERSION_MINOR[ \t]+([0-9]+)" _pv_minor_match
               "${_pv_openssl_version_text}")
  set(_pv_minor "${CMAKE_MATCH_1}")
  if(NOT _pv_major
     OR _pv_major LESS 3
     OR (_pv_major EQUAL 3 AND _pv_minor LESS 5))
    message(
      FATAL_ERROR
        "Proxy Verifier HTTP/3 requires upstream OpenSSL 3.5 or newer; found ${_pv_major}.${_pv_minor} under ${ROOT}."
    )
  endif()
endfunction()

function(_pv_collect_bootstrap_environment_modifications OUT_VAR)
  set(options)
  set(oneValueArgs CFLAGS CXXFLAGS)
  set(multiValueArgs)
  cmake_parse_arguments(PV "${options}" "${oneValueArgs}" "${multiValueArgs}"
                        ${ARGN})

  set(_pv_modifications)
  foreach(_pv_name CC CXX SDKROOT)
    set(_pv_value "")
    if(DEFINED ENV{${_pv_name}} AND NOT "$ENV{${_pv_name}}" STREQUAL "")
      set(_pv_value "$ENV{${_pv_name}}")
    elseif(_pv_name STREQUAL "CC" AND CMAKE_C_COMPILER)
      set(_pv_value "${CMAKE_C_COMPILER}")
    elseif(_pv_name STREQUAL "CXX" AND CMAKE_CXX_COMPILER)
      set(_pv_value "${CMAKE_CXX_COMPILER}")
    elseif(
      _pv_name STREQUAL "SDKROOT"
      AND APPLE
      AND CMAKE_OSX_SYSROOT)
      set(_pv_value "${CMAKE_OSX_SYSROOT}")
    endif()
    if(_pv_value)
      list(APPEND _pv_modifications "${_pv_name}=set:${_pv_value}")
    endif()
  endforeach()

  foreach(_pv_flag_name CFLAGS CXXFLAGS)
    set(_pv_flag_value "")
    if(DEFINED ENV{${_pv_flag_name}} AND NOT "$ENV{${_pv_flag_name}}" STREQUAL
                                         "")
      set(_pv_flag_value "$ENV{${_pv_flag_name}}")
    endif()
    if(PV_${_pv_flag_name})
      string(APPEND _pv_flag_value " ${PV_${_pv_flag_name}}")
    endif()
    string(STRIP "${_pv_flag_value}" _pv_flag_value)
    if(_pv_flag_value)
      string(REPLACE " " "\\ " _pv_flag_value_escaped "${_pv_flag_value}")
      list(APPEND _pv_modifications
           "${_pv_flag_name}=set:${_pv_flag_value_escaped}")
    endif()
  endforeach()

  set(${OUT_VAR}
      "${_pv_modifications}"
      PARENT_SCOPE)
endfunction()

function(_pv_append_bootstrap_install_byproducts OUT_VAR ROOT)
  set(options)
  set(oneValueArgs)
  set(multiValueArgs LIBRARIES)
  cmake_parse_arguments(PV "${options}" "${oneValueArgs}" "${multiValueArgs}"
                        ${ARGN})
  set(_pv_byproducts)
  foreach(_pv_library IN LISTS PV_LIBRARIES)
    _pv_get_library_path("${ROOT}" "${_pv_library}" _pv_library_path)
    list(APPEND _pv_byproducts "${_pv_library_path}")
  endforeach()
  set(${OUT_VAR}
      "${_pv_byproducts}"
      PARENT_SCOPE)
endfunction()

function(_pv_add_bootstrap_projects)
  set(options)
  set(oneValueArgs
      OPENSSL_ROOT
      NGHTTP3_ROOT
      NGHTTP2_ROOT
      BOOTSTRAP_OPENSSL
      BOOTSTRAP_NGHTTP3
      BOOTSTRAP_NGHTTP2
      OUT_TARGETS)
  set(multiValueArgs)
  cmake_parse_arguments(PV "${options}" "${oneValueArgs}" "${multiValueArgs}"
                        ${ARGN})

  ProcessorCount(_pv_jobs)
  if(NOT _pv_jobs)
    set(_pv_jobs 1)
  endif()
  _pv_collect_bootstrap_environment_modifications(
    _pv_environment CFLAGS "${PV_PORTABLE_C_FLAGS}" CXXFLAGS
    "${PV_PORTABLE_CXX_FLAGS}")

  set(_pv_targets)

  if(PV_BOOTSTRAP_OPENSSL)
    _pv_append_bootstrap_install_byproducts(
      _pv_openssl_byproducts "${PV_OPENSSL_ROOT}" LIBRARIES crypto ssl)
    ExternalProject_Add(
      pv_dep_openssl
      PREFIX "${CMAKE_BINARY_DIR}/_deps/openssl"
      GIT_REPOSITORY "https://github.com/openssl/openssl.git"
      GIT_TAG "${PV_OPENSSL_TAG}"
      GIT_SHALLOW TRUE
      UPDATE_DISCONNECTED TRUE
      BUILD_IN_SOURCE TRUE
      CONFIGURE_ENVIRONMENT_MODIFICATION
      ${_pv_environment}
      BUILD_ENVIRONMENT_MODIFICATION
      ${_pv_environment}
      INSTALL_ENVIRONMENT_MODIFICATION
      ${_pv_environment}
      INSTALL_BYPRODUCTS
      ${_pv_openssl_byproducts}
      CONFIGURE_COMMAND ./config enable-tls1_3 --prefix=${PV_OPENSSL_ROOT}
                        --libdir=lib
      BUILD_COMMAND make -j ${_pv_jobs}
      INSTALL_COMMAND make install_sw)
    list(APPEND _pv_targets pv_dep_openssl)
  endif()

  if(PV_BOOTSTRAP_NGHTTP3)
    _pv_append_bootstrap_install_byproducts(
      _pv_nghttp3_byproducts "${PV_NGHTTP3_ROOT}" LIBRARIES nghttp3)
    set(_pv_nghttp3_configure
        "autoreconf -if && ./configure --prefix='${PV_NGHTTP3_ROOT}' --enable-lib-only"
    )
    ExternalProject_Add(
      pv_dep_nghttp3
      PREFIX "${CMAKE_BINARY_DIR}/_deps/nghttp3"
      GIT_REPOSITORY "https://github.com/ngtcp2/nghttp3.git"
      GIT_TAG "${PV_NGHTTP3_TAG}"
      GIT_SHALLOW TRUE
      UPDATE_DISCONNECTED TRUE
      UPDATE_COMMAND git submodule update --init --recursive
      BUILD_IN_SOURCE TRUE
      CONFIGURE_ENVIRONMENT_MODIFICATION
      ${_pv_environment}
      BUILD_ENVIRONMENT_MODIFICATION
      ${_pv_environment}
      INSTALL_ENVIRONMENT_MODIFICATION
      ${_pv_environment}
      INSTALL_BYPRODUCTS
      ${_pv_nghttp3_byproducts}
      CONFIGURE_COMMAND /bin/sh -c "${_pv_nghttp3_configure}"
      BUILD_COMMAND make -j ${_pv_jobs}
      INSTALL_COMMAND make install)
    list(APPEND _pv_targets pv_dep_nghttp3)
  endif()

  if(PV_BOOTSTRAP_NGHTTP2)
    _pv_append_bootstrap_install_byproducts(
      _pv_nghttp2_byproducts "${PV_NGHTTP2_ROOT}" LIBRARIES nghttp2)
    set(_pv_nghttp2_configure
        "autoreconf -if && ./configure --prefix='${PV_NGHTTP2_ROOT}' --enable-lib-only"
    )
    ExternalProject_Add(
      pv_dep_nghttp2
      PREFIX "${CMAKE_BINARY_DIR}/_deps/nghttp2"
      GIT_REPOSITORY "https://github.com/nghttp2/nghttp2.git"
      GIT_TAG "${PV_NGHTTP2_TAG}"
      GIT_SHALLOW TRUE
      UPDATE_DISCONNECTED TRUE
      UPDATE_COMMAND git submodule update --init --recursive
      BUILD_IN_SOURCE TRUE
      CONFIGURE_ENVIRONMENT_MODIFICATION
      ${_pv_environment}
      BUILD_ENVIRONMENT_MODIFICATION
      ${_pv_environment}
      INSTALL_ENVIRONMENT_MODIFICATION
      ${_pv_environment}
      INSTALL_BYPRODUCTS
      ${_pv_nghttp2_byproducts}
      CONFIGURE_COMMAND /bin/sh -c "${_pv_nghttp2_configure}"
      BUILD_COMMAND make -j ${_pv_jobs}
      INSTALL_COMMAND make install)
    list(APPEND _pv_targets pv_dep_nghttp2)
  endif()

  set(${PV_OUT_TARGETS}
      "${_pv_targets}"
      PARENT_SCOPE)
endfunction()

function(pv_define_http_dependencies)
  set(options)
  set(oneValueArgs OUT_LIBRARIES OUT_RPATH_DIRS OUT_BOOTSTRAP_TARGETS
                   OUT_BOOTSTRAP_PREFIX)
  set(multiValueArgs)
  cmake_parse_arguments(PV "${options}" "${oneValueArgs}" "${multiValueArgs}"
                        ${ARGN})

  if(PV_NGTCP2_ROOT)
    message(
      DEPRECATION
        "PV_NGTCP2_ROOT is ignored because OpenSSL 3.5 now provides the QUIC transport."
    )
  endif()

  if(PV_BOOTSTRAP_DEPS)
    if(PV_DEPS_ROOT)
      set(_pv_bootstrap_prefix "${PV_DEPS_ROOT}")
    else()
      set(_pv_bootstrap_prefix "${CMAKE_BINARY_DIR}/pv-deps")
    endif()
  else()
    set(_pv_bootstrap_prefix "")
  endif()

  _pv_resolve_dependency(
    "openssl"
    "${PV_OPENSSL_ROOT}"
    "${PV_DEPS_ROOT}"
    "${_pv_bootstrap_prefix}/openssl"
    _pv_openssl_root
    _pv_bootstrap_openssl
    _pv_system_openssl)
  _pv_resolve_dependency(
    "nghttp3"
    "${PV_NGHTTP3_ROOT}"
    "${PV_DEPS_ROOT}"
    "${_pv_bootstrap_prefix}/nghttp3"
    _pv_nghttp3_root
    _pv_bootstrap_nghttp3
    _pv_system_nghttp3)
  _pv_resolve_dependency(
    "nghttp2"
    "${PV_NGHTTP2_ROOT}"
    "${PV_DEPS_ROOT}"
    "${_pv_bootstrap_prefix}/nghttp2"
    _pv_nghttp2_root
    _pv_bootstrap_nghttp2
    _pv_system_nghttp2)

  if(PV_BOOTSTRAP_DEPS)
    if(_pv_bootstrap_openssl)
      file(MAKE_DIRECTORY "${_pv_openssl_root}" "${_pv_openssl_root}/include"
           "${_pv_openssl_root}/lib")
    endif()
    if(_pv_bootstrap_nghttp3)
      file(MAKE_DIRECTORY "${_pv_nghttp3_root}" "${_pv_nghttp3_root}/include"
           "${_pv_nghttp3_root}/lib")
    endif()
    if(_pv_bootstrap_nghttp2)
      file(MAKE_DIRECTORY "${_pv_nghttp2_root}" "${_pv_nghttp2_root}/include"
           "${_pv_nghttp2_root}/lib")
    endif()
    _pv_add_bootstrap_projects(
      OPENSSL_ROOT
      "${_pv_openssl_root}"
      NGHTTP3_ROOT
      "${_pv_nghttp3_root}"
      NGHTTP2_ROOT
      "${_pv_nghttp2_root}"
      BOOTSTRAP_OPENSSL
      "${_pv_bootstrap_openssl}"
      BOOTSTRAP_NGHTTP3
      "${_pv_bootstrap_nghttp3}"
      BOOTSTRAP_NGHTTP2
      "${_pv_bootstrap_nghttp2}"
      OUT_TARGETS
      _pv_bootstrap_targets)
  else()
    set(_pv_bootstrap_targets)
  endif()

  set(_pv_libraries)
  set(_pv_rpath_dirs)

  if(_pv_system_openssl)
    find_package(OpenSSL 3.5 REQUIRED COMPONENTS SSL Crypto)
    list(APPEND _pv_libraries OpenSSL::SSL OpenSSL::Crypto)
  else()
    _pv_assert_external_layout("OpenSSL" "${_pv_openssl_root}")
    if(NOT _pv_bootstrap_openssl)
      _pv_assert_openssl_35("${_pv_openssl_root}")
    endif()
    _pv_get_library_path("${_pv_openssl_root}" "crypto" _pv_openssl_crypto)
    _pv_get_library_path("${_pv_openssl_root}" "ssl" _pv_openssl_ssl)
    if(NOT _pv_bootstrap_openssl)
      _pv_assert_library_exists("OpenSSL crypto" "${_pv_openssl_crypto}")
      _pv_assert_library_exists("OpenSSL ssl" "${_pv_openssl_ssl}")
    endif()
    set(_pv_openssl_depends)
    if(_pv_bootstrap_openssl)
      list(APPEND _pv_openssl_depends pv_dep_openssl)
    endif()
    _pv_define_imported_library(
      pv_openssl_crypto "${_pv_openssl_crypto}" "${_pv_openssl_root}/include"
      DEPENDS ${_pv_openssl_depends})
    _pv_define_imported_library(
      pv_openssl_ssl
      "${_pv_openssl_ssl}"
      "${_pv_openssl_root}/include"
      DEPENDS
      ${_pv_openssl_depends}
      INTERFACE_LINK_LIBRARIES
      pv_openssl_crypto)
    list(APPEND _pv_libraries pv_openssl_ssl pv_openssl_crypto)
    list(APPEND _pv_rpath_dirs "${_pv_openssl_root}/lib")
  endif()

  if(_pv_system_nghttp2 OR _pv_system_nghttp3)
    find_package(PkgConfig REQUIRED)
  endif()
  if(_pv_system_nghttp2)
    pkg_check_modules(PV_SYSTEM_NGHTTP2 REQUIRED IMPORTED_TARGET GLOBAL
                      libnghttp2)
    list(APPEND _pv_libraries PkgConfig::PV_SYSTEM_NGHTTP2)
  else()
    _pv_assert_external_layout("nghttp2" "${_pv_nghttp2_root}")
    _pv_get_library_path("${_pv_nghttp2_root}" "nghttp2" _pv_nghttp2_library)
    if(NOT _pv_bootstrap_nghttp2)
      _pv_assert_library_exists("nghttp2" "${_pv_nghttp2_library}")
    endif()
    set(_pv_nghttp2_depends)
    if(_pv_bootstrap_nghttp2)
      list(APPEND _pv_nghttp2_depends pv_dep_nghttp2)
    endif()
    _pv_define_imported_library(
      pv_nghttp2 "${_pv_nghttp2_library}" "${_pv_nghttp2_root}/include" DEPENDS
      ${_pv_nghttp2_depends})
    list(APPEND _pv_libraries pv_nghttp2)
    list(APPEND _pv_rpath_dirs "${_pv_nghttp2_root}/lib")
  endif()

  if(_pv_system_nghttp3)
    pkg_check_modules(PV_SYSTEM_NGHTTP3 REQUIRED IMPORTED_TARGET GLOBAL
                      libnghttp3)
    list(APPEND _pv_libraries PkgConfig::PV_SYSTEM_NGHTTP3)
  else()
    _pv_assert_external_layout("nghttp3" "${_pv_nghttp3_root}")
    _pv_get_library_path("${_pv_nghttp3_root}" "nghttp3" _pv_nghttp3_library)
    if(NOT _pv_bootstrap_nghttp3)
      _pv_assert_library_exists("nghttp3" "${_pv_nghttp3_library}")
    endif()
    set(_pv_nghttp3_depends)
    if(_pv_bootstrap_nghttp3)
      list(APPEND _pv_nghttp3_depends pv_dep_nghttp3)
    endif()
    _pv_define_imported_library(
      pv_nghttp3 "${_pv_nghttp3_library}" "${_pv_nghttp3_root}/include" DEPENDS
      ${_pv_nghttp3_depends})
    list(APPEND _pv_libraries pv_nghttp3)
    list(APPEND _pv_rpath_dirs "${_pv_nghttp3_root}/lib")
  endif()

  if(PV_STATIC_BUILD)
    set(_pv_rpath_dirs)
  else()
    list(REMOVE_DUPLICATES _pv_rpath_dirs)
  endif()

  set(${PV_OUT_LIBRARIES}
      "${_pv_libraries}"
      PARENT_SCOPE)
  set(${PV_OUT_RPATH_DIRS}
      "${_pv_rpath_dirs}"
      PARENT_SCOPE)
  set(${PV_OUT_BOOTSTRAP_TARGETS}
      "${_pv_bootstrap_targets}"
      PARENT_SCOPE)
  set(${PV_OUT_BOOTSTRAP_PREFIX}
      "${_pv_bootstrap_prefix}"
      PARENT_SCOPE)
endfunction()
