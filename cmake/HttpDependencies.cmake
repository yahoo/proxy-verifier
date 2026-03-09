# @file
#
# Copyright 2026, Verizon Media SPDX-License-Identifier: Apache-2.0
#

include_guard(GLOBAL)

include(ExternalProject)
include(ProcessorCount)

set(PV_OPENSSL_TAG "openssl-3.5.5")
set(PV_NGHTTP3_TAG "v1.15.0")
set(PV_NGTCP2_TAG "v1.21.0")
set(PV_NGHTTP2_TAG "v1.68.0")

function(
  _pv_resolve_dependency_root
  DEPENDENCY_NAME
  EXPLICIT_ROOT
  COMMON_ROOT
  BOOTSTRAP_ROOT
  OUT_ROOT
  OUT_BOOTSTRAP)
  if(EXPLICIT_ROOT)
    set(_pv_root "${EXPLICIT_ROOT}")
    set(_pv_bootstrap FALSE)
  elseif(PV_BOOTSTRAP_DEPS)
    if(COMMON_ROOT)
      set(_pv_root "${COMMON_ROOT}/${DEPENDENCY_NAME}")
    else()
      set(_pv_root "${BOOTSTRAP_ROOT}")
    endif()
    set(_pv_bootstrap TRUE)
  elseif(COMMON_ROOT)
    set(_pv_root "${COMMON_ROOT}/${DEPENDENCY_NAME}")
    set(_pv_bootstrap FALSE)
  else()
    message(
      FATAL_ERROR
        "No root was provided for ${DEPENDENCY_NAME}. Set PV_DEPS_ROOT or the matching per-dependency root, "
        "or enable PV_BOOTSTRAP_DEPS.")
  endif()

  set(${OUT_ROOT}
      "${_pv_root}"
      PARENT_SCOPE)
  set(${OUT_BOOTSTRAP}
      "${_pv_bootstrap}"
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
  if(NOT ROOT)
    message(FATAL_ERROR "No root was resolved for ${DEPENDENCY_NAME}.")
  endif()

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

function(_pv_collect_bootstrap_environment_modifications OUT_VAR)
  set(options)
  set(oneValueArgs PKG_CONFIG_PATH LDFLAGS)
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

  if(PV_PKG_CONFIG_PATH)
    list(APPEND _pv_modifications "PKG_CONFIG_PATH=set:${PV_PKG_CONFIG_PATH}")
  endif()

  if(PV_LDFLAGS)
    list(APPEND _pv_modifications "LDFLAGS=set:${PV_LDFLAGS}")
  endif()

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
      NGTCP2_ROOT
      NGHTTP2_ROOT
      BOOTSTRAP_OPENSSL
      BOOTSTRAP_NGHTTP3
      BOOTSTRAP_NGTCP2
      BOOTSTRAP_NGHTTP2
      OUT_TARGETS)
  set(multiValueArgs)
  cmake_parse_arguments(PV "${options}" "${oneValueArgs}" "${multiValueArgs}"
                        ${ARGN})

  ProcessorCount(_pv_jobs)
  if(NOT _pv_jobs)
    set(_pv_jobs 1)
  endif()

  _pv_collect_bootstrap_environment_modifications(_pv_base_env_modifications)
  _pv_collect_bootstrap_environment_modifications(
    _pv_ngtcp2_configure_env_modifications PKG_CONFIG_PATH
    "${PV_OPENSSL_ROOT}/lib/pkgconfig:${PV_NGHTTP3_ROOT}/lib/pkgconfig" LDFLAGS
    "-Wl,-rpath,${PV_OPENSSL_ROOT}/lib")
  _pv_collect_bootstrap_environment_modifications(
    _pv_nghttp2_configure_env_modifications
    PKG_CONFIG_PATH
    "${PV_OPENSSL_ROOT}/lib/pkgconfig:${PV_NGTCP2_ROOT}/lib/pkgconfig:${PV_NGHTTP3_ROOT}/lib/pkgconfig"
  )

  set(_pv_targets)

  if(PV_BOOTSTRAP_OPENSSL)
    _pv_append_bootstrap_install_byproducts(
      _pv_openssl_install_byproducts "${PV_OPENSSL_ROOT}" LIBRARIES crypto ssl)
    ExternalProject_Add(
      pv_dep_openssl
      PREFIX "${CMAKE_BINARY_DIR}/_deps/openssl"
      GIT_REPOSITORY "https://github.com/openssl/openssl.git"
      GIT_TAG "${PV_OPENSSL_TAG}"
      GIT_SHALLOW TRUE
      UPDATE_DISCONNECTED TRUE
      BUILD_IN_SOURCE TRUE
      CONFIGURE_ENVIRONMENT_MODIFICATION
      ${_pv_base_env_modifications}
      BUILD_ENVIRONMENT_MODIFICATION
      ${_pv_base_env_modifications}
      INSTALL_ENVIRONMENT_MODIFICATION
      ${_pv_base_env_modifications}
      INSTALL_BYPRODUCTS
      ${_pv_openssl_install_byproducts}
      CONFIGURE_COMMAND ./config enable-tls1_3 --prefix=${PV_OPENSSL_ROOT}
                        --libdir=lib
      BUILD_COMMAND make -j ${_pv_jobs}
      INSTALL_COMMAND make install_sw)
    list(APPEND _pv_targets pv_dep_openssl)
  endif()

  if(PV_BOOTSTRAP_NGHTTP3)
    _pv_append_bootstrap_install_byproducts(
      _pv_nghttp3_install_byproducts "${PV_NGHTTP3_ROOT}" LIBRARIES nghttp3)
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
      ${_pv_base_env_modifications}
      BUILD_ENVIRONMENT_MODIFICATION
      ${_pv_base_env_modifications}
      INSTALL_ENVIRONMENT_MODIFICATION
      ${_pv_base_env_modifications}
      INSTALL_BYPRODUCTS
      ${_pv_nghttp3_install_byproducts}
      CONFIGURE_COMMAND /bin/sh -c "${_pv_nghttp3_configure}"
      BUILD_COMMAND make -j ${_pv_jobs}
      INSTALL_COMMAND make install)
    list(APPEND _pv_targets pv_dep_nghttp3)
  endif()

  set(_pv_ngtcp2_depends_args)
  set(_pv_ngtcp2_depends)
  if(PV_BOOTSTRAP_OPENSSL)
    list(APPEND _pv_ngtcp2_depends pv_dep_openssl)
  endif()
  if(PV_BOOTSTRAP_NGHTTP3)
    list(APPEND _pv_ngtcp2_depends pv_dep_nghttp3)
  endif()
  if(_pv_ngtcp2_depends)
    set(_pv_ngtcp2_depends_args DEPENDS ${_pv_ngtcp2_depends})
  endif()

  if(PV_BOOTSTRAP_NGTCP2)
    _pv_append_bootstrap_install_byproducts(
      _pv_ngtcp2_install_byproducts "${PV_NGTCP2_ROOT}" LIBRARIES ngtcp2
      ngtcp2_crypto_ossl)
    set(_pv_ngtcp2_configure
        "autoreconf -if && ./configure --prefix='${PV_NGTCP2_ROOT}' --enable-lib-only"
    )
    ExternalProject_Add(
      pv_dep_ngtcp2
      PREFIX "${CMAKE_BINARY_DIR}/_deps/ngtcp2"
      GIT_REPOSITORY "https://github.com/ngtcp2/ngtcp2.git"
      GIT_TAG "${PV_NGTCP2_TAG}"
      GIT_SHALLOW TRUE
      UPDATE_DISCONNECTED TRUE
      UPDATE_COMMAND git submodule update --init --recursive
      BUILD_IN_SOURCE TRUE
      CONFIGURE_ENVIRONMENT_MODIFICATION
      ${_pv_ngtcp2_configure_env_modifications}
      BUILD_ENVIRONMENT_MODIFICATION
      ${_pv_base_env_modifications}
      INSTALL_ENVIRONMENT_MODIFICATION
      ${_pv_base_env_modifications}
      INSTALL_BYPRODUCTS
      ${_pv_ngtcp2_install_byproducts}
      CONFIGURE_COMMAND /bin/sh -c "${_pv_ngtcp2_configure}"
      BUILD_COMMAND make -j ${_pv_jobs}
      INSTALL_COMMAND make install ${_pv_ngtcp2_depends_args})
    list(APPEND _pv_targets pv_dep_ngtcp2)
  endif()

  set(_pv_nghttp2_depends_args)
  set(_pv_nghttp2_depends)
  if(PV_BOOTSTRAP_OPENSSL)
    list(APPEND _pv_nghttp2_depends pv_dep_openssl)
  endif()
  if(PV_BOOTSTRAP_NGHTTP3)
    list(APPEND _pv_nghttp2_depends pv_dep_nghttp3)
  endif()
  if(PV_BOOTSTRAP_NGTCP2)
    list(APPEND _pv_nghttp2_depends pv_dep_ngtcp2)
  endif()
  if(_pv_nghttp2_depends)
    set(_pv_nghttp2_depends_args DEPENDS ${_pv_nghttp2_depends})
  endif()

  if(PV_BOOTSTRAP_NGHTTP2)
    _pv_append_bootstrap_install_byproducts(
      _pv_nghttp2_install_byproducts "${PV_NGHTTP2_ROOT}" LIBRARIES nghttp2)
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
      ${_pv_nghttp2_configure_env_modifications}
      BUILD_ENVIRONMENT_MODIFICATION
      ${_pv_base_env_modifications}
      INSTALL_ENVIRONMENT_MODIFICATION
      ${_pv_base_env_modifications}
      INSTALL_BYPRODUCTS
      ${_pv_nghttp2_install_byproducts}
      CONFIGURE_COMMAND /bin/sh -c "${_pv_nghttp2_configure}"
      BUILD_COMMAND make -j ${_pv_jobs}
      INSTALL_COMMAND make install ${_pv_nghttp2_depends_args})
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

  if(PV_BOOTSTRAP_DEPS)
    if(PV_DEPS_ROOT)
      set(_pv_bootstrap_prefix "${PV_DEPS_ROOT}")
    else()
      set(_pv_bootstrap_prefix "${CMAKE_BINARY_DIR}/pv-deps")
    endif()
  else()
    set(_pv_bootstrap_prefix "")
  endif()

  _pv_resolve_dependency_root(
    "openssl" "${PV_OPENSSL_ROOT}" "${PV_DEPS_ROOT}"
    "${_pv_bootstrap_prefix}/openssl" _pv_openssl_root _pv_bootstrap_openssl)
  _pv_resolve_dependency_root(
    "nghttp3" "${PV_NGHTTP3_ROOT}" "${PV_DEPS_ROOT}"
    "${_pv_bootstrap_prefix}/nghttp3" _pv_nghttp3_root _pv_bootstrap_nghttp3)
  _pv_resolve_dependency_root(
    "ngtcp2" "${PV_NGTCP2_ROOT}" "${PV_DEPS_ROOT}"
    "${_pv_bootstrap_prefix}/ngtcp2" _pv_ngtcp2_root _pv_bootstrap_ngtcp2)
  _pv_resolve_dependency_root(
    "nghttp2" "${PV_NGHTTP2_ROOT}" "${PV_DEPS_ROOT}"
    "${_pv_bootstrap_prefix}/nghttp2" _pv_nghttp2_root _pv_bootstrap_nghttp2)

  if(PV_BOOTSTRAP_DEPS)
    if(_pv_bootstrap_openssl)
      file(MAKE_DIRECTORY "${_pv_openssl_root}" "${_pv_openssl_root}/include"
           "${_pv_openssl_root}/lib")
    endif()
    if(_pv_bootstrap_nghttp3)
      file(MAKE_DIRECTORY "${_pv_nghttp3_root}" "${_pv_nghttp3_root}/include"
           "${_pv_nghttp3_root}/lib")
    endif()
    if(_pv_bootstrap_ngtcp2)
      file(MAKE_DIRECTORY "${_pv_ngtcp2_root}" "${_pv_ngtcp2_root}/include"
           "${_pv_ngtcp2_root}/lib")
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
      NGTCP2_ROOT
      "${_pv_ngtcp2_root}"
      NGHTTP2_ROOT
      "${_pv_nghttp2_root}"
      BOOTSTRAP_OPENSSL
      "${_pv_bootstrap_openssl}"
      BOOTSTRAP_NGHTTP3
      "${_pv_bootstrap_nghttp3}"
      BOOTSTRAP_NGTCP2
      "${_pv_bootstrap_ngtcp2}"
      BOOTSTRAP_NGHTTP2
      "${_pv_bootstrap_nghttp2}"
      OUT_TARGETS
      _pv_bootstrap_targets)
  else()
    set(_pv_bootstrap_targets)
  endif()

  _pv_assert_external_layout("OpenSSL" "${_pv_openssl_root}")
  _pv_assert_external_layout("nghttp3" "${_pv_nghttp3_root}")
  _pv_assert_external_layout("ngtcp2" "${_pv_ngtcp2_root}")
  _pv_assert_external_layout("nghttp2" "${_pv_nghttp2_root}")

  _pv_get_library_path("${_pv_openssl_root}" "crypto"
                       _pv_openssl_crypto_library)
  _pv_get_library_path("${_pv_openssl_root}" "ssl" _pv_openssl_ssl_library)
  _pv_get_library_path("${_pv_nghttp2_root}" "nghttp2" _pv_nghttp2_library)
  _pv_get_library_path("${_pv_nghttp3_root}" "nghttp3" _pv_nghttp3_library)
  _pv_get_library_path("${_pv_ngtcp2_root}" "ngtcp2" _pv_ngtcp2_library)
  _pv_get_library_path("${_pv_ngtcp2_root}" "ngtcp2_crypto_ossl"
                       _pv_ngtcp2_crypto_ossl_library)

  if(NOT _pv_bootstrap_openssl)
    _pv_assert_library_exists("OpenSSL crypto" "${_pv_openssl_crypto_library}")
    _pv_assert_library_exists("OpenSSL ssl" "${_pv_openssl_ssl_library}")
  endif()
  if(NOT _pv_bootstrap_nghttp2)
    _pv_assert_library_exists("nghttp2" "${_pv_nghttp2_library}")
  endif()
  if(NOT _pv_bootstrap_nghttp3)
    _pv_assert_library_exists("nghttp3" "${_pv_nghttp3_library}")
  endif()
  if(NOT _pv_bootstrap_ngtcp2)
    _pv_assert_library_exists("ngtcp2" "${_pv_ngtcp2_library}")
    _pv_assert_library_exists("ngtcp2_crypto_ossl"
                              "${_pv_ngtcp2_crypto_ossl_library}")
  endif()

  set(_pv_openssl_depends)
  if(_pv_bootstrap_openssl)
    list(APPEND _pv_openssl_depends pv_dep_openssl)
  endif()
  set(_pv_nghttp2_depends)
  if(_pv_bootstrap_nghttp2)
    list(APPEND _pv_nghttp2_depends pv_dep_nghttp2)
  endif()
  set(_pv_nghttp3_depends)
  if(_pv_bootstrap_nghttp3)
    list(APPEND _pv_nghttp3_depends pv_dep_nghttp3)
  endif()
  set(_pv_ngtcp2_depends)
  if(_pv_bootstrap_ngtcp2)
    list(APPEND _pv_ngtcp2_depends pv_dep_ngtcp2)
  endif()

  _pv_define_imported_library(
    pv_openssl_crypto "${_pv_openssl_crypto_library}"
    "${_pv_openssl_root}/include" DEPENDS ${_pv_openssl_depends})
  _pv_define_imported_library(
    pv_openssl_ssl
    "${_pv_openssl_ssl_library}"
    "${_pv_openssl_root}/include"
    DEPENDS
    ${_pv_openssl_depends}
    INTERFACE_LINK_LIBRARIES
    pv_openssl_crypto)
  _pv_define_imported_library(
    pv_nghttp2 "${_pv_nghttp2_library}" "${_pv_nghttp2_root}/include" DEPENDS
    ${_pv_nghttp2_depends})
  _pv_define_imported_library(
    pv_nghttp3 "${_pv_nghttp3_library}" "${_pv_nghttp3_root}/include" DEPENDS
    ${_pv_nghttp3_depends})
  _pv_define_imported_library(
    pv_ngtcp2 "${_pv_ngtcp2_library}" "${_pv_ngtcp2_root}/include" DEPENDS
    ${_pv_ngtcp2_depends})
  _pv_define_imported_library(
    pv_ngtcp2_crypto_ossl
    "${_pv_ngtcp2_crypto_ossl_library}"
    "${_pv_ngtcp2_root}/include"
    DEPENDS
    ${_pv_ngtcp2_depends}
    INTERFACE_LINK_LIBRARIES
    "pv_ngtcp2;pv_openssl_ssl;pv_openssl_crypto")

  set(_pv_libraries pv_nghttp2 pv_nghttp3 pv_ngtcp2_crypto_ossl pv_ngtcp2
                    pv_openssl_ssl pv_openssl_crypto)

  if(PV_STATIC_BUILD)
    set(_pv_rpath_dirs)
  else()
    set(_pv_rpath_dirs "${_pv_nghttp2_root}/lib" "${_pv_nghttp3_root}/lib"
                       "${_pv_ngtcp2_root}/lib" "${_pv_openssl_root}/lib")
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
