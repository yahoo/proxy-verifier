# @file
#
# Copyright 2026, Verizon Media SPDX-License-Identifier: Apache-2.0
#

include_guard(GLOBAL)

function(pv_find_http_dependencies out_var)
  if(PV_STATIC_BUILD)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
    set(CMAKE_FIND_LIBRARY_SUFFIXES "${CMAKE_STATIC_LIBRARY_SUFFIX}")
  endif()

  find_package(OpenSSL 3.5 REQUIRED COMPONENTS SSL Crypto)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(PV_NGHTTP2 REQUIRED IMPORTED_TARGET GLOBAL
                    "libnghttp2>=1.60.0")
  pkg_check_modules(PV_NGHTTP3 REQUIRED IMPORTED_TARGET GLOBAL
                    "libnghttp3>=0.8.0")

  set(${out_var}
      OpenSSL::SSL OpenSSL::Crypto PkgConfig::PV_NGHTTP2 PkgConfig::PV_NGHTTP3
      PARENT_SCOPE)
endfunction()
