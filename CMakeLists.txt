cmake_minimum_required(VERSION 4.2.3)

if(APPLE)
  if(NOT DEFINED CMAKE_C_COMPILER)
    execute_process(
      COMMAND xcrun -find clang
      OUTPUT_VARIABLE _pv_apple_cc
      OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(_pv_apple_cc)
      set(CMAKE_C_COMPILER
          "${_pv_apple_cc}"
          CACHE FILEPATH "Apple clang selected by Proxy Verifier." FORCE)
    endif()
  endif()

  if(NOT DEFINED CMAKE_CXX_COMPILER)
    execute_process(
      COMMAND xcrun -find clang++
      OUTPUT_VARIABLE _pv_apple_cxx
      OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(_pv_apple_cxx)
      set(CMAKE_CXX_COMPILER
          "${_pv_apple_cxx}"
          CACHE FILEPATH "Apple clang++ selected by Proxy Verifier." FORCE)
    endif()
  endif()

  if(NOT DEFINED CMAKE_OSX_SYSROOT)
    execute_process(
      COMMAND xcrun --show-sdk-path
      OUTPUT_VARIABLE _pv_sdkroot
      OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(_pv_sdkroot)
      set(CMAKE_OSX_SYSROOT
          "${_pv_sdkroot}"
          CACHE PATH "Apple SDKROOT selected by Proxy Verifier." FORCE)
    endif()
  endif()
endif()

project(
  ProxyVerifier
  VERSION 2.12.1
  LANGUAGES C CXX)

include(CTest)
include(GNUInstallDirs)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set(CMAKE_INSTALL_PREFIX
      "/usr/local"
      CACHE PATH "Install path prefix, prepended onto install directories."
            FORCE)
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

option(
  PV_BOOTSTRAP_DEPS
  "Fetch and build external QUIC/TLS dependencies as part of the CMake build."
  OFF)
option(PV_STATIC_BUILD
       "Link the verifier binaries with static third-party dependencies." OFF)
option(PV_ENABLE_ASAN
       "Build the verifier binaries with AddressSanitizer instrumentation." OFF)
option(PV_RELEASE_LAYOUT
       "Install release artifacts into a platform-specific bindir." OFF)

set(PV_DEPS_ROOT
    ""
    CACHE
      PATH
      "Common dependency root containing openssl/nghttp2/ngtcp2/nghttp3 subdirectories."
)
set(PV_OPENSSL_ROOT
    ""
    CACHE PATH "Explicit OpenSSL root.")
set(PV_NGHTTP2_ROOT
    ""
    CACHE PATH "Explicit nghttp2 root.")
set(PV_NGTCP2_ROOT
    ""
    CACHE PATH "Explicit ngtcp2 root.")
set(PV_NGHTTP3_ROOT
    ""
    CACHE PATH "Explicit nghttp3 root.")
set(PV_RELEASE_TARGET
    ""
    CACHE STRING
          "Release artifact target name such as linux-amd64 or darwin-arm64.")

function(pv_detect_release_target out_var)
  string(TOLOWER "${CMAKE_SYSTEM_NAME}" _pv_release_os)
  if(_pv_release_os STREQUAL "linux")
    set(_pv_release_os "linux")
  elseif(_pv_release_os STREQUAL "darwin")
    set(_pv_release_os "darwin")
  else()
    message(
      FATAL_ERROR
        "Unsupported release platform \"${CMAKE_SYSTEM_NAME}\" for PV_RELEASE_LAYOUT."
    )
  endif()

  string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" _pv_release_arch)
  if(_pv_release_arch MATCHES "^(x86_64|amd64)$")
    set(_pv_release_arch "amd64")
  elseif(_pv_release_arch MATCHES "^(aarch64|arm64)$")
    set(_pv_release_arch "arm64")
  else()
    message(
      FATAL_ERROR
        "Unsupported release architecture \"${CMAKE_SYSTEM_PROCESSOR}\" for PV_RELEASE_LAYOUT."
    )
  endif()

  set(${out_var}
      "${_pv_release_os}-${_pv_release_arch}"
      PARENT_SCOPE)
endfunction()

if(PV_ENABLE_ASAN AND PV_STATIC_BUILD)
  message(
    FATAL_ERROR
      "PV_ENABLE_ASAN and PV_STATIC_BUILD cannot both be enabled in this build."
  )
endif()

if(PV_RELEASE_LAYOUT)
  pv_detect_release_target(_pv_detected_release_target)

  if(CMAKE_INSTALL_PREFIX STREQUAL "/tmp")
    set(CMAKE_INSTALL_PREFIX
        "/tmp/proxy-verifier-v${PROJECT_VERSION}"
        CACHE PATH "Install path prefix, prepended onto install directories."
              FORCE)
  endif()

  if(NOT PV_RELEASE_TARGET)
    set(PV_RELEASE_TARGET
        "${_pv_detected_release_target}"
        CACHE
          STRING
          "Release artifact target name such as linux-amd64 or darwin-arm64."
          FORCE)
  elseif(NOT PV_RELEASE_TARGET STREQUAL _pv_detected_release_target)
    message(
      FATAL_ERROR
        "PV_RELEASE_TARGET=\"${PV_RELEASE_TARGET}\" does not match the current build target "
        "\"${_pv_detected_release_target}\". Release presets are native-only unless you provide "
        "an explicit cross-compilation toolchain.")
  endif()

  set(CMAKE_INSTALL_BINDIR
      "${PV_RELEASE_TARGET}"
      CACHE STRING "Install directory for runtime targets." FORCE)
endif()

include(PVFetchDependencies)
pv_fetch_dependencies()

include(HttpDependencies)
pv_define_http_dependencies(
  OUT_LIBRARIES
  PV_EXTERNAL_DEPENDENCY_TARGETS
  OUT_RPATH_DIRS
  PV_EXTERNAL_RPATH_DIRS
  OUT_BOOTSTRAP_TARGETS
  PV_BOOTSTRAP_TARGETS
  OUT_BOOTSTRAP_PREFIX
  PV_BOOTSTRAP_PREFIX)

add_subdirectory(src)
add_subdirectory(tests/autests)
add_subdirectory(tests/unit_tests)
