set(PV_COMMON_WARNING_FLAGS -Wall -Wextra -Werror)

set(PV_CORE_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/core/ArgParser.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/core/http.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/core/http2.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/core/http3.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/core/https.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/core/Localizer.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/core/ProxyVerifier.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/core/proxy_protocol_util.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/core/verification.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/core/YamlParser.cc")

find_package(Threads REQUIRED)

add_library(verifier-core STATIC ${PV_CORE_SOURCES})

target_compile_options(verifier-core PRIVATE ${PV_COMMON_WARNING_FLAGS})
target_compile_definitions(verifier-core
                           PUBLIC PROXY_VERIFIER_VERSION=\"${PROJECT_VERSION}\")
target_include_directories(verifier-core PUBLIC "${PROJECT_SOURCE_DIR}/src")
target_link_libraries(
  verifier-core PUBLIC Threads::Threads libswoc-static yaml-cpp::yaml-cpp
                       ${PV_EXTERNAL_DEPENDENCY_TARGETS})

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  target_link_libraries(verifier-core PUBLIC stdc++fs)
endif()

if(PV_ENABLE_ASAN)
  target_compile_options(verifier-core PUBLIC -fsanitize=address
                                              -fno-omit-frame-pointer)
  if(NOT APPLE)
    target_link_options(verifier-core PUBLIC -fsanitize=address -static-libasan)
  else()
    target_link_options(verifier-core PUBLIC -fsanitize=address)
  endif()
endif()

add_executable(verifier-client
               "${CMAKE_CURRENT_SOURCE_DIR}/client/verifier-client.cc")
add_executable(verifier-server
               "${CMAKE_CURRENT_SOURCE_DIR}/server/verifier-server.cc")

target_link_libraries(verifier-client PRIVATE verifier-core)
target_link_libraries(verifier-server PRIVATE verifier-core)
target_compile_options(verifier-client PRIVATE ${PV_COMMON_WARNING_FLAGS})
target_compile_options(verifier-server PRIVATE ${PV_COMMON_WARNING_FLAGS})

if(PV_STATIC_BUILD AND NOT APPLE)
  target_link_options(verifier-client PRIVATE -static)
  target_link_options(verifier-server PRIVATE -static)
  target_link_libraries(verifier-client PRIVATE -Wl,--whole-archive pthread
                                                -Wl,--no-whole-archive dl)
  target_link_libraries(verifier-server PRIVATE -Wl,--whole-archive pthread
                                                -Wl,--no-whole-archive dl)
endif()

if(PV_EXTERNAL_RPATH_DIRS)
  list(JOIN PV_EXTERNAL_RPATH_DIRS ";" _pv_joined_rpath)
  set_target_properties(verifier-client verifier-server
                        PROPERTIES BUILD_RPATH "${_pv_joined_rpath}")
  if(NOT PV_STATIC_BUILD)
    set_target_properties(verifier-client verifier-server
                          PROPERTIES INSTALL_RPATH "${_pv_joined_rpath}")
  endif()
endif()

install(TARGETS verifier-client verifier-server
        RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
