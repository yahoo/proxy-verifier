cmake_minimum_required(VERSION 3.12)

project(verifier-server)
set(CMAKE_CXX_STANDARD 17)
include(GNUInstallDirs)
set(CMAKE_CXX_FLAGS_DEBUG "-g")

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_executable(verifier-server
    verifier-server.cc
)

target_link_libraries(verifier-server PUBLIC verifier-core ${CMAKE_INSTALL_LIBDIR}/libyaml-cpp.a Threads::Threads OpenSSL::SSL OpenSSL::Crypto PkgConfig::libnghttp2)

message("server bindir ${CMAKE_INSTALL_BINDIR}")
install(TARGETS verifier-server RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(TARGETS verifier-server
    EXPORT verifier-server-config
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
install(EXPORT verifier-server-config
    NAMESPACE verifier-server::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/verifier-server
    )
export(TARGETS verifier-server FILE verifier-server-config.cmake)
