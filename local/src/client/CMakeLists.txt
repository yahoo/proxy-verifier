cmake_minimum_required(VERSION 3.12)

project(verifier-client)
set(CMAKE_CXX_STANDARD 17)
include(GNUInstallDirs)

set(CMAKE_CXX_FLAGS_DEBUG "-g")

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_executable(verifier-client
    verifier-client.cc
)

target_link_libraries(verifier-client PUBLIC verifier-core ${CMAKE_INSTALL_LIBDIR}/libyaml-cpp.a Threads::Threads OpenSSL::SSL OpenSSL::Crypto PkgConfig::libnghttp2)

install(TARGETS verifier-client RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
message("client bindir ${CMAKE_INSTALL_BINDIR}")
install(TARGETS verifier-client
    EXPORT verifier-client-config
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
install(EXPORT verifier-client-config
    NAMESPACE verifier-clientl::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/verifier-client
    )
export(TARGETS verifier-client FILE verifier-client-config.cmake)
