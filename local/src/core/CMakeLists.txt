cmake_minimum_required(VERSION 3.12)

project(verifier-core)
set(CMAKE_CXX_STANDARD 17)
include(GNUInstallDirs)

find_package(OpenSSL REQUIRED)

add_library(verifier-core STATIC
    ArgParser.cc
    ProxyVerifier.cc
    Localizer.cc
    YamlParser.cc
)

target_include_directories(verifier-core PUBLIC)
target_link_libraries(verifier-core PUBLIC PkgConfig::libswoc++ PkgConfig::yaml-cpp)

install(TARGETS verifier-core ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(TARGETS verifier-core
    EXPORT verifier-core-config
    ARCHIVE DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
install(EXPORT verifier-core-config
    NAMESPACE verifier-core::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/verifier-core
    )
export(TARGETS verifier-core FILE verifier-core-config.cmake)
