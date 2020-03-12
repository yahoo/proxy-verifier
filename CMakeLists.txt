project("Proxy Verifier")
cmake_minimum_required(VERSION 3.12)
set(CMAKE_CXX_STANDARD 17)

set(INSTALL_DIR ${CMAKE_HOME_DIRECTORY})
if(NOT DEFINED CMAKE_PREFIX_PATH)
    set(CMAKE_PREFIX_PATH ${INSTALL_DIR})
endif()
set(CMAKE_INSTALL_BINDIR ${CMAKE_PREFIX_PATH}/bin)
set(CMAKE_INSTALL_LIBDIR ${CMAKE_PREFIX_PATH}/lib)

find_package(PkgConfig REQUIRED)
pkg_check_modules(yaml-cpp REQUIRED IMPORTED_TARGET libyaml-cpp)
pkg_check_modules(libswoc++ REQUIRED IMPORTED_TARGET libswoc++-static)
pkg_check_modules(libnghttp2 REQUIRED IMPORTED_TARGET libnghttp2)

add_subdirectory(local)
