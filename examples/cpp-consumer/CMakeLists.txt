cmake_minimum_required(VERSION 3.22)
project(resd_net_cpp_consumer CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(RESD_NET_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(RESD_NET_INCLUDE "${RESD_NET_ROOT}/include")
set(RESD_NET_PROFILE "release" CACHE STRING "cargo profile to link")
set(RESD_NET_LIB "${RESD_NET_ROOT}/target/${RESD_NET_PROFILE}/libresd_net.a")

find_package(PkgConfig REQUIRED)
pkg_check_modules(DPDK REQUIRED libdpdk)

add_executable(cpp_consumer main.cpp)
target_include_directories(cpp_consumer PRIVATE "${RESD_NET_INCLUDE}" ${DPDK_INCLUDE_DIRS})
target_link_libraries(cpp_consumer PRIVATE
    "${RESD_NET_LIB}"
    ${DPDK_LIBRARIES}
    pthread
    dl
    m
)
target_compile_options(cpp_consumer PRIVATE -Wall -Wextra -Werror)
