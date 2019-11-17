cmake_minimum_required(VERSION 3.13)
project(NoRTEthernetProxy)

include(FindPkgConfig)
pkg_search_module(MODBUS REQUIRED libmodbus)

add_executable(nort_eth_proxy main.c)
target_include_directories(nort_eth_proxy PUBLIC ${MODBUS_INCLUDE_DIRS})
target_link_libraries(nort_eth_proxy pthread ${MODBUS_LIBRARIES})
