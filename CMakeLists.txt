cmake_minimum_required(VERSION 3.13)
project(NoRTEthernetProxy)

add_executable(nort_eth_proxy main.c)
target_link_libraries(nort_eth_proxy pthread)

install(TARGETS nort_eth_proxy DESTINATION bin)

