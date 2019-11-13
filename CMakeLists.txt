project(NoRTEthernetProxy)

add_executable(nort_eth_proxy main.c)
target_link_libraries(nort_eth_proxy pthread)