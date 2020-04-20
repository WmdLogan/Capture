cmake_minimum_required(VERSION 3.16)
project(Capture C)

set(CMAKE_C_STANDARD 99)

link_libraries(pcap)

add_executable(get_interface get_interface.c)
add_executable(Capture capture.c)
add_executable(Mul_Cap Mul_Cap.c)
add_executable(Ethernet ethernet.c)
