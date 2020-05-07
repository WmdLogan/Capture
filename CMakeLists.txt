cmake_minimum_required(VERSION 3.16)
project(Capture C)

set(CMAKE_C_STANDARD 99)

link_libraries(pcap)
link_libraries(ccl)
link_libraries(pthread)

add_executable(Tcp_Capture  main.c Ethernet_Cap.c Ip_Capture.c Tcp_Capture.c Udp_Capture.c Icmp_Capture.c Arp_Capture.c Configure.c)
add_executable(File Save_File.c)
add_executable(test Configure.c)
add_executable(get_time Get_Update_Time.c)
add_executable(Cap main.c Capture Capture.c Configure.c Tcp_Capture.c Udp_Capture.c check_update.c)
add_executable(check check_update.c Include/Capture.h Configure.c)
add_executable(separate separate_check.c Configure.c)

include_directories(Include)