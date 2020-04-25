cmake_minimum_required(VERSION 3.16)
project(Capture C)

set(CMAKE_C_STANDARD 99)

link_libraries(pcap)
link_libraries(ccl)

add_executable(Tcp_Capture Capture.c Ethernet_Cap.h Ethernet_Cap.c Ip_Capture.h Ip_Capture.c Tcp_Capture.c Tcp_Capture.h
        Udp_Capture.c Udp_Capture.h Icmp_Capture.c Icmp_Capture.h Arp_Capture.c Arp_Capture.h)
add_executable(File Save_File.c Save_File.h)
add_executable(test Configure.c Configure.h)
