#include "Ip_Capture.h"
#include "Tcp_Capture.h"
#include "Udp_Capture.h"
#include "Icmp_Capture.h"
void ip_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header,
                                       const u_char *packet_content) {
    struct ip_header *ip_protocol;
    u_int header_length;
    u_int offset;
    u_char tos;
    u_int16_t checksum;
    //To get ip data, ignore ehternet head
    ip_protocol = (struct ip_header *)(packet_content + 14);
    checksum = ntohs(ip_protocol->ip_checksum);
    header_length = ip_protocol->ip_header_length * 4;
    tos = ip_protocol->ip_tos;
    offset = ntohs(ip_protocol->ip_off);
    printf("---------- IP Protocol (Network Layer) ----------\n");
    printf("IP Version: %d\n", ip_protocol->ip_version);
    printf("Header length: %d\n", header_length);
    printf("TOS: %d\n", tos);
    printf("Total length: %d\n", ntohs(ip_protocol->ip_length));
    printf("Identification: %d\n", ntohs(ip_protocol->ip_id));
    printf("Offset: %d\n", (offset & 0x1fff) * 8);
    printf("TTL: %d\n", ip_protocol->ip_ttl);
    printf("Protocol: %d\n", ip_protocol->ip_protocol);
    printf("Header checksum: %d\n", checksum);
    printf("Source address: %s\n", inet_ntoa(ip_protocol->ip_source_address));
    printf("Destination address: %s\n", inet_ntoa(ip_protocol->ip_destination_address));
    switch (ip_protocol->ip_protocol) {
        case 6: 
            printf("The Transport Layer Protocol is TCP\n");
            tcp_protocol_packet_callback(argument, packet_header, packet_content);
            break;
        case 17: 
            printf("The Transport Layer Protocol is UDP\n");
            udp_protocol_packet_callback(argument, packet_header, packet_content);
            break;
        case 1: 
            printf("The Transport Layer Protocol is ICMP\n");
            icmp_protocol_packet_callback(argument, packet_header, packet_content);
            break;
        default: 
            break;
    }
}



