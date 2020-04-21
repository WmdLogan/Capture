#include "pcap.h"
#include "Ip_Capture.h"

struct ether_header {
    u_int8_t ether_dhost[6]; //des ether
    u_int8_t ether_shost[6];//src ether
    u_int16_t ether_type;//ether type
};

typedef uint32_t in_addr_t;

struct ip_header {
#ifdef WORDS_BEGINDIAN
    u_int8_t    ip_version:4,
                ip_header_length:4;
#else
    u_int8_t ip_header_length: 4,
            ip_version: 4;
#endif
    u_int8_t ip_tos;
    u_int16_t ip_length;
    u_int16_t ip_id;
    u_int16_t ip_off;
    u_int8_t ip_ttl;
    u_int8_t ip_protocol;
    u_int16_t ip_checksum;
    struct in_addr ip_source_address;
    struct in_addr ip_destination_address;
};

void ip_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header,
                                       const u_char *packet_content) {
    struct ip_header *ip_protocol;
    u_int header_length;
    u_int offset;
    u_char tos;
    u_int16_t checksum;
    //To get ip data, ignore ehternet head
    ip_protocol = (struct ip_header *)(packet_content + 14);
    checksum = ntohs(ip_protocol->ip_off);
    header_length = ip_protocol->ip_header_length * 4;
    tos = ip_protocol->ip_tos;
    offset = ntohs(ip_protocol->ip_off);
    printf("------------IP Protocol (Network Layer)------------\n");
    printf("IP Version:%d\n", ip_protocol->ip_version);
    printf("Header length:%d\n", header_length);
    printf("TOS:%d\n", tos);
    printf("Total length:%d\n", ntohs(ip_protocol->ip_length));
    printf("Indentification:%d\n", ntohs(ip_protocol->ip_id));
    printf("Offset:%d\n", (offset & 0x1fff) * 8);
    printf("TTL:%d\n", ip_protocol->ip_ttl);
    printf("Protocol:%d\n", ip_protocol->ip_protocol);

    switch (ip_protocol->ip_protocol) {
        case 6:
            printf("The Transport Layer Protocol is TCP\n");
            break;
        case 17:
            printf("The Transport Layer Protocol is UDP\n");
            break;
        case 1:
            printf("The Transport Layer Protocol is ICMP\n");
            break;
        default:
            break;
    }
    printf("Header checksum:%d\n", checksum);
    printf("Source address:%s\n", inet_ntoa(ip_protocol->ip_source_address));
    printf("Destination address:%s\n", inet_ntoa(ip_protocol->ip_destination_address));
}



