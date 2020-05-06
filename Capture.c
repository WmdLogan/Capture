#include "Capture.h"


void capture_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content) {
    //Ethernet
    u_short ethernet_type;
    struct ether_header *ethernet_protocol;
    printf("\n\n\n------------------*****------------------\n");
    printf("---------- Ethernet protocol (Link Layer) ----------\n");
    printf("The %d Ethernet packet is captured.\n", packet_number);
    //get ethernet protocol data
    ethernet_protocol = (struct ether_header *) packet_content;
    //get type
    ethernet_type = ntohs(ethernet_protocol->ether_type);
    if (ethernet_type == 0x0800) {
        printf("---------- IP Protocol (Network Layer) ----------\n");
        struct ip_header *ip_protocol;
        ip_protocol = (struct ip_header *) (packet_content + 14);
        printf("Source address: %s\n", inet_ntoa(ip_protocol->ip_source_address));
        printf("Destination address: %s\n", inet_ntoa(ip_protocol->ip_destination_address));
        //filter ip address
        if ((strcmp(inet_ntoa(ip_protocol->ip_source_address), src_add) == 0 || strcmp(src_add, "") == 0) &&
            (strcmp(inet_ntoa(ip_protocol->ip_destination_address), des_add) == 0 || strcmp(des_add, "") == 0)) {
            printf("IP Qualified!!!!!\n");
            tcp_protocol_packet_callback(argument, packet_header, packet_content);
        }
/*            switch (ip_protocol->ip_protocol) {
                case 6:
                    printf("The Transport Layer Protocol is TCP\n");
                    tcp_protocol_packet_callback(argument, packet_header, packet_content);
                    break;
                case 17:
                    printf("The Transport Layer Protocol is UDP\n");
                    udp_protocol_packet_callback(argument, packet_header, packet_content);
                    break;
                default:
                    break;
            }*/

    }
    printf("------------------*****------------------\n");
    packet_number++;
}