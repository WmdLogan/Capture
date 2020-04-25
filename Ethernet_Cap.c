#include "pcap.h"
#include "Ethernet_Cap.h"
#include "Ip_Capture.h"
#include "Udp_Capture.h"
#include "Icmp_Capture.h"

void ethernet_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header,
                                       const u_char *packet_content) {
     printf("Received Packet Size: %d\n", packet_header->len);
     printf("Received Packet Content: %hhu\n", *packet_content);
     u_short ethernet_type;
     struct ether_header *ethernet_protocol;
     u_char *mac_string;
     static int packet_number = 1;
     printf("\n\n\n\n------------------*****------------------\n");
     printf("---------- Ethernet protocol (Link Layer) ----------\n");
     printf("The %d Ethernet packet is captured.\n", packet_number);
     //get ethernet protocol data
     ethernet_protocol = (struct ether_header *) packet_content;
     //get type
     ethernet_type = ntohs(ethernet_protocol->ether_type);
     printf("Ethernet type is:  %04x\n", ethernet_type);

     printf("Mac Source Address is : \n");
     mac_string = ethernet_protocol->ether_shost;
     printf("%02x: %02x: %02x: %02x: %02x: %02x: \n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3),
            *(mac_string + 4), *(mac_string + 5));

     printf("Mac Destination Address is :  \n");
     mac_string = ethernet_protocol->ether_dhost;
     printf("%02x: %02x: %02x: %02x: %02x: %02x: \n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3),
            *(mac_string + 4), *(mac_string + 5));

     switch (ethernet_type) {
         case 0x0800:
             printf("The Network Layer is IP Protocol\n");
             ip_protocol_packet_callback(argument, packet_header, packet_content);
             break;
         case 0x0806:
             printf("The Network Layer is ARP Protocol\n");
             udp_protocol_packet_callback(argument, packet_header, packet_content);
             break;
         case 0x8035:
             printf("The Network Layer is RARP Protocol\n");
             icmp_protocol_packet_callback(argument, packet_header, packet_content);
             break;
         default:
             break;
     }
     printf("------------------*****------------------\n");
     packet_number++;
}

