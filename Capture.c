#include "Capture.h"
#include "Ethernet_Cap.h"
#include "Ip_Capture.h"
#include "Arp_Capture.h"
#include "Tcp_Capture.h"
#include "Udp_Capture.h"
#include "Icmp_Capture.h"
#include "Configure.h"
#include "string.h"


void capture_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content) {
    //check configure update
    stat("/home/logan/CLionProjects/Capture/mytest.conf", &buf1);
    printf("\n\n\n\ncall_back :文件修改时间: %ld\n", buf1.st_ctime);
    if (buf1.st_mtime != update_time) {
        printf("config update!!!\n");
        struct ccl_t re = configure();
        const struct ccl_pair_t *iter;
        update_time = buf1.st_mtime;
        while ((iter = ccl_iterate(&re)) != 0) {
            if (strcmp(iter->key, "source_address") == 0) {
                strcpy(src_add, iter->value);
            } else if (strcmp(iter->key, "destination_address") == 0) {
                strcpy(des_add, iter->value);
            } else if (strcmp(iter->key, "source_port") == 0) {
                strcpy(s_port, iter->value);
            } else if (strcmp(iter->key, "destination_port") == 0) {
                strcpy(d_port, iter->value);
            }
        }
    }
    printf("s_add:%s\n", src_add);
    printf("d_add:%s\n", des_add);
    printf("s_port:%s\n", s_port);
    printf("d_port:%s\n", d_port);
    //Ethernet
    u_short ethernet_type;
    struct ether_header *ethernet_protocol;
    static int packet_number = 1;
    printf("------------------*****------------------\n");
    printf("---------- Ethernet protocol (Link Layer) ----------\n");
    printf("The %d Ethernet packet is captured.\n", packet_number);
    //get ethernet protocol data
    ethernet_protocol = (struct ether_header *) packet_content;
    //get type
    ethernet_type = ntohs(ethernet_protocol->ether_type);
    switch (ethernet_type) {
        case 0x0800:
            printf("---------- IP Protocol (Network Layer) ----------\n");
            struct ip_header *ip_protocol;
            ip_protocol = (struct ip_header *) (packet_content + 14);
            printf("Source address: %s\n", inet_ntoa(ip_protocol->ip_source_address));
            printf("Destination address: %s\n", inet_ntoa(ip_protocol->ip_destination_address));
            //filter ip address
            if ((strcmp(inet_ntoa(ip_protocol->ip_source_address), src_add) == 0 || strcmp(src_add, "") == 0) &&
                (strcmp(inet_ntoa(ip_protocol->ip_destination_address), des_add) == 0 || strcmp(des_add, "") == 0) ) {
                printf("IP Qualified!!!!!\n");
                tcp_protocol_packet_callback(argument, packet_header, packet_content);
            } else {
                break;
            }
//            switch (ip_protocol->ip_protocol) {
//                case 6:
//                    printf("The Transport Layer Protocol is TCP\n");
//                    tcp_protocol_packet_callback(argument, packet_header, packet_content);
//                    break;
//                case 17:
//                    printf("The Transport Layer Protocol is UDP\n");
//                    udp_protocol_packet_callback(argument, packet_header, packet_content);
//                    break;
//                case 1:
//                    printf("The Transport Layer Protocol is ICMP\n");
//                    icmp_protocol_packet_callback(argument, packet_header, packet_content);
//                    break;
//                default:
//                    break;
//            }
            break;
        case 0x0806:
            printf("The Network Layer is ARP Protocol\n");
            //          arp_protocol_packet_callback(argument, packet_header, packet_content);
            break;
        case 0x8035:
            printf("The Network Layer is RARP Protocol\n");
            break;
        default:
            break;
    }
    printf("------------------*****------------------\n");
    packet_number++;

}