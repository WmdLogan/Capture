#include <stdlib.h>
#include "Configure.h"
#include "Capture.h"
#include "string.h"

void tcp_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header,
                                  const u_char *packet_content) {
    struct tcp_header *tcp_protocol;
//    u_char flags;
//    int header_length;
    u_short source_port;
    u_short destination_port;
//    u_short windows;
//    u_short urgent_pointer;
//    u_int sequence;
//    u_int acknowledgement;
//    u_int16_t checksum;
    //ignore ethernet_head and ip_head
    tcp_protocol = (struct tcp_header *) (packet_content + 14 + 20);
    source_port = ntohs(tcp_protocol->tcp_source_port);
    destination_port = ntohs(tcp_protocol->tcp_destination_port);
//    header_length = tcp_protocol->tcp_offset * 4;
//    sequence = ntohl(tcp_protocol->tcp_acknowledgement);
//    acknowledgement = ntohl(tcp_protocol->tcp_ack);
//    windows = ntohs(tcp_protocol->tcp_windows);
//    urgent_pointer = ntohs(tcp_protocol->tcp_urgent_pointer);
//    flags = tcp_protocol->tcp_flags;
//    checksum = ntohs(tcp_protocol->tcp_checksum);
    printf("---------- TCP Protocol (Transport Layer) ----------\n");
    printf("Source Port: %d\n", source_port);
    printf("Destination Port: %d\n", destination_port);
//    printf("Sequence Number: %u\n", sequence);
//    printf("Acknowledgement Number: %u\n", acknowledgement);
//    printf("Header Length: %d\n", header_length);
//    printf("Reserved: %d\n", tcp_protocol->tcp_reserved);
//    printf("Sequence Number: %u\n", sequence);
//    printf("Flags: ");
//    if(flags & 0x08) printf("PSH ");
//    if(flags & 0x10) printf("ACK ");
//    if(flags & 0x02) printf("SYN ");
//    if(flags & 0x20) printf("URG ");
//    if(flags & 0x01) printf("FIN ");
//    if(flags & 0x04) printf("RST ");
//    printf("\nWindows Size: %d\n", windows);
//    printf("Checksum: %d\n", checksum);
//    printf("Urgent pointer: %d\n", urgent_pointer);

// filter port
    if ((ntohs(tcp_protocol->tcp_source_port) == atoi(s_port) || strcmp(s_port, "") == 0) &&
        (ntohs(tcp_protocol->tcp_source_port) == atoi(d_port) || strcmp(des_add, "") == 0)) {
        printf("Port Qualified!!!!!\n");
/*
        */
/*open pcap write output file*//*

//        pcap_dumper_t *out_pcap;
//        out_pcap = pcap_dump_open(pcap_handle, "/home/logan/pack.cap");
        pcap_dump((u_char *) out_pcap, packet_header, packet_content);
        printf("Received Packet Size: %d\n", packet_header->len);
        file_size += packet_header->len;
        if ( (buf2.st_size + packet_header->len + 16) < 800) {
            pcap_dump_flush(out_pcap);

        }
        */
/*flush buff*//*

        printf("file_size = %d\n", file_size);
        stat("/home/logan/pack.cap", &buf2);
        printf("文件size: %ld\n", buf2.st_size);
       // pcap_dump_close(out_pcap);

*/

    }
}