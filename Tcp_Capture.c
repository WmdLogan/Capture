#include <stdlib.h>
#include "Configure.h"
#include "Capture.h"
#include "string.h"

void tcp_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header,const u_char *packet_content) {
    struct tcp_header *tcp_protocol;
    u_short source_port;
    u_short destination_port;
//get port
    tcp_protocol = (struct tcp_header *) (packet_content + 14 + 20);
    source_port = ntohs(tcp_protocol->tcp_source_port);
    destination_port = ntohs(tcp_protocol->tcp_destination_port);

    printf("---------- TCP Protocol (Transport Layer) ----------\n");
    printf("Source Port: %d\n", source_port);
    printf("Destination Port: %d\n", destination_port);
//filter port
    if ((ntohs(tcp_protocol->tcp_source_port) == atoi(s_port) || strcmp(s_port, "") == 0) &&
        (ntohs(tcp_protocol->tcp_source_port) == atoi(d_port) || strcmp(des_add, "") == 0)) {
        printf("Port Qualified!!!!!\n");

//Qualified , start saving
//open first file
        if (first_file_flag == 0) {
            out_pcap = pcap_dump_open(pcap_handle, final_path);
//获得文件修改时间
            stat(final_path, &cap_buf);
            printf("文件修改时间: %ld\n", cap_buf.st_ctime);
            first_file_flag++;
        }
//calculate file size
        printf("Received Packet Size: %d\n", packet_header->len);
        current_size += packet_header->len + 16;
        printf("current size is = %d\n", current_size);
//if file size and file time qualified , dump
        if (current_size < atoi(file_size) && time(&rawtime) - cap_buf.st_ctime < file_time) {
            pcap_dump((u_char *) out_pcap, packet_header, packet_content);
            pcap_dump_flush(out_pcap);
        }
//size full or time out, open new file
        else {
            printf("new file or out of date!!!!! \n");
            next_file++;
            pcap_dump_close(out_pcap);
//set new file path and file name
            sprintf(final_path, "%s%s", path, "pcap");
            sprintf(final_path, "%s%d", final_path, next_file);
            sprintf(final_path, "%s%s", final_path, ".cap");
            printf("all path is:%s\n", final_path);
//open new file
            out_pcap = pcap_dump_open(pcap_handle, final_path);
            pcap_dump((u_char *) out_pcap, packet_header, packet_content);
            pcap_dump_flush(out_pcap);
//获得文件修改时间
            stat(final_path, &cap_buf);
            printf("文件修改时间: %ld\n", cap_buf.st_ctime);
            current_size = packet_header->len + 24;
        }
    }
}