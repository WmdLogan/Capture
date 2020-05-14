#include "hash.h"

void capture_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content) {
    bpf_u_int32 len = packet_header->len;
    struct ether_header *ethernet_protocol;
    struct udp_header *udp_protocol;
    struct tcp_header *tcp_protocol;
    struct ip_header *ip_protocol;
    u_short source_port;
    u_short destination_port;
    printf("\n\n\nThe %d Ethernet packet is captured.\n", packet_number);
//只要IP协议的包
    ethernet_protocol = (struct ether_header *) packet_content;
    if (ntohs(ethernet_protocol->ether_type) == 0x0800) {
        ip_protocol = (struct ip_header *) (packet_content + 14);
        printf("Source address: %s\n", inet_ntoa(ip_protocol->ip_source_address));
        printf("Destination address: %s\n", inet_ntoa(ip_protocol->ip_destination_address));
//过滤IP地址
        if ((strcmp(inet_ntoa(ip_protocol->ip_source_address), src_add) == 0 || strcmp(src_add, "") == 0) &&
            (strcmp(inet_ntoa(ip_protocol->ip_destination_address), des_add) == 0 || strcmp(des_add, "") == 0))
//如果IP符合，获取端口
        {
            printf("IP Qualified!!!!!\n");
            switch (ip_protocol->ip_protocol) {
                case 6:
                    printf("---------- TCP Protocol (Transport Layer) ----------\n");
                    tcp_protocol = (struct tcp_header *) (packet_content + 14 + 20);
                    source_port = ntohs(tcp_protocol->tcp_source_port);
                    destination_port = ntohs(tcp_protocol->tcp_destination_port);
                    printf("Source Port: %d\n", source_port);
                    printf("Destination Port: %d\n", destination_port);
                    break;
                case 17:
                    printf("---------- UDP Protocol (Transport Layer) ----------\n");
                    udp_protocol = (struct udp_header *) (packet_content + 14 + 20);
                    source_port = ntohs(udp_protocol->udp_source_port);
                    destination_port = ntohs(udp_protocol->udp_destination_port);
                    printf("Source Port: %d\n", source_port);
                    printf("Destination Port: %d\n", destination_port);
                    break;
                default:
                    break;
            }
//过滤端口
            if ((source_port == atoi(s_port) || strcmp(s_port, "") == 0) &&
                (destination_port == atoi(d_port) || strcmp(d_port, "") == 0))
//如果端口符合，开始保存
            {
                printf("Port Qualified!!!!!\n");
//插入哈希表
                insert_hash(packet_content, TCAP_hash, len);
//标志位为0，创建第一个文件，开始记录时间
                if (first_file_flag == 0) {
                    out_pcap = pcap_dump_open(pcap_handle, final_path);
                    stat(final_path, &cap_buf);
                    printf("new file time: %ld\n", cap_buf.st_ctime);
                    first_file_flag++;
                }
//计算如果保存这个包，文件的大小
                printf("Received Packet Size: %d\n", packet_header->len);
                current_size += packet_header->len + 16;
                printf("current size is = %d\n", current_size);
//如果文件大小、时间，如果符合，保存
                if (current_size < atoi(file_size) && time(&rawtime) - cap_buf.st_ctime < file_time) {
                    pcap_dump((u_char *) out_pcap, packet_header, packet_content);
                    pcap_dump_flush(out_pcap);
                }
//如果大小超了，或者超时了。打开新文件保存
                else {
                    printf("too large or out of date!!!!! \n");
                    next_file++;
                    pcap_dump_close(out_pcap);
//设置新的文件保存路径和文件名
                    sprintf(final_path, "%s%s", path, "pcap");
                    sprintf(final_path, "%s%d", final_path, next_file);
                    sprintf(final_path, "%s%s", final_path, ".cap");
                    printf("all path is:%s\n", final_path);
//打开新文件并保存这个包的数据
                    out_pcap = pcap_dump_open(pcap_handle, final_path);
                    pcap_dump((u_char *) out_pcap, packet_header, packet_content);
                    pcap_dump_flush(out_pcap);
//开始记录修改时间
                    stat(final_path, &cap_buf);
                    printf("new file time: %ld\n", cap_buf.st_ctime);
                    current_size = packet_header->len + 40;
                }
            }
        }
    }
    packet_number++;
}