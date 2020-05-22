#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<netinet/in.h>
#include "pcap.h"
#include <dirent.h>
#include <unistd.h>

struct ether_header {
    u_int8_t ether_dhost[6]; //des ether
    u_int8_t ether_shost[6];//src ether
    u_int16_t ether_type;//ether type
};

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
    u_int i_ip_source_address;
    struct in_addr ip_destination_address;
    u_int i_ip_destination_address;
};
struct tcp_header {
    u_int16_t tcp_source_port;
    u_int16_t tcp_destination_port;
    u_int32_t tcp_acknowledgement; //seq
    u_int32_t tcp_ack; //ack
#ifdef WORDS_BIGENDDIAN
    u_int8_t tcp_offset:4, tcp_reserved:4;
#else
    u_int8_t tcp_reserved: 4, tcp_offset: 4;
#endif
    u_int8_t tcp_flags;
    u_int16_t tcp_windows;
    u_int16_t tcp_checksum;
    u_int16_t tcp_urgent_pointer;
};

struct udp_header {
    u_int16_t udp_source_port;
    u_int16_t udp_destination_port;
    u_int16_t udp_length;
    u_int16_t udp_checksum;
};
int packet_number = 1;
pcap_dumper_t *out_pcap;

void merge_file(char merged_path[], char file_path[]) {
    FILE *merged;
    FILE *fp;
//写入的文件
    if ((fp = fopen(file_path, "r")) == NULL) {
        printf("error: can not open pcap file\n");
        exit(0);
    }
    fseek(fp, 24, SEEK_SET);
//被写入的文件
    if ((merged = fopen(merged_path, "a+")) == NULL) {
        exit(0);
    }

//merge file
    char ch;
    while ((ch = fgetc(fp)) != EOF) {
        fputc(ch, merged);
    }
    fclose(merged);
    fclose(fp);
    printf("merge complete!\n");
}

void analysis(u_char *argument, struct pcap_pkthdr *packet_header, u_char *packet_content) {
    printf("Analysis packet %d!\n", packet_number);
    printf("time: %ld\n", packet_header->ts.tv_sec);
    packet_header->ts.tv_sec += 10;
    printf("time: %ld\n", packet_header->ts.tv_sec);
    pcap_dump((u_char *) out_pcap, packet_header, packet_content);
    pcap_dump_flush(out_pcap);
    packet_number++;
}

int main() {
    char *final_path;//拼成文件名
    final_path = (char *) malloc(sizeof(char) * 30);
    int count = 0;
    int loc;
    pcap_t *pcap_handle;
    char error_content[PCAP_ERRBUF_SIZE];
    struct bpf_program bpf_filter;
    char bpf_filter_string[] = "";
//    char bpf_filter_string[] = " ";
    bpf_u_int32 net_ip;
/*    pcap_handle = pcap_open_offline("/home/packets/bpcap1.cap", error_content);
    pcap_compile(pcap_handle, &bpf_filter, bpf_filter_string, 0, net_ip);
    pcap_setfilter(pcap_handle, &bpf_filter);

    out_pcap = pcap_dump_open(pcap_handle, "/home/change.cap");

    pcap_loop(pcap_handle, -1, analysis, NULL);
    pcap_close(pcap_handle);*/
    while (1) {
        loc = 0;
//10 seconds filter once
        sleep(10);
        DIR *pDir;
        struct dirent *ent;
        pDir = opendir("/home/packets");
        while ((ent = readdir(pDir)) != NULL) {
            if (ent->d_type & DT_DIR) {
                if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
                    continue;
            } else {
                loc++;
                if (loc <= count) {
                    continue;
                }
                count++;
                sprintf(final_path, "%s%s", "/home/packets/", ent->d_name);
                printf("analysing :%s\n", final_path);

                pcap_handle = pcap_open_offline(final_path, error_content);
                pcap_compile(pcap_handle, &bpf_filter, bpf_filter_string, 0, net_ip);
                pcap_setfilter(pcap_handle, &bpf_filter);

                out_pcap = pcap_dump_open(pcap_handle, final_path);
                pcap_loop(pcap_handle, -1, analysis, NULL);
                pcap_close(pcap_handle);
            }
        }
    }
    return 0;
}
