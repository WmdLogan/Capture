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
pcap_dumper_t *out_pcap;
//merge file_path after merged_path
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

int packet_number = 0;
pcap_dumper_t *out_pcap;
void analysis(u_char *argument,  struct pcap_pkthdr *packet_header,  u_char *packet_content) {
    printf("Analysis packet %d!\n", packet_number);
    printf("packet length:%d!\n", packet_header->len);
    pcap_dump((u_char *) out_pcap, packet_header, packet_content);
    pcap_dump_flush(out_pcap);
    packet_number++;
}

int main() {
    char bpf_filter_string[1000];
    char exact[30];
//3 piece of wu-yuan-zu
    pid_t pid; //fpid表示fork函数返回的值
    pid = fork();
    if (pid < 0)
        printf("error in fork!");
    else if (pid == 0) {//child
        pid_t pid1; //fpid表示fork函数返回的值
        pid1 = fork();
        if (pid1 < 0)
            printf("error in fork!");
        else if (pid1 == 0) {//child
            strcpy(bpf_filter_string, "src host 192.168.2.101 and dst host 34.211.106.52 and src port 34258 and dst port 443");
            strcpy(exact, "/home/src.cap");
        }
        else {//grandchild
            strcpy(bpf_filter_string, "dst host 192.168.2.101 and src host 34.211.106.52 and dst port 34258 and src port 443");
            strcpy(exact, "/home/dst.cap");
        }
    }
    else {//father
        strcpy(bpf_filter_string, "host 192.168.2.101 and host 34.211.106.52 and tcp port 34258 and port 443");
        strcpy(exact, "/home/all.cap");
    }
//single wu-yuan-zu
/*    strcpy(bpf_filter_string, "host 192.168.2.101");
    strcpy(exact, "/home/test1.cap");*/
    char *final_path;//拼成文件名
    final_path = (char *) malloc(sizeof(char) * 30);
    int count = 0;
    int loc, open_flag = 1;
    pcap_t *pcap_handle;
    char error_content[PCAP_ERRBUF_SIZE];
    struct bpf_program bpf_filter;
    bpf_u_int32 net_ip;
    while (1) {
        loc = 0;
//10 seconds filter once
        sleep(1);
        DIR *pDir;
        struct dirent *ent;
        pDir = opendir("/home/packets");
        while ((ent = readdir(pDir)) != NULL) {
            if (ent->d_type & DT_DIR) {
                if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
                    continue;
            } else {
                loc++;
//filter last time's file
                if (loc <= count) {
                    open_flag = 1;
                    continue;
                }
//new file in this time
                count++;
                sprintf(final_path, "%s%s", "/home/packets/", ent->d_name);
                printf("analysing :%s\n", final_path);

                pcap_handle = pcap_open_offline(final_path, error_content);
                pcap_compile(pcap_handle, &bpf_filter, bpf_filter_string, 0, net_ip);
                pcap_setfilter(pcap_handle, &bpf_filter);
                if (open_flag == 1) {
                    open_flag = 0;
                    out_pcap = pcap_dump_open(pcap_handle, exact);
                }

                pcap_loop(pcap_handle, -1, analysis, NULL);
                pcap_close(pcap_handle);
            }
        }
    }
        return 0;
}
