//
// Created by root on 2020/5/27.
//

#include "stdio.h"
#include "pcap.h"

typedef struct {
    unsigned int begin;
    unsigned int end;
}package;


int packet_number = 0;
pcap_dumper_t *out_pcap;
package aPackage[1000];
void sort_file(char merged_path[], char file_path[], package *pac) {
    FILE *merged;
    FILE *fp;
    char ch;
    unsigned int loc = 24;
//写入的文件
    if ((fp = fopen(file_path, "r")) == NULL) {
        printf("error: can not open pcap file\n");
        return;
    }
    fseek(fp, 0, SEEK_SET);
//被写入的文件
    if ((merged = fopen(merged_path, "a+")) == NULL) {
        return;
    }
//sort file
    for (int i = packet_number - 1; i >= 0; i--) {
        printf("loc = %d\n", loc);
        while (loc != 0) {
            ch = fgetc(fp);
            fputc(ch, merged);
            loc--;
        }
        fseek(fp, pac[i].begin, SEEK_SET);
        loc = pac[i].end - pac[i].begin;
    }

    fclose(merged);
    fclose(fp);
    printf("merge complete!\n");
};
void analysis(u_char *argument,  struct pcap_pkthdr *packet_header,  u_char *packet_content) {
    static unsigned int location = 24;
    printf("Analysis packet %d!\n", packet_number);
    printf("packet length:%d!\n", packet_header->len);
    aPackage[packet_number].begin = location;
    location += packet_header->len + 16;
    aPackage[packet_number].end = location;
/*
    pcap_dump((u_char *) out_pcap, packet_header, packet_content);
    pcap_dump_flush(out_pcap);*/
    packet_number++;
}
 int main(){
    char exact[30];
    pcap_t *pcap_handle;
    char error_content[PCAP_ERRBUF_SIZE];
    struct bpf_program bpf_filter;
    bpf_u_int32 net_ip;
    char *bpf_filter_string = " ";
    pcap_handle = pcap_open_offline("/home/extract1.cap", error_content);
    pcap_compile(pcap_handle, &bpf_filter, bpf_filter_string, 0, net_ip);
    pcap_setfilter(pcap_handle, &bpf_filter);

//    out_pcap = pcap_dump_open(pcap_handle, "/home/extract1_change.cap");

    pcap_loop(pcap_handle, -1, analysis, NULL);

    pcap_close(pcap_handle);
    sort_file("/home/extract1_change.cap", "/home/extract1.cap", aPackage);
    return 0;
    return 0;
}

