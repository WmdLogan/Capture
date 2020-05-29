//
// Created by root on 2020/5/27.
//

#include "stdio.h"
#include "pcap.h"

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
typedef struct {
    unsigned int begin;
    unsigned int end;
    u_int seq;
    u_int ack;
    u_int length;
} package;


pcap_dumper_t *out_pcap;
package aPackage[1000];
int aPacket_number = 0;
package bPackage[1000];
int bPacket_number = 0;
int packet_number = 0;

void sort_cap(package *pac, const int len) {
    int i, count = 0, flag = 3, length;
    u_int key;
    for (i = 0; i < len; i++) {
        if (pac[i].seq == pac[i + 1].seq) {
            count++;
            if (count == 3) {
                flag = 0;
                break;
            }
            continue;
        } else if (pac[i].ack == pac[i + 1].ack) {
            count++;
            if (count == 3) {
                flag = 1;
                break;
            }
            continue;
        } else {
            count = 0;
        }
    }

    if (flag == 1) {//sort by seq
        for (i = 1; i < len; i++) {
            package p = pac[i];
            length = pac[i].length;
            int j = i - 1;
            while (pac[j].seq >= p.seq && j >= 0) {
                if (pac[j].seq == p.seq && pac[j].length < length) {
                    //len bigger ,later
                    continue;
                }
                pac[j + 1].seq = pac[j].seq;
                pac[j + 1].ack = pac[j].ack;
                pac[j + 1].length = pac[j].length;
                pac[j + 1].begin = pac[j].begin;
                pac[j + 1].end = pac[j].end;
                j--;
            }
            pac[j + 1].ack = p.ack;
            pac[j + 1].length = p.length;
            pac[j + 1].seq = p.seq;
            pac[j + 1].begin = p.begin;
            pac[j + 1].end = p.end;
        }
    } else {//sort by ack
        for (i = 1; i < len; i++) {
            package p = pac[i];
            length = pac[i].length;
            int j = i - 1;
            while (pac[j].ack >= p.ack && j >= 0) {
                if (pac[j].ack == p.ack && pac[j].length < length) {
                    //len bigger ,later
                    continue;
                }
                pac[j + 1].seq = pac[j].seq;
                pac[j + 1].ack = pac[j].ack;
                pac[j + 1].length = pac[j].length;
                pac[j + 1].begin = pac[j].begin;
                pac[j + 1].end = pac[j].end;
                j--;
            }
            pac[j + 1].ack = p.ack;
            pac[j + 1].length = p.length;
            pac[j + 1].seq = p.seq;
            pac[j + 1].begin = p.begin;
            pac[j + 1].end = p.end;
        }
    }
}

void disorder_file(char merged_path[], char file_path[], package *pac) {
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
    for (int i = packet_number - 1; i >= -1; i--) {
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

void sort_file(char src_path[], int a_len, char des_path[], int b_len) {

    FILE *sort;
    FILE *fp_a;
    FILE *fp_b;
    int i = 0;
    char ch;
    unsigned int loc_a = 24;
    unsigned int loc_b = 24;
    if ((fp_a = fopen(src_path, "r")) == NULL || (fp_b = fopen(des_path, "r")) == NULL) {
        printf("error: can not open pcap file\n");
        return;
    }
    if ((sort = fopen("/home/sort_tcp", "a+")) == NULL) {
        return;
    }
    if (aPackage[i].ack == 0) {//start from a
        fseek(fp_a, 24, SEEK_SET);
        fseek(fp_b, bPackage[0].begin, SEEK_SET);
        loc_b = bPackage[0].end - bPackage[0].begin;
//merge and sort
        while (i < a_len && i < b_len) {
//write file a
            printf("a_loc = %d\n", loc_a);
            while (loc_a != 0) {
                ch = fgetc(fp_a);
                fputc(ch, sort);
                loc_a--;
            }
            fseek(fp_a, aPackage[i].begin, SEEK_SET);
            loc_a = aPackage[i].end - aPackage[i].begin;
//write file b
            printf("b_loc = %d\n", loc_b);
            while (loc_b != 0) {
                ch = fgetc(fp_b);
                fputc(ch, sort);
                loc_b--;
            }
            fseek(fp_b, bPackage[i].begin, SEEK_SET);
            loc_b = bPackage[i].end - bPackage[i].begin;
            i++;
        }
    } else {//start from b
        fseek(fp_a, aPackage[0].begin, SEEK_SET);
        fseek(fp_b, 24, SEEK_SET);
        loc_a = aPackage[0].end - aPackage[0].begin;
//merge and sort

        while (i < a_len && i < b_len) {
//write file b
            printf("b_loc = %d\n", loc_b);
            while (loc_b != 0) {
                ch = fgetc(fp_b);
                fputc(ch, sort);
                loc_b--;
            }
            fseek(fp_b, bPackage[i].begin, SEEK_SET);
            loc_b = bPackage[i].end - bPackage[i].begin;
//write file a
            printf("a_loc = %d\n", loc_a);
            while (loc_a != 0) {
                ch = fgetc(fp_a);
                fputc(ch, sort);
                loc_a--;
            }
            fseek(fp_a, aPackage[i].begin, SEEK_SET);
            loc_a = aPackage[i].end - aPackage[i].begin;
            i++;
        }
    }
    fclose(sort);
    fclose(fp_a);
    fclose(fp_b);
    printf("merge complete!\n");
};


void analysis_a(u_char *argument, struct pcap_pkthdr *packet_header, u_char *packet_content) {
    printf("packet length:%d!\n", packet_header->len);
    printf("Analysis packet %d!\n", packet_number);
    struct tcp_header *tcp_protocol;
    tcp_protocol = (struct tcp_header *) (packet_content + 14 + 20);
    static unsigned int location = 24;
    printf("packet length:%d!\n", packet_header->len);
    printf("packet seq:%u\n", ntohl(tcp_protocol->tcp_acknowledgement));
    printf("packet ack:%u\n", ntohl(tcp_protocol->tcp_ack));
    aPackage[packet_number].begin = location;
    location += packet_header->len + 16;
    aPackage[packet_number].end = location;
    aPackage[packet_number].ack = ntohl(tcp_protocol->tcp_ack);
    aPackage[packet_number].seq = ntohl(tcp_protocol->tcp_acknowledgement);
    aPackage[packet_number].length = packet_header->len;
    packet_number++;
}

void analysis_b(u_char *argument, struct pcap_pkthdr *packet_header, u_char *packet_content) {
    printf("packet length:%d!\n", packet_header->len);
    printf("Analysis packet %d!\n", packet_number);
    struct tcp_header *tcp_protocol;
    tcp_protocol = (struct tcp_header *) (packet_content + 14 + 20);
    static unsigned int location = 24;
    printf("packet length:%d!\n", packet_header->len);
    printf("packet seq:%u\n", ntohl(tcp_protocol->tcp_acknowledgement));
    printf("packet ack:%u\n", ntohl(tcp_protocol->tcp_ack));
    bPackage[packet_number].begin = location;
    location += packet_header->len + 16;
    bPackage[packet_number].end = location;
    bPackage[packet_number].ack = ntohl(tcp_protocol->tcp_ack);
    bPackage[packet_number].seq = ntohl(tcp_protocol->tcp_acknowledgement);
    bPackage[packet_number].length = packet_header->len;
    packet_number++;
}

int main() {
    char exact[30];
    pcap_t *pcap_handle;
    char error_content[PCAP_ERRBUF_SIZE];
    struct bpf_program bpf_filter;
    bpf_u_int32 net_ip;
    char *bpf_filter_string = " ";
//    disorder_file("/home/extract2_change.cap", "/home/extract2.cap", aPackage);
//    out_pcap = pcap_dump_open(pcap_handle, "/home/extract2.cap");

//sort a.cap
    pcap_handle = pcap_open_offline("/home/extract1_change.cap", error_content);

    pcap_compile(pcap_handle, &bpf_filter, bpf_filter_string, 0, net_ip);
    pcap_setfilter(pcap_handle, &bpf_filter);

    pcap_loop(pcap_handle, -1, analysis_a, NULL);
    pcap_close(pcap_handle);
    aPacket_number = packet_number;
    sort_cap(aPackage, packet_number);
    for (int k = 0; k < aPacket_number; k++) {
        printf("seq: %u, ack: %u\n", aPackage[k].seq, aPackage[k].ack);
        printf("length = %d\n", aPackage[k].length);
    }
    packet_number = 0;
//sort b.cap
    pcap_handle = pcap_open_offline("/home/extract2_change.cap", error_content);

    pcap_compile(pcap_handle, &bpf_filter, bpf_filter_string, 0, net_ip);
    pcap_setfilter(pcap_handle, &bpf_filter);

    pcap_loop(pcap_handle, -1, analysis_b, NULL);
    pcap_close(pcap_handle);
    bPacket_number = packet_number;

    sort_cap(bPackage, packet_number);
    for (int k = 0; k < bPacket_number; k++) {
        printf("seq: %u, ack: %u\n", bPackage[k].seq, bPackage[k].ack);
        printf("length = %d\n", bPackage[k].length);
    }
    sort_file("/home/extract1_change.cap", aPacket_number, "/home/extract2_change.cap", bPacket_number);
    return 0;
}

