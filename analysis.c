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
    u_int ip_source_address;
    u_int ip_destination_address;
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

typedef struct {
    unsigned int begin;
    unsigned int end;
    u_int seq;
    u_int ack;
    u_int length;
    u_int fin;
} package;

pcap_dumper_t *out_pcap;
package aPackage[65535];
int a_Packet_number = 0;
package bPackage[65535];
int b_Packet_number = 0;

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

//sort single cap
void sort_cap(package *pac, const int len) {
    int i;
    for (i = 1; i < len; i++) {
        int j = i - 1;
        package p = pac[i];
        while (pac[j].seq >= p.seq && j >= 0) {
            // len/ack bigger ,later
            if (pac[j].seq == p.seq) {
                if (pac[j].ack < p.ack) {
                    break;
                } else if (pac[j].ack == p.ack && pac[j].length < p.length) {
                    break;
                } else if (pac[j].ack == p.ack && pac[j].length == p.length && pac[j].fin < p.fin) {
                    break;
                }
            }
            pac[j + 1] = pac[j];
            j--;
        }
        pac[j + 1] = p;
    }
    printf("sort end!\n");
}

//sort and merge two cap
void sort_file(char src_path[], char des_path[], int a_len, package *a_Package, int b_len, package *b_Package) {
    FILE *sort;
    FILE *fp_a;
//    FILE *fp_b;
    int i = 0, j = 0;//count
    char ch;
//start read loc
    unsigned int loc_a = 24;
    unsigned int loc_b = 24;
//open cap1 and cap2
    if ((fp_a = fopen(src_path, "r")) == NULL) {
        printf("error: can not open pcap file\n");
        return;
    }
//open sort and merge file
    if ((sort = fopen(des_path, "a+")) == NULL) {
        return;
    }
//read a's 24B file header
        fseek(fp_a, 0, SEEK_SET);
        while (loc_a != 0) {
            ch = fgetc(fp_a);
            fputc(ch, sort);
            loc_a--;
        }
//merge and sort,one packet once
        while (i <= a_len && j <= b_len) {
//write file a's packet
//find a start loc and packet length
            fseek(fp_a, a_Package[i].begin, SEEK_SET);
            loc_a = a_Package[i].end - a_Package[i].begin;
            while (loc_a != 0) {
                ch = fgetc(fp_a);
                fputc(ch, sort);
                loc_a--;
            }
            i++;
//if b's ack > a's next seq ,write next a
            u_int a_next_seq = a_Package[i - 1].seq + a_Package[i - 1].length;
            if (a_next_seq < b_Package[j].ack) {
                continue;
            }

//write file b's packet, similar with a
//write file b's packet
//find b start loc and packet length
            fseek(fp_a, b_Package[j].begin, SEEK_SET);
            loc_b = b_Package[j].end - b_Package[j].begin;
            while (loc_b != 0) {
                ch = fgetc(fp_a);
                fputc(ch, sort);
                loc_b--;
            }
            j++;
//if a's ack > b's next seq ,write next b
            while ((b_Package[j - 1].seq + b_Package[j - 1].length) < a_Package[i].ack) {
                fseek(fp_a, b_Package[j].begin, SEEK_SET);
                loc_b = b_Package[j].end - b_Package[j].begin;
                while (loc_b != 0) {
                    ch = fgetc(fp_a);
                    fputc(ch, sort);
                    loc_b--;
                }
                j++;
            }
        }
//if one file finished ,write the rest
    while (i <= a_len) {
        //write file a
        fseek(fp_a, a_Package[i].begin, SEEK_SET);
        loc_a = a_Package[i].end - a_Package[i].begin;
        while (loc_a != 0) {
            ch = fgetc(fp_a);
            fputc(ch, sort);
            loc_a--;
        }
        i++;
    }
    while (j <= b_len) {
        fseek(fp_a, b_Package[j].begin, SEEK_SET);
        loc_b = b_Package[j].end - b_Package[j].begin;
        while (loc_b != 0) {
            ch = fgetc(fp_a);
            fputc(ch, sort);
            loc_b--;
        }
        j++;
    }
    fclose(sort);
    fclose(fp_a);
    printf("merge complete!\n");
};

void analysis(u_char *argument,  struct pcap_pkthdr *packet_header,  u_char *packet_content) {
//save file
    pcap_dump((u_char *) out_pcap, packet_header, packet_content);
    pcap_dump_flush(out_pcap);
//generate packet array
    static packet_number = 0;
    static u_int ip_src;
    static unsigned int location = 24;
    struct tcp_header *tcp_protocol;
    struct ip_header *ip_protocol;
    ip_protocol = (struct ip_header *) (packet_content + 14);
    tcp_protocol = (struct tcp_header *) (packet_content + 14 + 20);
//confirm one direction's src ip
    if (packet_number == 0) { ip_src = ip_protocol->ip_source_address; }
//one direction
    if (ip_protocol->ip_source_address == ip_src) {
        aPackage[a_Packet_number].begin = location;
        location += packet_header->len + 16;
        aPackage[a_Packet_number].end = location;
        aPackage[a_Packet_number].ack = ntohl(tcp_protocol->tcp_ack);
        aPackage[a_Packet_number].seq = ntohl(tcp_protocol->tcp_acknowledgement);
        u_int header_length = tcp_protocol->tcp_offset * 4 + 34;
        aPackage[a_Packet_number].length = packet_header->len - header_length;
        u_int flags = tcp_protocol->tcp_flags;
        if (flags & 0x01) {//fin, len++
            aPackage[a_Packet_number].length++;
            aPackage[a_Packet_number].fin = 1;
        } else { aPackage[a_Packet_number].fin = 0; }
        if (flags & 0x02) {//syn, len++
            aPackage[a_Packet_number].length++;
        }
        a_Packet_number++;
    }
//the other direction
    else {
        bPackage[b_Packet_number].begin = location;
        location += packet_header->len + 16;
        bPackage[b_Packet_number].end = location;
        bPackage[b_Packet_number].ack = ntohl(tcp_protocol->tcp_ack);
        bPackage[b_Packet_number].seq = ntohl(tcp_protocol->tcp_acknowledgement);
        u_int header_length = tcp_protocol->tcp_offset * 4 + 34;
        bPackage[b_Packet_number].length = packet_header->len - header_length;
        u_int flags = tcp_protocol->tcp_flags;
        if (flags & 0x01) {//fin, len++
            bPackage[b_Packet_number].fin = 1;
            bPackage[b_Packet_number].length++;
        } else { bPackage[b_Packet_number].fin = 0; }
        if (flags & 0x02) {//syn, len++
            bPackage[b_Packet_number].length++;
        }
        b_Packet_number++;
    }
    packet_number++;
}

int main() {
    char bpf_filter_string[1000];
    char exact[30];
    char sorted[30];
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
            strcpy(bpf_filter_string, "host 192.168.2.101 and host 210.30.199.4 and tcp port 80 and port 59236");
            strcpy(exact, "/home/anl1.cap");
            strcpy(sorted, "/home/sort1.cap");
        }
        else {//grandchild
            strcpy(bpf_filter_string, "host 192.168.2.101 and host 210.30.199.4 and tcp port 80 and port 59238");
            strcpy(exact, "/home/anl2.cap");
            strcpy(sorted, "/home/sort2.cap");
        }
    }
    else {//father
        strcpy(bpf_filter_string, "host 192.168.2.101 and host 210.30.199.4 and tcp port 80 and port 59240");
        strcpy(exact, "/home/anl3.cap");
        strcpy(sorted, "/home/sort3.cap");
    }

//single wu-yuan-zu
/*    strcpy(bpf_filter_string, "host 192.168.2.101 and host 218.7.43.8 and tcp port 80 and port 54148");
    strcpy(exact, "/home/anl1.cap");
    strcpy(sorted, "/home/sort1.cap");*/
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
        sleep(2);
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
        sort_cap(aPackage, a_Packet_number);
        sort_cap(bPackage, b_Packet_number);
//fin = 1 ,start sorting
        if (aPackage[a_Packet_number - 1].fin == 1 || aPackage[a_Packet_number - 2].fin == 1 ||
                bPackage[b_Packet_number - 1].fin == 1 || bPackage[b_Packet_number - 2].fin == 1){
            if (aPackage[0].ack == 0) {
                sort_file(exact, sorted, a_Packet_number, aPackage, b_Packet_number, bPackage);
            } else if (bPackage[0].ack == 0) {
                sort_file(exact, sorted, b_Packet_number, bPackage, a_Packet_number, aPackage);
            }
        }
    }
    return 0;
}