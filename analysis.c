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
//    printf("Analysis packet %d!\n", packet_number);
//    printf("packet length:%d!\n", packet_header->len);
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
            strcpy(bpf_filter_string, "src host 192.168.2.101 and dst host 218.7.43.8 and src port 54148 and dst port 80");
            strcpy(exact, "/home/src.cap");
        }
        else {//grandchild
            strcpy(bpf_filter_string, "dst host 192.168.2.101 and src host 218.7.43.8 and dst port 54148 and src port 80");
            strcpy(exact, "/home/dst.cap");
        }
    }
    else {//father
        strcpy(bpf_filter_string, "host 192.168.2.101 and host 218.7.43.8 and tcp port 80 and port 54148");
        strcpy(exact, "/home/all.cap");
    }

//single wu-yuan-zu
/*    strcpy(bpf_filter_string, "dst host 192.168.2.101 and src host 210.30.199.4 and dst port 38696 and src port 80");
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
/*
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<netinet/in.h>
#include "pcap.h"
#include "nids.h"
#include <unistd.h>
#include <dirent.h>

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
    u_int ack;
    u_int seq;
    int len;
    int flag;
} package;
pcap_dumper_t *out_pcap;
int packet_number = 0;
int a_Packet_number = 0;
int b_Packet_number = 0;
u_int ip_src;
package aPackage[1000];
package bPackage[1000];

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


void analysis(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content) {
    pcap_dump((u_char *) out_pcap, packet_header, packet_content);
    pcap_dump_flush(out_pcap);
    static unsigned int location = 24;
    // printf("loc= %d \n",aPackage[a_Packet_number].end-aPackage[a_Packet_number].begin);
    struct tcp_header *tcp_protocol;
    struct ip_header *ip_protocol;
    u_char flags;
    int header_length;

    ip_protocol = (struct ip_header *) (packet_content + 14);
    if (packet_number == 0) { ip_src = ip_protocol->ip_source_address; }

    if (ip_protocol->ip_source_address == ip_src) {
        tcp_protocol = (struct tcp_header *) (packet_content + 14 + 20);
        flags = tcp_protocol->tcp_flags;
//        printf("port = %d %d\n", ntohs(tcp_protocol->tcp_destination_port), ntohs(tcp_protocol->tcp_source_port));
        aPackage[a_Packet_number].begin = location;
        location += packet_header->len + 16;
        aPackage[a_Packet_number].end = location;
        if (flags & 0x01 || flags & 0x02) {
            aPackage[a_Packet_number].flag = 1;
            // printf("fin or syn\n");
        } else { aPackage[a_Packet_number].flag = 0; }
        int ack1 = ntohl(tcp_protocol->tcp_ack);
        int seq1 = ntohl(tcp_protocol->tcp_acknowledgement);
        aPackage[a_Packet_number].ack = ack1;
        aPackage[a_Packet_number].seq = seq1;
        // aPackage[a_Packet_number].time=packet_header->ts.tv_usec;
        // printf("ack=%u seq=%u ",aPackage[a_Packet_number].ack,aPackage[a_Packet_number].seq);
        if (packet_header->len == 54 || packet_header->len == 60) { aPackage[a_Packet_number].len = 0; }
        else {
            header_length = tcp_protocol->tcp_offset * 4 + 34;
            // printf("header len=%d\n",header_length);
            aPackage[a_Packet_number].len = packet_header->caplen - header_length;
        }
        //printf("a len=%d\n",aPackage[a_Packet_number].len);
        a_Packet_number++;
    } else {
        tcp_protocol = (struct tcp_header *) (packet_content + 14 + 20);
        flags = tcp_protocol->tcp_flags;

        bPackage[b_Packet_number].begin = location;
        location += packet_header->len + 16;
        bPackage[b_Packet_number].end = location;
        if (flags & 0x01 || flags & 0x02) {
            bPackage[b_Packet_number].flag = 1;
            // printf("fin or syn\n");
        } else { bPackage[b_Packet_number].flag = 0; }
        int ack1 = ntohl(tcp_protocol->tcp_ack);
        int seq1 = ntohl(tcp_protocol->tcp_acknowledgement);
        bPackage[b_Packet_number].ack = ack1;
        bPackage[b_Packet_number].seq = seq1;
        // bPackage[b_Packet_number].time=packet_header->ts.tv_usec;
        //printf("ack=%u seq=%u ",bPackage[b_Packet_number].ack,bPackage[b_Packet_number].seq);
        if (packet_header->len == 54 || packet_header->len == 60) {
            bPackage[b_Packet_number].len = 0;
        } else {
            header_length = tcp_protocol->tcp_offset * 4 + 34;
            bPackage[b_Packet_number].len = packet_header->len - header_length;
        }
        // printf("b len=%d\n",bPackage[b_Packet_number].len);
        b_Packet_number++;
    }
    packet_number++;
}

void sort_cap(package *pac, const int len) {
    int i, length, flag;
    u_int ack, fin;
    for (i = 1; i < len; i++) {
        package p = pac[i];
        length = pac[i].len;
        ack = pac[i].ack;
        flag = pac[i].flag;
        int j = i - 1;
        while (pac[j].seq >= p.seq && j >= 0) {
            // len/ack bigger ,later
            if (pac[j].seq == p.seq) {
                if (pac[j].ack < ack) {
                    j--;
                    continue;
                } else if (pac[j].ack == ack && pac[j].len < length) {
                    j--;
                    continue;
                } else if (pac[j].ack == ack && pac[j].len == length && pac[j].flag < flag) {
                    j--;
                    continue;
                }
            }
            pac[j + 1].seq = pac[j].seq;
            pac[j + 1].ack = pac[j].ack;
            pac[j + 1].len = pac[j].len;
            pac[j + 1].begin = pac[j].begin;
            pac[j + 1].end = pac[j].end;
            pac[j + 1].flag = pac[j].flag;
            //  pac[j + 1].time = pac[j].time;
            j--;

            pac[j + 1].ack = p.ack;
            pac[j + 1].len = p.len;
            pac[j + 1].seq = p.seq;
            pac[j + 1].begin = p.begin;
            pac[j + 1].end = p.end;
            pac[j + 1].flag = p.flag;
            // pac[j + 1].time = p.time;
        }
    }
    int m;
    for (m = 0; m < len; m++) {
        printf("seq=%u ack=%u len=%d flag=%d loc=%d\n", pac[m].seq, pac[m].ack, pac[m].len, pac[m].flag,
               pac[m].end - pac[m].begin);
    }
    printf("len=%d\n", len);
    printf("sort end!\n");
}

void sort_file(char final_path[], char path[], int a_len, package *a_Package, int b_len, package *b_Package) {
    FILE *sort;
    FILE *fp_a;
    int i = 0, j = 0;//count
    char ch;
//start read loc
    */
/* unsigned int loc_a = 24;
     unsigned int loc_b = 24;*//*

//open cap1 and cap2
    if ((fp_a = fopen(path, "r")) == NULL) {
        printf("error: can not open pcap file\n");
        return;
    }
//open sort and merge file
    if ((sort = fopen(final_path, "a+")) == NULL) {
        return;
    }
    if (aPackage[i].ack == 0) {
        unsigned int loc = 24;
        fseek(fp_a, 0, SEEK_SET);
        while (loc != 0) {
            ch = fgetc(fp_a);
            fputc(ch, sort);
            loc--;
        } //file header
        fseek(fp_a, a_Package[0].begin, SEEK_SET);
        loc = a_Package[0].end - a_Package[0].begin;
*/
/*        fseek(fp_b, b_Package[0].begin, SEEK_SET);
        loc_b = b_Package[0].end - b_Package[0].begin;*//*

        // printf("loc b=%d\n",loc_b);
        while (loc != 0) {
            ch = fgetc(fp_a);
            fputc(ch, sort);
            loc--;
        } //first package
        i++;
        fseek(fp_a, b_Package[0].begin, SEEK_SET);
        loc = b_Package[0].end - b_Package[0].begin;
        // printf("i=%d\n",i);
        while (loc != 0) {
            ch = fgetc(fp_a);
            fputc(ch, sort);
            loc--;
        }
        j++;
        fseek(fp_a, a_Package[i].begin, SEEK_SET);
        loc = a_Package[i].end - a_Package[i].begin;
        //printf("ack=%u  seq=%u loc=%d\n",a_Package[i].ack,a_Package[i].seq,loc_a);
        while (loc != 0) {
            ch = fgetc(fp_a);
            fputc(ch, sort);
            loc--;
        }
        i++;
        while (i <= a_len && j <= b_len) {
            //b response a
            if ((b_Package[j].ack == a_Package[i - 1].seq + a_Package[i - 1].len &&
                 b_Package[j].seq == a_Package[i - 1].ack && a_Package[i].ack >= b_Package[j].seq + b_Package[j].len) ||
                (a_Package[i - 1].flag == 1 && b_Package[j].ack == a_Package[i - 1].seq + a_Package[i - 1].len + 1 &&
                 b_Package[j].seq == a_Package[i - 1].ack)) {
                fseek(fp_a, b_Package[j].begin, SEEK_SET);
                loc = b_Package[j].end - b_Package[j].begin;
                while (loc != 0) {
                    ch = fgetc(fp_a);
                    fputc(ch, sort);
                    loc--;
                }
                j++;

            }
                //b first fin
            else if (b_Package[j - 1].flag == 1 && a_Package[i].ack == b_Package[j - 1].seq + 1 &&
                     a_Package[i].seq == b_Package[j - 1].ack) {
                fseek(fp_a, a_Package[i].begin, SEEK_SET);
                loc = a_Package[i].end - a_Package[i].begin;
                while (loc != 0) {
                    ch = fgetc(fp_a);
                    fputc(ch, sort);
                    loc--;
                }
                i++;

            }
                //a not stop and b response a
            else if (a_Package[i].seq + a_Package[i].len == b_Package[j].ack && a_Package[i].ack == b_Package[j].seq) {
                fseek(fp_a, a_Package[i].begin, SEEK_SET);
                loc = a_Package[i].end - a_Package[i].begin;
                while (loc != 0) {
                    ch = fgetc(fp_a);
                    fputc(ch, sort);
                    loc--;
                }
                i++;

            }
                //a not stop
            else if (a_Package[i].seq == a_Package[i - 1].seq + a_Package[i - 1].len &&
                     a_Package[i].ack == a_Package[i - 1].ack) {
                fseek(fp_a, a_Package[i].begin, SEEK_SET);
                loc = a_Package[i].end - a_Package[i].begin;
                while (loc != 0) {
                    ch = fgetc(fp_a);
                    fputc(ch, sort);
                    loc--;
                }
                i++;

            } else if (b_Package[j].seq == b_Package[j - 1].seq + b_Package[j - 1].len &&
                       b_Package[j].ack == b_Package[j - 1].ack) {
                fseek(fp_a, b_Package[j].begin, SEEK_SET);
                loc = b_Package[j].end - b_Package[j].begin;
                while (loc != 0) {
                    ch = fgetc(fp_a);
                    fputc(ch, sort);
                    loc--;
                }
                j++;

            } else {
                fseek(fp_a, a_Package[i].begin, SEEK_SET);
                loc = a_Package[i].end - a_Package[i].begin;
                while (loc != 0) {
                    ch = fgetc(fp_a);
                    fputc(ch, sort);
                    loc--;
                }
                i++;
            }

        }
    } else {
        unsigned int loc = 24;
        fseek(fp_a, 0, SEEK_SET);
        while (loc != 0) {
            ch = fgetc(fp_a);
            fputc(ch, sort);
            loc--;
        } //file header
        fseek(fp_a, b_Package[0].begin, SEEK_SET);
        loc = b_Package[0].end - b_Package[0].begin;
        printf("begin=%d\n", b_Package[0].begin);
        printf("sort loc=%d\n", loc);
        while (loc != 0) {
            ch = fgetc(fp_a);
            fputc(ch, sort);
            loc--;
        } //first package
        i++;
        fseek(fp_a, a_Package[0].begin, SEEK_SET);
        loc = a_Package[0].end - a_Package[0].begin;
        // printf("i=%d\n",i);
        while (loc != 0) {
            ch = fgetc(fp_a);
            fputc(ch, sort);
            loc--;
        }
        j++;
        fseek(fp_a, b_Package[i].begin, SEEK_SET);
        loc = b_Package[i].end - b_Package[i].begin;
        while (loc != 0) {
            ch = fgetc(fp_a);
            fputc(ch, sort);
            loc--;
        }
        i++;
        while (i <= a_len && j <= b_len) {
            //b response a
            if ((a_Package[j].ack == b_Package[i - 1].seq + b_Package[i - 1].len &&
                 a_Package[j].seq == b_Package[i - 1].ack && b_Package[i].ack >= a_Package[j].seq + a_Package[j].len) ||
                (b_Package[i - 1].flag == 1 && a_Package[j].ack == b_Package[i - 1].seq + b_Package[i - 1].len + 1 &&
                 a_Package[j].seq == b_Package[i - 1].ack)) {
                fseek(fp_a, a_Package[j].begin, SEEK_SET);
                loc = a_Package[j].end - a_Package[j].begin;
                while (loc != 0) {
                    ch = fgetc(fp_a);
                    fputc(ch, sort);
                    loc--;
                }
                j++;

            }
                //b first fin
            else if (a_Package[j - 1].flag == 1 && b_Package[i].ack == a_Package[j - 1].seq + 1 &&
                     b_Package[i].seq == a_Package[j - 1].ack) {
                fseek(fp_a, b_Package[i].begin, SEEK_SET);
                loc = b_Package[i].end - b_Package[i].begin;
                while (loc != 0) {
                    ch = fgetc(fp_a);
                    fputc(ch, sort);
                    loc--;
                }
                i++;

            }
                //a not stop and b response a
            else if (b_Package[i].seq + b_Package[i].len == a_Package[j].ack && b_Package[i].ack == a_Package[j].seq) {
                fseek(fp_a, b_Package[i].begin, SEEK_SET);
                loc = b_Package[i].end - b_Package[i].begin;
                while (loc != 0) {
                    ch = fgetc(fp_a);
                    fputc(ch, sort);
                    loc--;
                }
                i++;

            }
                //a not stop
            else if (b_Package[i].seq == b_Package[i - 1].seq + b_Package[i - 1].len &&
                     b_Package[i].ack == b_Package[i - 1].ack) {
                fseek(fp_a, b_Package[i].begin, SEEK_SET);
                loc = b_Package[i].end - b_Package[i].begin;
                while (loc != 0) {
                    ch = fgetc(fp_a);
                    fputc(ch, sort);
                    loc--;
                }
                i++;

            } else if (a_Package[j].seq == a_Package[j - 1].seq + a_Package[j - 1].len &&
                       a_Package[j].ack == a_Package[j - 1].ack) {
                fseek(fp_a, a_Package[j].begin, SEEK_SET);
                loc = a_Package[j].end - a_Package[j].begin;
                while (loc != 0) {
                    ch = fgetc(fp_a);
                    fputc(ch, sort);
                    loc--;
                }
                j++;

            } else {
                fseek(fp_a, b_Package[i].begin, SEEK_SET);
                loc = b_Package[i].end - b_Package[i].begin;
                while (loc != 0) {
                    ch = fgetc(fp_a);
                    fputc(ch, sort);
                    loc--;
                }
                i++;
            }

        }

    }
    fclose(sort);
    fclose(fp_a);

}

int main() {
    char bpf_filter_string[30];
    char file_path[1000];
    char exact[300];
    char dir[1000];
    pid_t pid; //fpid表示fork函数返回的值
    pid = fork();
    if (pid < 0)
        printf("error in fork!");
    else if (pid == 0) {//child
        pid_t pid1; //fpid表示fork函数返回的值
        pid1 = fork();
        if (pid1 < 0)
            printf("error in fork!");
        if (pid1 == 0) {//child
            strcpy(bpf_filter_string, "tcp port 54832");
            strcpy(file_path, "/home/new1.pcap");
            strcpy(exact, "/home/cap3.cap");
        } else {//grandchild
            strcpy(bpf_filter_string, "tcp  port 54836");
            strcpy(file_path, "/home/new3.pcap");
            strcpy(exact, "/home/cap5.cap");
        }
    } else {//father
        strcpy(bpf_filter_string, "tcp port 58438");
        strcpy(file_path, "/home/new2.pcap");
        strcpy(exact, "/home/cap4.cap");
    }
    char *path;//拼成文件名
    path = (char *) malloc(sizeof(char) * 300);
    int count = 0;
    int loc, open_flag = 1;
    pcap_t *pcap_handle;
    char error_content[PCAP_ERRBUF_SIZE];
    struct bpf_program bpf_filter;
    bpf_u_int32 net_ip;
    int signal = 0;
    int mask = 0;
    while (mask < 1) {
        loc = 0;
//sleep seconds filter once
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
                if (loc <= count) {//ignore
                    open_flag = 1;
                    continue;
                }
                count++;
                sprintf(path, "%s%s", "/home/packets/", ent->d_name);//read file name
//                printf("analysing :%s\n", path);
                pcap_handle = pcap_open_offline(path, error_content);
                pcap_compile(pcap_handle, &bpf_filter, bpf_filter_string, 0, net_ip);
                pcap_setfilter(pcap_handle, &bpf_filter);
//                printf("bpf silter=%s\n",bpf_filter_string);
                if (open_flag == 1) {//update new read file location
                    open_flag = 0;
                    out_pcap = pcap_dump_open(pcap_handle, file_path);
                }
                pcap_loop(pcap_handle, -1, analysis, NULL);
                pcap_close(pcap_handle);
            }
        }
        sort_cap(aPackage, a_Packet_number);
        sort_cap(bPackage, b_Packet_number);
        if ((aPackage[a_Packet_number - 2].flag == 1 && bPackage[b_Packet_number - 1].flag == 1 && signal == 0) ||
            (bPackage[b_Packet_number - 2].flag == 1 && aPackage[a_Packet_number - 1].flag == 1 && signal == 0)) {
            sort_file(exact, file_path, a_Packet_number, aPackage, b_Packet_number, bPackage);
            signal = 1;
        }
    }
}*/
