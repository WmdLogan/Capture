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
package dis_aPackage[1000];
int aPacket_number = 0;
package bPackage[1000];
package dis_bPackage[1000];
int bPacket_number = 0;
int packet_number = 0;
int flag = 0;

//sort single cap
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

//disorder file
void disorder_file(char origin_path[], char disorder_path[], package *pac) {
    FILE *merged;
    FILE *fp;
    char ch;
    unsigned int loc = 24;
//origin file
    if ((fp = fopen(origin_path, "r")) == NULL) {
        printf("error: can not open pcap file\n");
        return;
    }
    fseek(fp, 0, SEEK_SET);
//disorder file
    if ((merged = fopen(disorder_path, "a+")) == NULL) {
        return;
    }
//reverse
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

//sort and merge two cap
void sort_file(char src_path[], int a_len, package *a_Package, char des_path[], int b_len, package *b_Package) {
    FILE *sort;
    FILE *fp_a;
    FILE *fp_b;
    int i = 0, j = 0;//count
    char ch;
//start read loc
    unsigned int loc_a = 24;
    unsigned int loc_b = 24;
//open cap1 and cap2
    if ((fp_a = fopen(src_path, "r")) == NULL || (fp_b = fopen(des_path, "r")) == NULL) {
        printf("error: can not open pcap file\n");
        return;
    }
//open sort and merge file
    if ((sort = fopen("/home/sort1_tcp.cap", "a+")) == NULL) {
        return;
    }
//a's ack == 0, start from a
    if (a_Package[i].ack == 0) {
//read a's 24B file header
        fseek(fp_a, 0, SEEK_SET);
        while (loc_a != 0) {
            ch = fgetc(fp_a);
            fputc(ch, sort);
            loc_a--;
        }
//find a and b start loc and packet length
        fseek(fp_a, a_Package[0].begin, SEEK_SET);
        loc_a = a_Package[0].end - a_Package[0].begin;
        fseek(fp_b, b_Package[0].begin, SEEK_SET);
        loc_b = b_Package[0].end - b_Package[0].begin;
        i++;
        j++;
//merge and sort,one packet once
        while (i <= a_len && j <= b_len) {
//write file a's packet
            printf("a_loc = %d\n", loc_a);
            while (loc_a != 0) {
                ch = fgetc(fp_a);
                fputc(ch, sort);
                loc_a--;
            }
//find a's next start loc and packet length
            fseek(fp_a, a_Package[i].begin, SEEK_SET);
            loc_a = a_Package[i].end - a_Package[i].begin;
//if next packet ack,seq same ,write next packet
            if (a_Package[i - 1].ack == a_Package[i].ack && a_Package[i - 1].seq == a_Package[i].seq) {
                i++;
                while (loc_a != 0) {
                    ch = fgetc(fp_a);
                    fputc(ch, sort);
                    loc_a--;
                }
                fseek(fp_a, a_Package[i].begin, SEEK_SET);
                loc_a = a_Package[i].end - a_Package[i].begin;
            }
//write file b's packet, similar with a
            printf("b_loc = %d\n", loc_b);
            while (loc_b != 0) {
                ch = fgetc(fp_b);
                fputc(ch, sort);
                loc_b--;
            }
            fseek(fp_b, b_Package[j].begin, SEEK_SET);
            loc_b = b_Package[j].end - b_Package[j].begin;
            if (b_Package[j - 1].ack == b_Package[j].ack && b_Package[j - 1].seq == b_Package[j].seq) {
                j++;
                while (loc_b != 0) {
                    ch = fgetc(fp_b);
                    fputc(ch, sort);
                    loc_b--;
                }
                fseek(fp_b, b_Package[j].begin, SEEK_SET);
                loc_b = b_Package[j].end - b_Package[j].begin;
            }
            i++;
            j++;
        }
    }
//b's ack == 0, start from b
    else {
//write b's file header
        fseek(fp_b, 0, SEEK_SET);
        while (loc_b != 0) {
            ch = fgetc(fp_b);
            fputc(ch, sort);
            loc_b--;
        }
        fseek(fp_b, b_Package[0].begin, SEEK_SET);
        loc_b = b_Package[0].end - b_Package[0].begin;
        fseek(fp_a, a_Package[0].begin, SEEK_SET);
        loc_a = a_Package[0].end - a_Package[0].begin;
        i++;
        j++;
//merge and sort
        while (i <= a_len && j <= b_len) {
//write file b's packet
            printf("b_loc = %d\n", loc_b);
            while (loc_b != 0) {
                ch = fgetc(fp_b);
                fputc(ch, sort);
                loc_b--;
            }
            fseek(fp_b, b_Package[j].begin, SEEK_SET);
            loc_b = b_Package[j].end - b_Package[j].begin;
            if (b_Package[j - 1].ack == b_Package[j].ack && b_Package[j - 1].seq == b_Package[j].seq) {
                j++;
                while (loc_b != 0) {
                    ch = fgetc(fp_b);
                    fputc(ch, sort);
                    loc_b--;
                }
                fseek(fp_b, b_Package[j].begin, SEEK_SET);
                loc_b = b_Package[j].end - b_Package[j].begin;
            }
//write file a's packet
            printf("a_loc = %d\n", loc_a);
            while (loc_a != 0) {
                ch = fgetc(fp_a);
                fputc(ch, sort);
                loc_a--;
            }
            fseek(fp_a, a_Package[i].begin, SEEK_SET);
            loc_a = a_Package[i].end - a_Package[i].begin;
            if (a_Package[i - 1].ack == a_Package[i].ack && a_Package[i - 1].seq == a_Package[i].seq) {
                i++;
                while (loc_a != 0) {
                    ch = fgetc(fp_a);
                    fputc(ch, sort);
                    loc_a--;
                }
                fseek(fp_a, a_Package[i].begin, SEEK_SET);
                loc_a = a_Package[i].end - a_Package[i].begin;
            }
            i++;
            j++;
        }
    }
//if one file finished ,write the rest
    while (i <= a_len) {
        //write file a
        printf("a_loc = %d\n", loc_a);
        while (loc_a != 0) {
            ch = fgetc(fp_a);
            fputc(ch, sort);
            loc_a--;
        }
        fseek(fp_a, a_Package[i].begin, SEEK_SET);
        loc_a = a_Package[i].end - a_Package[i].begin;
        i++;
    }
    while (j <= b_len) {
        printf("b_loc = %d\n", loc_b);
        while (loc_b != 0) {
            ch = fgetc(fp_b);
            fputc(ch, sort);
            loc_b--;
        }
        fseek(fp_b, b_Package[j].begin, SEEK_SET);
        loc_b = b_Package[j].end - b_Package[j].begin;
        j++;
    }
    fclose(sort);
    fclose(fp_a);
    fclose(fp_b);
    printf("merge complete!\n");
};

//set aPackage[]
void analysis_a(u_char *argument, struct pcap_pkthdr *packet_header, u_char *packet_content) {
    printf("Analysis packet %d!\n", packet_number);
    struct tcp_header *tcp_protocol;
    tcp_protocol = (struct tcp_header *) (packet_content + 14 + 20);
    static unsigned int location = 24;
    printf("packet length:%d!\n", packet_header->len);
    printf("packet seq:%u\n", ntohl(tcp_protocol->tcp_acknowledgement));
    printf("packet ack:%u\n", ntohl(tcp_protocol->tcp_ack));
    if (flag == 0) {
        dis_aPackage[packet_number].begin = location;
        location += packet_header->len + 16;
        dis_aPackage[packet_number].end = location;
        dis_aPackage[packet_number].length = packet_header->len;
    }
    if (flag == 1) {
        aPackage[packet_number].begin = location;
        location += packet_header->len + 16;
        aPackage[packet_number].end = location;
        aPackage[packet_number].ack = ntohl(tcp_protocol->tcp_ack);
        aPackage[packet_number].seq = ntohl(tcp_protocol->tcp_acknowledgement);
        aPackage[packet_number].length = packet_header->len;
    }
    packet_number++;
}

//set bPackage[]
void analysis_b(u_char *argument, struct pcap_pkthdr *packet_header, u_char *packet_content) {
    printf("packet length:%d!\n", packet_header->len);
    printf("Analysis packet %d!\n", packet_number);
    struct tcp_header *tcp_protocol;
    tcp_protocol = (struct tcp_header *) (packet_content + 14 + 20);
    static unsigned int location = 24;
    printf("packet length:%d!\n", packet_header->len);
    printf("packet seq:%u\n", ntohl(tcp_protocol->tcp_acknowledgement));
    printf("packet ack:%u\n", ntohl(tcp_protocol->tcp_ack));
    if (flag == 0) {
        dis_bPackage[packet_number].begin = location;
        location += packet_header->len + 16;
        dis_bPackage[packet_number].end = location;
        dis_bPackage[packet_number].length = packet_header->len;
    }
    if (flag == 1) {
        bPackage[packet_number].begin = location;
        location += packet_header->len + 16;
        bPackage[packet_number].end = location;
        bPackage[packet_number].ack = ntohl(tcp_protocol->tcp_ack);
        bPackage[packet_number].seq = ntohl(tcp_protocol->tcp_acknowledgement);
        bPackage[packet_number].length = packet_header->len;
    }
    packet_number++;
}

int main() {
    char exact[30];
    pcap_t *pcap_handle;
    char error_content[PCAP_ERRBUF_SIZE];
    struct bpf_program bpf_filter;
    bpf_u_int32 net_ip;
    char *bpf_filter_string = " ";
//disorder src.cap
/*    pcap_handle = pcap_open_offline("/home/src.cap", error_content);

    pcap_compile(pcap_handle, &bpf_filter, bpf_filter_string, 0, net_ip);
    pcap_setfilter(pcap_handle, &bpf_filter);

    pcap_loop(pcap_handle, -1, analysis_a, NULL);
    pcap_close(pcap_handle);
    aPacket_number = packet_number;
    disorder_file("/home/src.cap", "/home/src_change.cap",dis_aPackage);
    packet_number = 0;

//disorder dst.cap
    pcap_handle = pcap_open_offline("/home/dst.cap", error_content);

    pcap_compile(pcap_handle, &bpf_filter, bpf_filter_string, 0, net_ip);
    pcap_setfilter(pcap_handle, &bpf_filter);

    pcap_loop(pcap_handle, -1, analysis_b, NULL);
    pcap_close(pcap_handle);
    aPacket_number = packet_number;
    disorder_file("/home/dst.cap", "/home/dst_change.cap",dis_bPackage);
    packet_number = 0;*/

    flag = 1;
//sort disordered a.cap
    pcap_handle = pcap_open_offline("/home/src_change.cap", error_content);

    pcap_compile(pcap_handle, &bpf_filter, bpf_filter_string, 0, net_ip);
    pcap_setfilter(pcap_handle, &bpf_filter);

    pcap_loop(pcap_handle, -1, analysis_a, NULL);
    pcap_close(pcap_handle);
    aPacket_number = packet_number;
    sort_cap(aPackage, packet_number);
    packet_number = 0;

//sort disordered b.cap
    pcap_handle = pcap_open_offline("/home/dst_change.cap", error_content);

    pcap_compile(pcap_handle, &bpf_filter, bpf_filter_string, 0, net_ip);
    pcap_setfilter(pcap_handle, &bpf_filter);

    pcap_loop(pcap_handle, -1, analysis_b, NULL);
    pcap_close(pcap_handle);
    bPacket_number = packet_number;
    sort_cap(bPackage, packet_number);

//sort and merge 2 file
    sort_file("/home/src_change.cap", aPacket_number, aPackage, "/home/dst_change.cap", bPacket_number,
              bPackage);
    return 0;
}

