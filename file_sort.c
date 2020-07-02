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
    u_int fin;
} package;


pcap_dumper_t *out_pcap;
package aPackage[65535];
package dis_aPackage[65535];
int aPacket_number = 0;
package bPackage[65535];
package dis_bPackage[65535];
int bPacket_number = 0;
int packet_number = 0;
int flag = 0;

//disorder file
/*void disorder_file(char origin_path[], char disorder_path[], package *pac) {
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
    printf("disorder complete!\n");
};*/

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
//merge and sort,one packet once
        while (i <= a_len && j <= b_len) {
//write file a's packet
//            printf("a_loc = %d\n", loc_a);
            while (loc_a != 0) {
                ch = fgetc(fp_a);
                fputc(ch, sort);
                loc_a--;
            }
//find a's next start loc and packet length
            i++;
            fseek(fp_a, a_Package[i].begin, SEEK_SET);
            loc_a = a_Package[i].end - a_Package[i].begin;
//if b's ack > a's next seq ,write next a
            u_int a_next_seq = a_Package[i - 1].seq + a_Package[i - 1].length;
            if (a_next_seq < b_Package[j].ack) {
                continue;
            }

//write file b's packet, similar with a
//            printf("b_loc = %d\n", loc_b);
            while (loc_b != 0) {
                ch = fgetc(fp_b);
                fputc(ch, sort);
                loc_b--;
            }
//find b's next start loc and packet length
            j++;
            fseek(fp_b, b_Package[j].begin, SEEK_SET);
            loc_b = b_Package[j].end - b_Package[j].begin;
//if a's ack > b's next seq ,write next b
            while ((b_Package[j - 1].seq + b_Package[j - 1].length) < a_Package[i].ack) {
                while (loc_b != 0) {
                    ch = fgetc(fp_b);
                    fputc(ch, sort);
                    loc_b--;
                }
                j++;
                fseek(fp_b, b_Package[j].begin, SEEK_SET);
                loc_b = b_Package[j].end - b_Package[j].begin;
            }
        }
    }
//b's ack == 0, start from b
    else{
//read a's 24B file header
        fseek(fp_b, 0, SEEK_SET);
        while (loc_b != 0) {
            ch = fgetc(fp_b);
            fputc(ch, sort);
            loc_b--;
        }
//find a and b start loc and packet length
        fseek(fp_a, a_Package[0].begin, SEEK_SET);
        loc_a = a_Package[0].end - a_Package[0].begin;
        fseek(fp_b, b_Package[0].begin, SEEK_SET);
        loc_b = b_Package[0].end - b_Package[0].begin;
//merge and sort,one packet once
        while (i <= a_len && j <= b_len) {
//write file b's packet
            while (loc_b != 0) {
                ch = fgetc(fp_b);
                fputc(ch, sort);
                loc_b--;
            }
//find b's next start loc and packet length
            j++;
            fseek(fp_b, b_Package[j].begin, SEEK_SET);
            loc_b = b_Package[j].end - b_Package[j].begin;
//if a's ack > b's next seq ,write next b
            u_int b_next_seq = b_Package[j - 1].seq + b_Package[j - 1].length;
            if (b_next_seq < a_Package[i].ack) {
                continue;
            }

//write file a's packet, similar with b
            while (loc_a != 0) {
                ch = fgetc(fp_a);
                fputc(ch, sort);
                loc_a--;
            }
//find a's next start loc and packet length
            i++;
            fseek(fp_a, a_Package[i].begin, SEEK_SET);
            loc_a = a_Package[i].end - a_Package[i].begin;
//if b's ack > a's next seq ,write next a
            while ((a_Package[i - 1].seq + a_Package[i - 1].length) < b_Package[j].ack) {
                while (loc_a != 0) {
                    ch = fgetc(fp_a);
                    fputc(ch, sort);
                    loc_a--;
                }
                i++;
                fseek(fp_a, a_Package[i].begin, SEEK_SET);
                loc_a = a_Package[i].end - a_Package[i].begin;
            }
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
//    printf("\nAnalysis packet %d!\n", packet_number);
    struct tcp_header *tcp_protocol;
    tcp_protocol = (struct tcp_header *) (packet_content + 14 + 20);
    static unsigned int location = 24;
//    static unsigned int dis_location = 24;
//    printf("packet length:%d!\n", packet_header->len);
//    printf("packet seq:%u\n", ntohl(tcp_protocol->tcp_acknowledgement));
//    printf("packet ack:%u\n", ntohl(tcp_protocol->tcp_ack));
/*    if (flag == 0) {
        dis_aPackage[packet_number].begin = dis_location;
        dis_location += packet_header->len + 16;
        dis_aPackage[packet_number].end = dis_location;
        u_int header_length = tcp_protocol->tcp_offset * 4 + 34;
        dis_aPackage[packet_number].length = packet_header->len - header_length;
    }*/
    aPackage[packet_number].begin = location;
    location += packet_header->len + 16;
    aPackage[packet_number].end = location;
    aPackage[packet_number].ack = ntohl(tcp_protocol->tcp_ack);
    aPackage[packet_number].seq = ntohl(tcp_protocol->tcp_acknowledgement);
    u_int header_length = tcp_protocol->tcp_offset * 4 + 34;
    aPackage[packet_number].length = packet_header->len - header_length;
    u_int flags = tcp_protocol->tcp_flags;
    if (flags & 0x01) {
        aPackage[packet_number].length++;
        aPackage[packet_number].fin = 1;
    } else { aPackage[packet_number].fin = 0; }
    if (flags & 0x02) {//syn = a,len++
        aPackage[packet_number].length++;
    }
    packet_number++;
}

//set bPackage[]
void analysis_b(u_char *argument, struct pcap_pkthdr *packet_header, u_char *packet_content) {
//    printf("\npacket length:%d!\n", packet_header->len);
//    printf("Analysis packet %d!\n", packet_number);
    struct tcp_header *tcp_protocol;
    tcp_protocol = (struct tcp_header *) (packet_content + 14 + 20);
    static unsigned int location = 24;
//    static unsigned int dis_location = 24;
/*    printf("packet length:%d!\n", packet_header->len);
    printf("packet seq:%u\n", ntohl(tcp_protocol->tcp_acknowledgement));
    printf("packet ack:%u\n", ntohl(tcp_protocol->tcp_ack));
    if (flag == 0) {
        dis_bPackage[packet_number].begin = dis_location;
        dis_location += packet_header->len + 16;
        dis_bPackage[packet_number].end = dis_location;
        u_int header_length = tcp_protocol->tcp_offset * 4 + 34;
        dis_bPackage[packet_number].length = packet_header->len - header_length;
    }*/
    bPackage[packet_number].begin = location;
    location += packet_header->len + 16;
    bPackage[packet_number].end = location;
    bPackage[packet_number].ack = ntohl(tcp_protocol->tcp_ack);
    bPackage[packet_number].seq = ntohl(tcp_protocol->tcp_acknowledgement);
    u_int header_length = tcp_protocol->tcp_offset * 4 + 34;
    bPackage[packet_number].length = packet_header->len - header_length;
    u_int flags = tcp_protocol->tcp_flags;
    if (flags & 0x01) {
        bPackage[packet_number].fin = 1;
        bPackage[packet_number].length++;
    } else { bPackage[packet_number].fin = 0; }
    if (flags & 0x02) {//syn = a,len++
        bPackage[packet_number].length++;
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
    disorder_file("/home/src.cap", "/home/src_change.cap", dis_aPackage);
    packet_number = 0;

//disorder dst.cap
    pcap_handle = pcap_open_offline("/home/dst.cap", error_content);

    pcap_compile(pcap_handle, &bpf_filter, bpf_filter_string, 0, net_ip);
    pcap_setfilter(pcap_handle, &bpf_filter);

    pcap_loop(pcap_handle, -1, analysis_b, NULL);
    pcap_close(pcap_handle);
    disorder_file("/home/dst.cap", "/home/dst_change.cap", dis_bPackage);
    packet_number = 0;*/

//sort disordered a.cap
    pcap_handle = pcap_open_offline("/home/src.cap", error_content);

    pcap_compile(pcap_handle, &bpf_filter, bpf_filter_string, 0, net_ip);
    pcap_setfilter(pcap_handle, &bpf_filter);

    pcap_loop(pcap_handle, -1, analysis_a, NULL);
    pcap_close(pcap_handle);
    aPacket_number = packet_number;
    sort_cap(aPackage, aPacket_number);
    packet_number = 0;

//sort disordered b.cap
    pcap_handle = pcap_open_offline("/home/dst.cap", error_content);

    pcap_compile(pcap_handle, &bpf_filter, bpf_filter_string, 0, net_ip);
    pcap_setfilter(pcap_handle, &bpf_filter);

    pcap_loop(pcap_handle, -1, analysis_b, NULL);
    pcap_close(pcap_handle);
    bPacket_number = packet_number;
    sort_cap(bPackage, bPacket_number);
//sort and merge 2 file
    sort_file("/home/src.cap", aPacket_number, aPackage, "/home/dst.cap", bPacket_number,
              bPackage);
    return 0;
}

