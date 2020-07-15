#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<netinet/in.h>
#include<pcap.h>
#include<dirent.h>
#include<unistd.h>
#include <ccl/ccl.h>
#include<time.h>

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
    long int begin;
    long int end;
    u_int seq;
    u_int ack;
    u_short length;
    u_short fin;
} package;

pcap_dumper_t *out_pcap;
package aPackage[9999999];
int a_Packet_number = 0;
package bPackage[9999999];
int b_Packet_number = 0;

struct ccl_t configure() {
    struct ccl_t config;
    config.comment_char = '#';
    config.sep_char = '=';
    config.str_char = '"';

    ccl_parse(&config, "/home/logan/CLionProjects/Capture/anl.conf");
    return config;
}



//sort single cap
void sort_cap(package *pac, const u_int len) {
    u_int i;
    short sort_flag = 0;//0: sort by seq; 1: sort by ack
    if ( (pac[5].seq == pac[6].seq) && (pac[5].seq == pac[7].seq) ){
        sort_flag = 1;

    }
    printf("flag = %d\n", sort_flag);
//sort by seq
    if (sort_flag == 0) {
        for (i = 1; i < len; i++) {
            u_int j = i - 1;
//key
            package key = pac[i];
//current
            while (pac[j].seq >= key.seq) {
                // len/ack bigger ,later
		if(pac[j].seq - key.seq > 2000) break;
                if (pac[j].seq == key.seq) {
                    if (pac[j].length < key.length) {
                        break;
                    } else if (pac[j].length == key.length && pac[j].fin < key.fin) {
                        break;
                    }
                }
                pac[j + 1] = pac[j];
                j--;
                if (j > i) { break; }
              //  p = pac[j];
            }
	if(j != (i - 1) ){
            pac[j + 1] = key;
            }
        }
    } else {
//sort by ack
        for (i = 1; i < len; i++) {
            u_int j = i - 1;
//key
            package key = pac[i];
//current
         //   package p = pac[j];
            while (pac[j].ack >= key.ack) {
		if(pac[j].ack - key.ack > 2000 ) break;
                // len/ack bigger ,later
                if (pac[j].ack == key.ack) {
                    if (pac[j].length < key.length) {
                        break;
                    } else if (pac[j].length == key.length && pac[j].fin < key.fin) {
                        break;
                    }
                }
                pac[j + 1] = pac[j];
                j--;
                if (j > i) { break; }
            //    p = pac[j];
            }
	if(j != (i - 1) ){
            pac[j + 1] = key;}
        }
    }
    time_t t;
    struct tm *timeinfo;
    time(&t);
    timeinfo = localtime(&t);
    printf("time:%s\n", asctime(timeinfo));
    printf("sort end!\n");
}

void sort_file(char final_path[], char path[], int a_len, package *a_Package, int b_len, package *b_Package) {
    printf("in file sort %d %d\n", a_len, b_len);
    FILE *sort;
    FILE *fp_a;
    int i = 0, j = 0;//count
    char ch;
//start read loc
    /* unsigned int loc_a = 24;
     unsigned int loc_b = 24;*/
//open cap1 and cap2
    if ((fp_a = fopen(path, "r")) == NULL) {
        printf("error: can not open pcap file\n");
        return;
    }
//open sort and merge file
    if ((sort = fopen(final_path, "a+")) == NULL) {
        return;
    }
    unsigned int loc = 24;
    fseek(fp_a, 0, SEEK_SET);
    while (loc != 0) {
        ch = fgetc(fp_a);
        fputc(ch, sort);
        loc--;
    }
    if (aPackage[i].ack == 0) {
        //file header
        fseek(fp_a, a_Package[0].begin, SEEK_SET);
        loc = a_Package[0].end - a_Package[0].begin;
/*        fseek(fp_b, b_Package[0].begin, SEEK_SET);
        loc_b = b_Package[0].end - b_Package[0].begin;*/
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
            if ((b_Package[j].ack == a_Package[i - 1].seq + a_Package[i - 1].length &&
                 b_Package[j].seq == a_Package[i - 1].ack &&
                 a_Package[i].ack >= b_Package[j].seq + b_Package[j].length) ||
                (a_Package[i - 1].fin == 1 && b_Package[j].ack == a_Package[i - 1].seq + a_Package[i - 1].length + 1 &&
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
            else if (b_Package[j - 1].fin == 1 && a_Package[i].ack == b_Package[j - 1].seq + 1 &&
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
            else if (a_Package[i].seq + a_Package[i].length == b_Package[j].ack &&
                     a_Package[i].ack == b_Package[j].seq) {
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
            else if (a_Package[i].seq == a_Package[i - 1].seq + a_Package[i - 1].length &&
                     a_Package[i].ack == a_Package[i - 1].ack) {
                fseek(fp_a, a_Package[i].begin, SEEK_SET);
                loc = a_Package[i].end - a_Package[i].begin;
                while (loc != 0) {
                    ch = fgetc(fp_a);
                    fputc(ch, sort);
                    loc--;
                }
                i++;

            } else if (b_Package[j].seq == b_Package[j - 1].seq + b_Package[j - 1].length &&
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
        //file header
        fseek(fp_a, b_Package[0].begin, SEEK_SET);
        loc = b_Package[0].end - b_Package[0].begin;
        // printf("begin=%d\n",b_Package[0].begin);
        //printf("sort loc=%d\n",loc);
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
        while (i <= b_len && j <= a_len) {
            //b response a
            if ((a_Package[j].ack == b_Package[i - 1].seq + b_Package[i - 1].length &&
                 a_Package[j].seq == b_Package[i - 1].ack &&
                 b_Package[i].ack >= a_Package[j].seq + a_Package[j].length) ||
                (b_Package[i - 1].fin == 1 && a_Package[j].ack == b_Package[i - 1].seq + b_Package[i - 1].length + 1 &&
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
            else if (a_Package[j - 1].fin == 1 && b_Package[i].ack == a_Package[j - 1].seq + 1 &&
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
            else if (b_Package[i].seq + b_Package[i].length == a_Package[j].ack &&
                     b_Package[i].ack == a_Package[j].seq) {
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
            else if (b_Package[i].seq == b_Package[i - 1].seq + b_Package[i - 1].length &&
                     b_Package[i].ack == b_Package[i - 1].ack) {
                fseek(fp_a, b_Package[i].begin, SEEK_SET);
                loc = b_Package[i].end - b_Package[i].begin;
                while (loc != 0) {
                    ch = fgetc(fp_a);
                    fputc(ch, sort);
                    loc--;
                }
                i++;

            } else if (a_Package[j].seq == a_Package[j - 1].seq + a_Package[j - 1].length &&
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
    printf("i=%d j=%d\n", i, j);
    time_t t;
    struct tm *timeinfo;
    time(&t);
    timeinfo = localtime(&t);
    printf("time:%s\n", asctime(timeinfo));
    fclose(sort);
    fclose(fp_a);

}

void analysis(u_char *argument, struct pcap_pkthdr *packet_header, u_char *packet_content) {
//save file
    pcap_dump((u_char *) out_pcap, packet_header, packet_content);
    pcap_dump_flush(out_pcap);
//generate packet array
    static packet_number = 0;
    static u_int ip_src;
    static long int location = 24;
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
        } else { aPackage[a_Packet_number].fin = 0; }
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
        } else { bPackage[b_Packet_number].fin = 0; }
        b_Packet_number++;
    }
//	printf("a = %d, b = %d\n",a_Packet_number,b_Packet_number);
    packet_number++;
}

int main() {
    char bpf_filter_string_1[1000] = "host ";
    char bpf_filter_string_2[1000] = "host ";
    char bpf_filter_string_3[1000] = "host ";
    char exact[30];
    char sorted[30];
    char src_add_1[16], src_add_2[16], src_add_3[16], src_add_4[16];
    char des_add_1[16], des_add_2[16], des_add_3[16], des_add_4[16];
    char s_port_1[5], s_port_2[5], s_port_3[5], s_port_4[5];
    char d_port_1[5], d_port_2[5], d_port_3[5], d_port_4[5];
//3 piece of wu-yuan-zu
/*    pid_t pid; //fpid表示fork函数返回的值
    pid = fork();
    int fork_flag;
    if (pid < 0)
        printf("error in fork!");
    else if (pid == 0) {//child
        pid_t pid1; //fpid表示fork函数返回的值
        pid1 = fork();
        if (pid1 < 0)
            printf("error in fork!");
        else if (pid1 == 0) {//child
            fork_flag = 1;
            strcpy(exact, "/home/anl1.cap");
            strcpy(sorted, "/home/sort1.cap");
        } else {//grandchild
            fork_flag = 2;
            strcpy(exact, "/home/anl2.cap");
            strcpy(sorted, "/home/sort2.cap");
        }
    } else {//father
        fork_flag = 3;
        strcpy(exact, "/home/anl3.cap");
        strcpy(sorted, "/home/sort3.cap");
    }
*/
//single wu-yuan-zu
    // strcpy(bpf_filter_string, "host 192.168.2.101 and host 218.7.43.8 and tcp port 80 and port 45332");
    strcpy(exact, "/home/anl1.cap");
    strcpy(sorted, "/home/sort1.cap");
    char *final_path;//拼成文件名
    final_path = (char *) malloc(sizeof(char) * 30);
    int count = 0;
    int loc, open_flag = 1;
    pcap_t *pcap_handle;
    char error_content[PCAP_ERRBUF_SIZE];
    struct bpf_program bpf_filter;
    bpf_u_int32 net_ip;
    int sort_flag = 0;
    while (1) {
        time_t t;
        struct tm *timeinfo;
        time(&t);
        timeinfo = localtime(&t);
        printf("time:%s\n", asctime(timeinfo));
        strcpy(bpf_filter_string_1, "host ");
        strcpy(bpf_filter_string_2, "host ");
        strcpy(bpf_filter_string_3, "host ");
        struct ccl_t re;//读取配置文件用
        const struct ccl_pair_t *iter;
        re = configure();
        while ((iter = ccl_iterate(&re)) != 0) {
            if (strcmp(iter->key, "source_address_1") == 0) {
                strcpy(src_add_1, iter->value);
            } else if (strcmp(iter->key, "destination_address_1") == 0) {
                strcpy(des_add_1, iter->value);
            } else if (strcmp(iter->key, "source_port_1") == 0) {
                strcpy(s_port_1, iter->value);
            } else if (strcmp(iter->key, "destination_port_1") == 0) {
                strcpy(d_port_1, iter->value);
            } else if (strcmp(iter->key, "source_address_2") == 0) {
                strcpy(src_add_2, iter->value);
            } else if (strcmp(iter->key, "destination_address_2") == 0) {
                strcpy(des_add_2, iter->value);
            } else if (strcmp(iter->key, "source_port_2") == 0) {
                strcpy(s_port_2, iter->value);
            } else if (strcmp(iter->key, "destination_port_2") == 0) {
                strcpy(d_port_2, iter->value);
            } else if (strcmp(iter->key, "source_address_3") == 0) {
                strcpy(src_add_3, iter->value);
            } else if (strcmp(iter->key, "destination_address_3") == 0) {
                strcpy(des_add_3, iter->value);
            } else if (strcmp(iter->key, "source_port_3") == 0) {
                strcpy(s_port_3, iter->value);
            } else if (strcmp(iter->key, "destination_port_3") == 0) {
                strcpy(d_port_3, iter->value);
            }
        }
        sprintf(bpf_filter_string_1, "%s%s", bpf_filter_string_1, src_add_1);
        sprintf(bpf_filter_string_1, "%s%s", bpf_filter_string_1, " and host ");
        sprintf(bpf_filter_string_1, "%s%s", bpf_filter_string_1, des_add_1);
        sprintf(bpf_filter_string_1, "%s%s", bpf_filter_string_1, " and tcp port ");
        sprintf(bpf_filter_string_1, "%s%s", bpf_filter_string_1, s_port_1);
        sprintf(bpf_filter_string_1, "%s%s", bpf_filter_string_1, " and port ");
        sprintf(bpf_filter_string_1, "%s%s", bpf_filter_string_1, d_port_1);
        printf("tuple 1 = %s\n", bpf_filter_string_1);
        sprintf(bpf_filter_string_2, "%s%s", bpf_filter_string_2, src_add_2);
        sprintf(bpf_filter_string_2, "%s%s", bpf_filter_string_2, " and host ");
        sprintf(bpf_filter_string_2, "%s%s", bpf_filter_string_2, des_add_2);
        sprintf(bpf_filter_string_2, "%s%s", bpf_filter_string_2, " and tcp port ");
        sprintf(bpf_filter_string_2, "%s%s", bpf_filter_string_2, s_port_2);
        sprintf(bpf_filter_string_2, "%s%s", bpf_filter_string_2, " and port ");
        sprintf(bpf_filter_string_2, "%s%s", bpf_filter_string_2, d_port_2);
//        printf("tuple 2 = %s\n", bpf_filter_string_2);
        sprintf(bpf_filter_string_3, "%s%s", bpf_filter_string_3, src_add_3);
        sprintf(bpf_filter_string_3, "%s%s", bpf_filter_string_3, " and host ");
        sprintf(bpf_filter_string_3, "%s%s", bpf_filter_string_3, des_add_3);
        sprintf(bpf_filter_string_3, "%s%s", bpf_filter_string_3, " and tcp port ");
        sprintf(bpf_filter_string_3, "%s%s", bpf_filter_string_3, s_port_3);
        sprintf(bpf_filter_string_3, "%s%s", bpf_filter_string_3, " and port ");
        sprintf(bpf_filter_string_3, "%s%s", bpf_filter_string_3, d_port_3);
//        printf("tuple 3 = %s\n", bpf_filter_string_3);

        loc = 0;
//10 seconds filter once
        sleep(2);
        DIR *pDir;
        struct dirent *ent;
        pDir = opendir("/home/packets");
        while ((ent = readdir(pDir)) != NULL) {
            if (ent->d_type & DT_DIR) {
                if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) { continue; }
            } else {
                if (strstr(ent->d_name, ".cap")) {
                    loc++;
//filter last time's file
                    if (loc <= count) {
                        continue;
                    }
//new file in this time
                    count++;
                    sprintf(final_path, "%s%s", "/home/packets/", ent->d_name);
                    printf("%s\n", ent->d_name);
                    printf("analysing :%s\n", final_path);

                    pcap_handle = pcap_open_offline(final_path, error_content);
                    /* if (fork_flag == 1) {
                         pcap_compile(pcap_handle, &bpf_filter, bpf_filter_string_1, 0, net_ip);
                         pcap_setfilter(pcap_handle, &bpf_filter);
                     } else if (fork_flag == 2) {
                         pcap_compile(pcap_handle, &bpf_filter, bpf_filter_string_2, 0, net_ip);
                         pcap_setfilter(pcap_handle, &bpf_filter);
                     } else if (fork_flag == 3) {
                         pcap_compile(pcap_handle, &bpf_filter, bpf_filter_string_3, 0, net_ip);
                         pcap_setfilter(pcap_handle, &bpf_filter);

                     }*/

                    pcap_compile(pcap_handle, &bpf_filter, bpf_filter_string_1, 0, net_ip);
                    pcap_setfilter(pcap_handle, &bpf_filter);
                    if (open_flag == 1) {
                        open_flag = 0;
                        out_pcap = pcap_dump_open(pcap_handle, exact);
                    }
                    pcap_loop(pcap_handle, -1, analysis, NULL);
                    pcap_close(pcap_handle);
                    //	remove(final_path);
                }
            }
        }
        printf("anumber = %d\n", a_Packet_number);
        printf("bnumber = %d\n", b_Packet_number);
	
        sort_cap(bPackage, b_Packet_number);
        sort_cap(aPackage, a_Packet_number);


//fin = 1 ,start sorting
        /*    if ((aPackage[a_Packet_number - 1].fin == 1 && bPackage[b_Packet_number - 2].fin == 1 && sort_flag == 0)
                || (bPackage[b_Packet_number - 1].fin == 1 && aPackage[a_Packet_number - 2].fin == 1
                    && sort_flag == 0)) {
                if (aPackage[0].ack == 0) {
                    sort_file(sorted, exact, a_Packet_number, aPackage, b_Packet_number, bPackage);
                } else if (bPackage[0].ack == 0) {
                    sort_file(sorted, exact, a_Packet_number, aPackage, b_Packet_number, bPackage);
                }
                sort_flag++;
            }*/

        sort_file(sorted, exact, a_Packet_number, aPackage, b_Packet_number, bPackage);
        break;
//	time(&t);
//	timeinfo = localtime(&t);
//	printf("time:%s\n",asctime(timeinfo));
    }
    return 0;
}
