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

typedef struct package {
    long int begin;
    long int end;
    u_int seq;
    u_int ack;
    u_short length;
    u_short fin;
    struct package *pre;
    struct package *next;
} package;

pcap_dumper_t *out_pcap;
package *L_packageNode = NULL, *R_packageNode = NULL;

struct ccl_t configure() {
    struct ccl_t config;
    config.comment_char = '#';
    config.sep_char = '=';
    config.str_char = '"';

    ccl_parse(&config, "/home/logan/CLionProjects/Capture/anl.conf");
    return config;
}

void sort_cap_list(package *l) {
    short sort_flag = 0;//0: sort by seq; 1: sort by ack
    package *seq_5 = l->next->next->next->next;
    if ((seq_5->seq == seq_5->next->seq) && (seq_5->seq == seq_5->pre->seq)) {
        sort_flag = 1;
    }
    printf("flag = %d\n", sort_flag);
    package *cur = l->next;
    if (sort_flag == 0) {
        while (cur) {
            package *next = cur->next;
            package *tmppackage = cur->pre;
            package *key = tmppackage;
            while (tmppackage && tmppackage->seq >= cur->seq) {
                // len/ack bigger ,later
                if (tmppackage->seq - cur->seq > 2000) break;
                if (tmppackage->seq == cur->seq) {
                    if (tmppackage->length < cur->length) break;
                    else if (tmppackage->length == cur->length && tmppackage->fin < cur->fin) break;
                }
                tmppackage = tmppackage->pre;
            }
            if (key != tmppackage) {
                if (tmppackage == NULL) {//插入到链表的最前面
                    cur->pre->next = cur->next;
                    if (cur->next != NULL) cur->next->pre = cur->pre;
                    l->pre = cur;
                    cur->next = l;
                    cur->pre = NULL;
                    l = cur;

                } else if (tmppackage->next != cur) {
                    cur->pre->next = cur->next;
                    if (cur->next != NULL) cur->next->pre = cur->pre;
                    else {
                        cur->pre = tmppackage;
                        cur->next = tmppackage->next;
                        tmppackage->next->pre = cur;
                        tmppackage->next = cur;
                    }
                }
            }
            cur = next;
        }

    } else {//sort by ack
        while (cur) {
            package *next = cur->next;
            package *tmppackage = cur->pre;
            package *key = tmppackage;
            while (tmppackage && tmppackage->ack >= cur->ack) {
                // len/ack bigger ,later
                if (tmppackage->ack - cur->ack > 2000) break;
                if (tmppackage->ack == cur->ack) {
                    if (tmppackage->length < cur->length) break;
                    else if (tmppackage->length == cur->length && tmppackage->fin < cur->fin) break;
                }
                tmppackage = tmppackage->pre;
            }
            if (key != tmppackage) {
                if (tmppackage == NULL) {//插入到链表的最前面
                    cur->pre->next = cur->next;
                    if (cur->next != NULL) cur->next->pre = cur->pre;
                    l->pre = cur;
                    cur->next = l;
                    cur->pre = NULL;
                    l = cur;

                } else if (tmppackage->next != cur) {
                    cur->pre->next = cur->next;
                    if (cur->next != NULL) cur->next->pre = cur->pre;
                    else {
                        cur->pre = tmppackage;
                        cur->next = tmppackage->next;
                        tmppackage->next->pre = cur;
                        tmppackage->next = cur;
                    }
                }
            }
            cur = next;
        }
    }
    time_t t;
    struct tm *timeinfo;
    time(&t);
    timeinfo = localtime(&t);
    printf("time:%s\n", asctime(timeinfo));
    printf("sort end!\n");
}

//sort single cap

void sort_file_list(char final_path[], char path[], package *a_Package, package *b_Package) {
    FILE *sort;
    FILE *fp_a;
    char ch;
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
    if (a_Package->ack == 0) {
        //file header
        fseek(fp_a, a_Package->begin, SEEK_SET);
        loc = a_Package->end - a_Package->begin;

        while (loc != 0) {
            ch = fgetc(fp_a);
            fputc(ch, sort);
            loc--;
        } //first package
        a_Package = a_Package->next;
        
        fseek(fp_a, b_Package->begin, SEEK_SET);
        loc = b_Package->end - b_Package->begin;
        while (loc != 0) {
            ch = fgetc(fp_a);
            fputc(ch, sort);
            loc--;
        }
        b_Package = b_Package->next;
        
        fseek(fp_a, a_Package->begin, SEEK_SET);
        loc = a_Package->end - a_Package->begin;
        //printf("ack=%u  seq=%u loc=%d\n",a_Package->ack,a_Package->seq,loc_a);
        while (loc != 0) {
            ch = fgetc(fp_a);
            fputc(ch, sort);
            loc--;
        }
        a_Package = a_Package->next;
        
        while (a_Package && b_Package) {
            //b response a
            if ((b_Package->ack == a_Package->pre->seq + a_Package->pre->length &&
                 b_Package->seq == a_Package->pre->ack &&
                 a_Package->ack >= b_Package->seq + b_Package->length) ||
                (a_Package->pre->fin == 1 && b_Package->ack == a_Package->pre->seq + a_Package->pre->length + 1 &&
                 b_Package->seq == a_Package->pre->ack)) {
                fseek(fp_a, b_Package->begin, SEEK_SET);
                loc = b_Package->end - b_Package->begin;
                while (loc != 0) {
                    ch = fgetc(fp_a);
                    fputc(ch, sort);
                    loc--;
                }
                b_Package = b_Package->next;

            }
                //b first fin
            else if (b_Package->pre->fin == 1 && a_Package->ack == b_Package->pre->seq + 1 &&
                     a_Package->seq == b_Package->pre->ack) {
                fseek(fp_a, a_Package->begin, SEEK_SET);
                loc = a_Package->end - a_Package->begin;
                while (loc != 0) {
                    ch = fgetc(fp_a);
                    fputc(ch, sort);
                    loc--;
                }
                a_Package = a_Package->next;

            }
//a not stop and b response a
            else if (a_Package->seq + a_Package->length == b_Package->ack &&
                     a_Package->ack == b_Package->seq) {
                fseek(fp_a, a_Package->begin, SEEK_SET);
                loc = a_Package->end - a_Package->begin;
                while (loc != 0) {
                    ch = fgetc(fp_a);
                    fputc(ch, sort);
                    loc--;
                }
                a_Package = a_Package->next;

            }
                //a not stop
            else if (a_Package->seq == a_Package->pre->seq + a_Package->pre->length &&
                     a_Package->ack == a_Package->pre->ack) {
                fseek(fp_a, a_Package->begin, SEEK_SET);
                loc = a_Package->end - a_Package->begin;
                while (loc != 0) {
                    ch = fgetc(fp_a);
                    fputc(ch, sort);
                    loc--;
                }
                a_Package = a_Package->next;

            } else if (b_Package->seq == b_Package->pre->seq + b_Package->pre->length &&
                       b_Package->ack == b_Package->pre->ack) {
                fseek(fp_a, b_Package->begin, SEEK_SET);
                loc = b_Package->end - b_Package->begin;
                while (loc != 0) {
                    ch = fgetc(fp_a);
                    fputc(ch, sort);
                    loc--;
                }
                b_Package = b_Package->next;
                

            } else {
                fseek(fp_a, a_Package->begin, SEEK_SET);
                loc = a_Package->end - a_Package->begin;
                while (loc != 0) {
                    ch = fgetc(fp_a);
                    fputc(ch, sort);
                    loc--;
                }
                a_Package = a_Package->next;
                
            }

        }
    } else {
        //file header
        fseek(fp_a, b_Package->begin, SEEK_SET);
        loc = b_Package->end - b_Package->begin;

        while (loc != 0) {
            ch = fgetc(fp_a);
            fputc(ch, sort);
            loc--;
        } //first package
        b_Package = b_Package->next;
        
        fseek(fp_a, a_Package->begin, SEEK_SET);
        loc = a_Package->end - a_Package->begin;
        // printf("i=%d\n",i);
        while (loc != 0) {
            ch = fgetc(fp_a);
            fputc(ch, sort);
            loc--;
        }
        a_Package = a_Package->next;

        fseek(fp_a, b_Package->begin, SEEK_SET);
        loc = b_Package->end - b_Package->begin;
        while (loc != 0) {
            ch = fgetc(fp_a);
            fputc(ch, sort);
            loc--;
        }
        b_Package = b_Package->next;

        while (a_Package && b_Package) {
            //b response a
            if ((a_Package->ack == b_Package->pre->seq + b_Package->pre->length &&
                 a_Package->seq == b_Package->pre->ack &&
                 b_Package->ack >= a_Package->seq + a_Package->length) ||
                (b_Package->pre->fin == 1 && a_Package->ack == b_Package->pre->seq + b_Package->pre->length + 1 &&
                 a_Package->seq == b_Package->pre->ack)) {
                fseek(fp_a, a_Package->begin, SEEK_SET);
                loc = a_Package->end - a_Package->begin;
                while (loc != 0) {
                    ch = fgetc(fp_a);
                    fputc(ch, sort);
                    loc--;
                }
                a_Package = a_Package->next;

            }
                //b first fin
            else if (a_Package->pre->fin == 1 && b_Package->ack == a_Package->pre->seq + 1 &&
                     b_Package->seq == a_Package->pre->ack) {
                fseek(fp_a, b_Package->begin, SEEK_SET);
                loc = b_Package->end - b_Package->begin;
                while (loc != 0) {
                    ch = fgetc(fp_a);
                    fputc(ch, sort);
                    loc--;
                }
                b_Package = b_Package->next;

            }
                //a not stop and b response a
            else if (b_Package->seq + b_Package->length == a_Package->ack &&
                     b_Package->ack == a_Package->seq) {
                fseek(fp_a, b_Package->begin, SEEK_SET);
                loc = b_Package->end - b_Package->begin;
                while (loc != 0) {
                    ch = fgetc(fp_a);
                    fputc(ch, sort);
                    loc--;
                }
                b_Package = b_Package->next;

            }
                //a not stop
            else if (b_Package->seq == b_Package->pre->seq + b_Package->pre->length &&
                     b_Package->ack == b_Package->pre->ack) {
                fseek(fp_a, b_Package->begin, SEEK_SET);
                loc = b_Package->end - b_Package->begin;
                while (loc != 0) {
                    ch = fgetc(fp_a);
                    fputc(ch, sort);
                    loc--;
                }
                b_Package = b_Package->next;

            } else if (a_Package->seq == a_Package->pre->seq + a_Package->pre->length &&
                       a_Package->ack == a_Package->pre->ack) {
                fseek(fp_a, a_Package->begin, SEEK_SET);
                loc = a_Package->end - a_Package->begin;
                while (loc != 0) {
                    ch = fgetc(fp_a);
                    fputc(ch, sort);
                    loc--;
                }
                a_Package = a_Package->next;

            } else {
                fseek(fp_a, b_Package->begin, SEEK_SET);
                loc = b_Package->end - b_Package->begin;
                while (loc != 0) {
                    ch = fgetc(fp_a);
                    fputc(ch, sort);
                    loc--;
                }
                b_Package = b_Package->next;

            }
        }

    }
    printf("merge end!\n");
    time_t t;
    struct tm *timeinfo;
    time(&t);
    timeinfo = localtime(&t);
    printf("time:%s\n", asctime(timeinfo));
    fclose(sort);
    fclose(fp_a);
}


void analysis_list(u_char *argument, struct pcap_pkthdr *packet_header, u_char *packet_content) {
    //save file
    pcap_dump((u_char *) out_pcap, packet_header, packet_content);
    pcap_dump_flush(out_pcap);
//generate packet array
    static packet_number = 0;
    static a_Packet_number = 0;
    static b_Packet_number = 0;
    static u_int ip_src;
    static long int location = 24;
    struct tcp_header *tcp_protocol;
    struct ip_header *ip_protocol;
    ip_protocol = (struct ip_header *) (packet_content + 14);
    tcp_protocol = (struct tcp_header *) (packet_content + 14 + 20);
    static package *L_cur = NULL;
    static package *R_cur = NULL;
//confirm one direction's src ip
    if (packet_number == 0) { ip_src = ip_protocol->ip_source_address; }
//one direction
    if (ip_protocol->ip_source_address == ip_src) {
        package *tmpDNode = (package *) malloc(sizeof(package));
        tmpDNode->begin = location;
        location += packet_header->len + 16;
        tmpDNode->end = location;

        tmpDNode->ack = ntohl(tcp_protocol->tcp_ack);
        tmpDNode->seq = ntohl(tcp_protocol->tcp_acknowledgement);
        u_int header_length = tcp_protocol->tcp_offset * 4 + 34;
        tmpDNode->length = packet_header->len - header_length;
        u_int flags = tcp_protocol->tcp_flags;
        if (flags & 0x01) {//fin, len++
            tmpDNode->length++;
        } else { tmpDNode->fin = 0; }
        tmpDNode->next = NULL;
        if (a_Packet_number == 0) {
            L_packageNode = tmpDNode;
            L_packageNode->pre = NULL;
            L_cur = L_packageNode;
        } else {
            tmpDNode->pre = L_cur;
            L_cur->next = tmpDNode;
            L_cur = tmpDNode;
        }
        a_Packet_number++;
    }
//the other direction
    else {
        package *tmpDNode = (package *) malloc(sizeof(package));
        tmpDNode->begin = location;
        location += packet_header->len + 16;
        tmpDNode->end = location;

        tmpDNode->ack = ntohl(tcp_protocol->tcp_ack);
        tmpDNode->seq = ntohl(tcp_protocol->tcp_acknowledgement);
        u_int header_length = tcp_protocol->tcp_offset * 4 + 34;
        tmpDNode->length = packet_header->len - header_length;
        u_int flags = tcp_protocol->tcp_flags;
        if (flags & 0x01) {//fin, len++
            tmpDNode->length++;
        } else { tmpDNode->fin = 0; }
        tmpDNode->next = NULL;
        if (b_Packet_number == 0) {
            R_packageNode = tmpDNode;
            R_packageNode->pre = NULL;
            R_cur = R_packageNode;
        } else {
            tmpDNode->pre = R_cur;
            R_cur->next = tmpDNode;
            R_cur = tmpDNode;
        }
        b_Packet_number++;
    }
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
                    pcap_loop(pcap_handle, -1, analysis_list, NULL);
                    pcap_close(pcap_handle);
                }
            }
        }
        
        sort_cap_list(L_packageNode);
        sort_cap_list(R_packageNode);
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
        
        sort_file_list(sorted, exact,  L_packageNode,  R_packageNode);
        break;
    }
    return 0;
}
