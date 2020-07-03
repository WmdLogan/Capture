//#include "Capture.h"
#include "delete_hash.h"


//检查配置文件更新线程
void check_update() {
    struct stat configure_buf;//获取配置文件最后修改时间，与 update_time比较，判断是否更新
    long int update_time;//配置文件最后修改时间
    int flag = 1;
//获取配置文件最后修改时间
    if (stat("/home/logan/CLionProjects/Capture/mytest1.conf", &configure_buf) != 0)
        perror("显示文件状态信息出错");//并提示出错的原因，如No such file or directory（无此文件或索引）
    else {
       //printf("文件修改时间: %ld\n", configure_buf.st_ctime);
        update_time = configure_buf.st_ctime;
    }
    while (flag) {
//获取配置文件最后修改时间，并检查是否更新
        stat("/home/logan/CLionProjects/Capture/mytest1.conf", &configure_buf);
//如果配置文件更新了，重新读配置文件使配置生效；若没更新，继续循环
        if (configure_buf.st_mtime != update_time) {
           printf("config update!!!\n");
            re = configure1();
            unsigned long int src_ip_host;
            unsigned long int dst_ip_host;
            unsigned long int mask_ip_host;
            unsigned long int src_mask_ip_host;
            unsigned long int dst_mask_ip_host;
            update_time = configure_buf.st_mtime;
            while ((iter = ccl_iterate(&re)) != 0) {
//若网卡修改了，跳出回调函数
                if (strcmp(iter->key, "net_interface") == 0 && strcmp(net_interface, iter->value) != 0) {
                   //printf("net_interface update!!!!\n");
                    strcpy(net_interface, iter->value);
                    pcap_breakloop(pcap_handle);
                }
                if (strcmp(iter->key, "source_address") == 0) {
                    struct in_addr src_ip;
                    inet_aton(iter->value, &src_ip);
                    src_ip_host = ntohl(src_ip.s_addr);
//                    printf("sip=%lu\n", src_ip_host);
                } else if (strcmp(iter->key, "destination_address") == 0) {
                    struct in_addr des_ip;
                    inet_aton(iter->value, &des_ip);
                    dst_ip_host = ntohl(des_ip.s_addr);
//                    printf("dip=%lu\n", dst_ip_host);
                }  else if (strcmp(iter->key, "mask") == 0) {
                    struct in_addr mask;
                    inet_aton(iter->value, &mask);
                    mask_ip_host = ntohl(mask.s_addr);
//                    printf("mask=%lu\n", mask_ip_host);
                } else if (strcmp(iter->key, "source_port") == 0) {
                    strcpy(s_port, iter->value);
//                    printf("配置s_port为:%s\n", s_port);
                } else if (strcmp(iter->key, "destination_port") == 0) {
                    strcpy(d_port, iter->value);
//                    printf("配置d_port为:%s\n", d_port);
                } else if (strcmp(iter->key, "file_size") == 0) {
                    strcpy(file_size, iter->value);
//                    printf("配置file_size为%s\n", file_size);
                } else if (strcmp(iter->key, "save_path") == 0) {
                    strcpy(path, iter->value);
//                    printf("配置save_path为%s\n", path);
                } else if (strcmp(iter->key, "file_time") == 0) {
                    file_time = atoi(iter->value);
//                    printf("配置file_time为%d\n", file_time);
                }
            }
            struct in_addr s_addr;
            struct in_addr d_addr;
            src_mask_ip_host = htonl(src_ip_host & mask_ip_host);
            memcpy(&s_addr,&src_mask_ip_host,4);
            strcpy(src_add, inet_ntoa(s_addr));
            printf("%s\n", src_add);
            dst_mask_ip_host = htonl(dst_ip_host & mask_ip_host);
            memcpy(&d_addr,&dst_mask_ip_host,4);
            strcpy(des_add, inet_ntoa(d_addr));
            printf("%s\n", des_add);
        }
    }
}
pcap_t *pcap_handle;
pcap_dumper_t *out_pcap;
int packet_number = 1;
struct stat cap_buf;//获取保存文件创建时间
time_t rawtime;
int first_file_flag = 0;//标志位，0代表判断需要打开第一个文件
int next_file = 1;//给保存文件命名的编号
char* final_path;//拼成文件保存的路径以及给保存文件命名，格式为file_path + .cap + next_file
unsigned int current_size = 24;//计算保存文件加上当前数据包的大小，若超过file_size，打开新文件保存
char net_interface[5];
char src_add[16];
char des_add[16];
char s_port[5];
char d_port[5];
char file_size[8];//最大分片大小
char path[50];//保存路径
int file_time;//最大记录时长
pthread_mutex_t hash_mutex;
/*pthread_mutex_t queue_mutex;

void capture_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content) {
    pthread_mutex_lock(&queue_mutex);
    en_queue(cap_queue, packet_header, packet_content);
    pthread_mutex_unlock(&queue_mutex);
}*/

int main() {
//启动检查更新线程
    pthread_t check;
    pthread_t delete;
    pthread_t p_queue;
    init_hashlist(TCAP_hash);
/*    cap_queue = (Queue *) malloc(sizeof(Queue));
    init_queue(cap_queue);

    pthread_create(&p_queue,NULL,(void*)cap_analysis,NULL);*/
    pthread_create(&delete,NULL,(void*)hash_analysis,NULL);
    pthread_create(&check, NULL, (void *) check_update, NULL);
    pthread_mutex_init(&hash_mutex, NULL);

    int up_key = 0;//网卡修改后的标志位
    char error_content[PCAP_ERRBUF_SIZE];
    struct bpf_program bpf_filter;
    char bpf_filter_string[] = "";
    bpf_u_int32 net_mask;
    bpf_u_int32 net_ip;
    Restart:
//网卡修改，需要重新给pcap设置网卡
    if (up_key == 1) {
        if (strcmp(net_interface, "") != 0) {
            pcap_lookupnet(net_interface, &net_ip, &net_mask, error_content);
            pcap_handle = pcap_open_live(net_interface, BUFSIZ, 1, 1, error_content);
        } else {
            pcap_lookupnet("ens33", &net_ip, &net_mask, error_content);
            pcap_handle = pcap_open_live("ens33", BUFSIZ, 1, 1, error_content);
        }
       //printf("配置net_interface为%s\n", net_interface);
    }
//程序启动，第一次让配置文件生效，这样check_update线程判断配置文件修改了再生效配置
    if (up_key == 0) {
        re = configure1();
        unsigned long int src_ip_host;
        unsigned long int dst_ip_host;
        unsigned long int mask_ip_host;
        unsigned long int src_mask_ip_host;
        unsigned long int dst_mask_ip_host;
//设置网卡
        while ((iter = ccl_iterate(&re)) != 0) {
            if (strcmp(iter->key, "net_interface") == 0) {
               //printf("配置%s为: %s\n", iter->key, iter->value);
                strcpy(net_interface, iter->value);
                if (strcmp(iter->value, "") != 0) {
                    pcap_lookupnet(iter->value, &net_ip, &net_mask, error_content);
                    pcap_handle = pcap_open_live(iter->value, BUFSIZ, 1, 1, error_content);
                } else {
                    pcap_lookupnet("ens33", &net_ip, &net_mask, error_content);
                    pcap_handle = pcap_open_live("ens33", BUFSIZ, 1, 1, error_content);
                }
            } else if (strcmp(iter->key, "source_address") == 0) {
                struct in_addr src_ip;
                inet_aton(iter->value, &src_ip);
                src_ip_host = ntohl(src_ip.s_addr);
//                printf("sip=%lu\n", src_ip_host);
            } else if (strcmp(iter->key, "destination_address") == 0) {
                struct in_addr des_ip;
                inet_aton(iter->value, &des_ip);
                dst_ip_host = ntohl(des_ip.s_addr);
//                printf("dip=%lu\n", dst_ip_host);
            }  else if (strcmp(iter->key, "mask") == 0) {
                struct in_addr mask;
                inet_aton(iter->value, &mask);
                mask_ip_host = ntohl(mask.s_addr);
//                printf("mask=%lu\n", mask_ip_host);
            } else if (strcmp(iter->key, "source_port") == 0) {
                strcpy(s_port, iter->value);
            } else if (strcmp(iter->key, "destination_port") == 0) {
                strcpy(d_port, iter->value);
            } else if (strcmp(iter->key, "file_size") == 0) {
                strcpy(file_size, iter->value);
            } else if (strcmp(iter->key, "save_path") == 0) {
                strcpy(path, iter->value);
                //拼保存文件的路径
                final_path = (char *) malloc(strlen(path) + 10);
                sprintf(final_path, "%s%s", path, "pcap");
                sprintf(final_path, "%s%d", final_path, next_file);
                sprintf(final_path, "%s%s", final_path, ".cap");
               //printf("all path is:%s\n", final_path);
            } else if (strcmp(iter->key, "file_time") == 0) {
                file_time = atoi(iter->value);
            }
        }
        struct in_addr s_addr;
        struct in_addr d_addr;
        src_mask_ip_host = htonl(src_ip_host & mask_ip_host);
        memcpy(&s_addr,&src_mask_ip_host,4);
        strcpy(src_add, inet_ntoa(s_addr));
        printf("%s\n", src_add);
        dst_mask_ip_host = htonl(dst_ip_host & mask_ip_host);
        memcpy(&d_addr,&dst_mask_ip_host,4);
        strcpy(des_add, inet_ntoa(d_addr));
        printf("%s\n", des_add);
        ccl_release(&re);
        up_key = 1;
    }
    pcap_compile(pcap_handle, &bpf_filter, bpf_filter_string, 0, net_ip);
    pcap_setfilter(pcap_handle, &bpf_filter);
    if (pcap_datalink(pcap_handle) != DLT_EN10MB)
        return 0;

    pcap_loop(pcap_handle, -1, cap_analysis, NULL);
   //printf("end!!!!!!!\n");
    pcap_close(pcap_handle);
   //printf("restart\n");
    goto Restart;
    return 0;
}
