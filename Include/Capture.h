#include "pcap.h"
#include "string.h"
#include <sys/stat.h>
#include "time.h"
#include "pthread.h"
#include <stdlib.h>
#include "Configure.h"
#include "Queue.h"

//pcap 捕包初始化
extern pcap_t *pcap_handle;
extern pcap_dumper_t *out_pcap;

//包头定义
struct ether_header {
    u_int8_t ether_dhost[6]; //des ether
    u_int8_t ether_shost[6];//src ether
    u_int16_t ether_type;//ether type
};

struct tcp_header {
    u_int16_t tcp_source_port;
    u_int16_t tcp_destination_port;
    u_int32_t tcp_acknowledgement; //seq
    u_int32_t tcp_ack; //ack
#ifdef WORDS_BIGENDDIAN
    u_int8_t tcp_offset:4, tcp_reserved:4;
#else
    u_int8_t tcp_reserved:4, tcp_offset:4;
#endif
    u_int8_t tcp_flags;
    u_int16_t tcp_windows;
    u_int16_t tcp_checksum;
    u_int16_t tcp_urgent_pointer;
};

struct udp_header
{
    u_int16_t udp_source_port;
    u_int16_t udp_destination_port;
    u_int16_t udp_length;
    u_int16_t udp_checksum;
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
    struct in_addr ip_destination_address;
};

struct ip_hash_header {
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
    u_int i_ip_source_address;
    u_int i_ip_destination_address;
};

//配置文件
extern char net_interface[5];
extern char src_add[16];
extern char des_add[16];
extern char s_port[5];
extern char d_port[5];
extern char file_size[8];//最大分片大小
extern char path[50];//保存路径
extern int file_time;//最大记录时长
extern pthread_mutex_t hash_mutex;
extern pthread_mutex_t queue_mutex;

//file 分片保存用
extern int packet_number;//给所有捕获的包计数
extern struct stat cap_buf;//获取保存文件创建时间
extern time_t rawtime;//获取当前时间，与cap_buf进行比较，若超过file_time，打开新文件保存
extern int first_file_flag;//标志位，0代表判断需要打开第一个文件
extern int next_file;//给保存文件命名的编号
extern char* final_path;//拼成文件保存的路径以及给保存文件命名，格式为file_path + .cap + next_file
extern unsigned int current_size;//计算保存文件加上当前数据包的大小，若超过file_size，打开新文件保存


void cap_analysis(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content);
