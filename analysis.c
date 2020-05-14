#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<netinet/in.h>
#include<time.h>
#include "pcap.h"
#include <arpa/inet.h>

#define BUFSIZE 1024
#define STRSIZE 1024

//数据帧头
/*typedef struct FramHeader_t
{ //Pcap捕获的数据帧头
    u_int8 DstMAC[6]; //目的MAC地址
    u_int8 SrcMAC[6]; //源MAC地址
    u_short FrameType;    //帧类型
} FramHeader_t;*/
//IP数据报头
/*typedef struct IPHeader_t
{ //IP数据报头
    u_int8 Ver_HLen;       //版本+报头长度
    u_int8 TOS;            //服务类型
    u_int16 TotalLen;       //总长度
    u_int16 ID; //标识
    u_int16 Flag_Segment;   //标志+片偏移
    u_int8 TTL;            //生存周期
    u_int8 Protocol;       //协议类型
    u_int16 Checksum;       //头部校验和
    u_int32 SrcIP; //源IP地址
    u_int32 DstIP; //目的IP地址
} IPHeader_t;*/

//TCP数据报头
/*typedef struct TCPHeader_t
{ //TCP数据报头
    u_int16 SrcPort; //源端口
    u_int16 DstPort; //目的端口
    u_int32 SeqNO; //序号
    u_int32 AckNO; //确认号
    u_int8 HeaderLen; //数据报头的长度(4 bit) + 保留(4 bit)
    u_int8 Flags; //标识TCP不同的控制消息
    u_int16 Window; //窗口大小
    u_int16 Checksum; //校验和
    u_int16 UrgentPointer;  //紧急指针
}TCPHeader_t;*/
//包头定义
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

//
int main() {
    struct pcap_file_header *file_header;
    struct pcap_pkthdr *ptk_header;
    struct ip_header *ip_header;
    struct tcp_header *tcp_header;
    struct udp_header *udp_header;
    FILE *fp, *output;
    int pkt_offset, i = 0;
    int ip_len, ip_protocol;
    u_short src_port, dst_port;
    char buf[1024], my_time[STRSIZE];
    char src_ip[STRSIZE], dst_ip[STRSIZE];
//初始化
    file_header = (struct pcap_file_header *) malloc(sizeof(struct pcap_file_header));
    ptk_header = (struct pcap_pkthdr *) malloc(sizeof(struct pcap_pkthdr));
    ip_header = (struct ip_header *) malloc(sizeof(struct ip_header));
    tcp_header = (struct tcp_header *) malloc(sizeof(struct tcp_header));
//
    if ((fp = fopen("/home/logan/pcap2.cap", "r")) == NULL) {
        printf("error: can not open pcap file\n");
        exit(0);
    }
    fseek(fp, 0, SEEK_SET);

    if ((output = fopen("/home/logan/pcap1.cap", "a+")) == NULL) {
        exit(0);
    }
    fseek(output, 0, SEEK_END);

/*    pkt_offset = 24; //pcap文件头结构 24个字节
    fseek(fp, pkt_offset, SEEK_SET);*/
    char ch;
    while ((ch = fgetc(fp)) != EOF){
        fputc(ch, stdout);
        printf("%c", stdout);
        fputc(ch, output);
    }
    printf("This is the end!\n");
/*    fseek(fp, 0, SEEK_SET);
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        fputs(buf, output);
        printf("%s", buf);
        printf("next!!!!\n");
    }*/
//        fwrite(buf, strlen(buf), 1, output);
    fclose(output);
    fclose(fp);
//开始读数据包
    /* while (fseek(fp, pkt_offset, SEEK_SET) == 0) //遍历数据包
     {
         i++;
         printf("packet NO.%d\n", i);
         printf("pkt_offset =%d\n", pkt_offset);
         //pcap 数据包头结构 16个字节
         if (fread(ptk_header, 16, 1, fp) != 1) //读pcap数据包头结构
         {
             printf("\nread end of pcap file\n");
             break;
         }
         printf("length =%d\n", ptk_header->len);

         pkt_offset += 16;
         pkt_offset += ptk_header->caplen;   //下一个数据包的偏移值
         //数据帧头 14字节
         fseek(fp, 14, SEEK_CUR); //忽略数据帧头
         //IP数据报头 20字节
         if (fread(ip_header, sizeof(struct ip_header), 1, fp) != 1) {
             printf("%d: can not read ip_header\n", i);
             break;
         }
 //        inet_ntoa(AF_INET, (void *)&(ip_header->ip_source_address), src_ip, 16);
         strcpy(src_ip, inet_ntoa(ip_header->ip_source_address));
         strcpy(dst_ip, inet_ntoa(ip_header->ip_destination_address));
 //        inet_ntop(AF_INET, (void *)&(ip_header->ip_destination_address), dst_ip, 16);
         printf("src_ip = %s\n", src_ip);
         printf("dst_ip = %s\n", dst_ip);
         ip_protocol = ip_header->ip_protocol;
         ip_len = ip_header->ip_length; //IP数据报总长度
         // printf("%d:  src=%s\n", i, src_ip);
         if (ip_protocol != 0x06) //判断是否是 TCP 协议
         {
             continue;
         }
         printf("THIS PACKET IS TCP PROTOCOL!!!!!!!\n");

         //TCP头 20字节
         if (fread(tcp_header, sizeof(struct tcp_header), 1, fp) != 1) {
             printf("%d: can not read ip_header\n", i);
             break;
         }
         src_port = ntohs(tcp_header->tcp_source_port);
         dst_port = ntohs(tcp_header->tcp_destination_port);
         printf("src_port = %d\n", src_port);
         printf("dst_port = %d\n", dst_port);
     } */

    return 0;
}
