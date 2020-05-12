//
// Created by root on 20-4-28.
//
#include "nids.h"
#include "stdlib.h"
#include "pcap.h"
#include <stdint.h>
#include <sys/time.h>
#include "Capture.h"
#define HashMaxSize 65535
struct ip_and_port
{
    u_short source_port;
    u_short dest_port;
    u_int source_ip;
    u_int dest_ip;
};
typedef struct hash_list   //哈希表
{
    struct hash_node *first;   //指向的第一个节点
}hash_list[HashMaxSize];
struct hash_list  TCAP_hash[HashMaxSize];
typedef struct hash_node   //冲突结点
{
    int ttl;
    bpf_u_int32 len;
    int number;
    int average_len;
    int mask;
    struct ip_and_port tupl4; //四元组
    struct hash_node *next; //处理冲突用的指针
    struct timeval start;
}hash_node;
void init_hashlist(hash_list hash);
unsigned int hash_key(struct ip_and_port tupl4);
void insert_hash(const u_char *packet_content,hash_list Hashlist,bpf_u_int32 length);
int cmp_tuple(struct ip_and_port a,struct ip_and_port b);
void delete_hash(hash_list hashList,struct ip_and_port addr);