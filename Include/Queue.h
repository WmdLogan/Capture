//
// Created by root on 2020/6/24.
//

#ifndef CAPTURE_QUEUE_H
#define CAPTURE_QUEUE_H

#include <sys/param.h>
#include <pcap.h>

#define MaxSize 2018
typedef struct  {
    struct pcap_pkthdr *packet_header;
    u_char *packet_content;
}Packet;

typedef struct
{
    int front;
    int rear;
    Packet data[MaxSize];
}Queue;
Queue *cap_queue;
void init_queue(Queue *queue);
int en_queue(Queue *queue, struct pcap_pkthdr *packet_header, u_char *packet_content);
int de_queue(Queue *queue, struct pcap_pkthdr *packet_header, u_char *packet_content);
#endif //CAPTURE_QUEUE_H
