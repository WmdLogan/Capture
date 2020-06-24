//
// Created by root on 2020/6/24.
//

#include "Queue.h"
#include <string.h>
#include <stdlib.h>

void init_queue(Queue *queue) {
    queue->front = 0;
    queue->rear = 0;
}
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

int en_queue(Queue *queue, struct pcap_pkthdr *packet_header, u_char *packet_content) {
    if ((queue->rear + 1) % MaxSize == queue->front)//队满
    { return 0; }
    queue->data[queue->rear].packet_header = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
    queue->data[queue->rear].packet_content = (u_char *)malloc(sizeof(u_char) * 1600);

    memcpy(queue->data[queue->rear].packet_header, packet_header, sizeof(struct pcap_pkthdr));
    memcpy(queue->data[queue->rear].packet_content, packet_content, sizeof(u_char) * 1600);


    queue->rear = (queue->rear + 1) % MaxSize;
    return 1;
}

int de_queue(Queue *queue, struct pcap_pkthdr *packet_header, u_char *packet_content) {
    if (queue->front == queue->rear)//队空
    {return 0;}

    memcpy(packet_header, queue->data[queue->front].packet_header, sizeof(struct pcap_pkthdr));
    memcpy(packet_content, queue->data[queue->front].packet_content, sizeof(u_char) * 1600);

    free(queue->data[queue->front].packet_header);
    free(queue->data[queue->front].packet_content);
    queue->front = (queue->front + 1) % MaxSize;
    return 1;
}