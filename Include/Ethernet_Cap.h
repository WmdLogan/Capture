#include "pcap.h"
struct ether_header {
    u_int8_t ether_dhost[6]; //des ether
    u_int8_t ether_shost[6];//src ether
    u_int16_t ether_type;//ether type
};
void ethernet_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header,const u_char *packet_content);