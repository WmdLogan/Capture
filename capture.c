#include "pcap.h"

void main(){
    char error_content[PCAP_ERRBUF_SIZE]; //error info
    struct pcap_pkthdr protocol_header; //packet head info
    pcap_t *pcap_handle = NULL;
    struct bpf_program bpf_filter; //bpf rules
    char bpf_filter_string[] = "";
    const u_char *packet_content; //packet data buff
    bpf_u_int32 net_ip;
    bpf_u_int32 net_mask;
    char *net_interface;
    net_interface = pcap_lookupdev(error_content);
    //get interface info
    pcap_lookupnet(net_interface, &net_ip, &net_mask, error_content);
    //open interface
    pcap_handle = pcap_open_live(net_interface, BUFSIZ, 1, 0, error_content);
    //compile bpf rules
    pcap_compile(pcap_handle, &bpf_filter, bpf_filter_string, 0, net_ip);
    //set bpf rules
    pcap_setfilter(pcap_handle, &bpf_filter);
    //capture a packet and return it
    packet_content = pcap_next(pcap_handle, &protocol_header);
    printf("Capture a packet from ens33\n");
    printf("The packet length is :%d\n", protocol_header.len);
    pcap_close(pcap_handle);
}