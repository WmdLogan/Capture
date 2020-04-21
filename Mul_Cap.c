#include "pcap.h"
void packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char * packet_content){
    static int packet_number = 1;
    printf("The %d packet is captured. \n", packet_number);
    packet_number++;
}
void main(){
    pcap_t *pcap_handle;
    char error_content[PCAP_ERRBUF_SIZE]; //error info
    char *net_interface;
    struct bpf_program bpf_filter; //bpf rules
    char bpf_filter_string[] = "ip";
    bpf_u_int32 net_mask;
    bpf_u_int32 net_ip;
    net_interface = pcap_lookupdev(error_content);
    //get interface info
    pcap_lookupnet(net_interface, &net_ip, &net_mask, error_content);
    //open interface
    pcap_handle = pcap_open_live(net_interface, BUFSIZ, 1, 0, error_content);
    //compile bpf rules
    pcap_compile(pcap_handle, &bpf_filter, bpf_filter_string, 0, net_ip);
    //set bpf rules
    pcap_setfilter(pcap_handle, &bpf_filter);
    pcap_loop(pcap_handle, 15, packet_callback, NULL);
    pcap_close(pcap_handle);
}