#include "pcap.h"
#include "Ethernet_Cap.h"
#include "ccl/ccl.h"

void main() {

    pcap_t *pcap_handle;
    char error_content[PCAP_ERRBUF_SIZE];
    char *net_interface;
    struct bpf_program bpf_filter;
    char bpf_filter_string[] = "http";
    bpf_u_int32 net_mask;
    bpf_u_int32 net_ip;

  //  net_interface = pcap_lookupdev(error_content);
    pcap_lookupnet("ens33", &net_ip, &net_mask, error_content);
    //open interface
    pcap_handle = pcap_open_live("ens33", BUFSIZ, 1, 1, error_content);
    //compile and set bpf rules
    pcap_compile(pcap_handle, &bpf_filter, bpf_filter_string, 0, net_ip);
    pcap_setfilter(pcap_handle, &bpf_filter);
    if (pcap_datalink(pcap_handle) != DLT_EN10MB)
        return;
    //-1 means endless capture
    pcap_loop(pcap_handle, -1, ethernet_protocol_packet_callback, NULL);
    pcap_close(pcap_handle);
}

