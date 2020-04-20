#include <time.h>
#include "pcap.h"

struct ether_header {
    u_int8_t ether_dhost[6]; //des ether
    u_int8_t ether_shost[6];//src ether
    u_int16_t ether_type;//ether type
};

void main() {
    char error_content[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle;
    //packet cache
    const u_char *packet_content;
    u_char *mac_string;
    u_short ethernet_type;
    bpf_u_int32 net_mask;
    bpf_u_int32 net_ip;
    char *net_interface;

    struct pcap_pkthdr protocol_header;
    struct ether_header *ethernet_protocol;

    struct bpf_program bpf_filter;
    char bpf_filter_string[] = "ip";
    //get interface
    net_interface = pcap_lookupdev(error_content);
    pcap_lookupnet(net_interface, &net_ip, &net_mask, error_content);
    //open interface
    pcap_handle = pcap_open_live(net_interface, BUFSIZ, 1, 0, error_content);
    //compile and set bpf rules
    pcap_compile(pcap_handle, &bpf_filter, bpf_filter_string, 0, net_ip);
    pcap_setfilter(pcap_handle, &bpf_filter);
    if (pcap_datalink(pcap_handle) != DLT_EN10MB)
        return;
    //get packet byte stream
    packet_content = pcap_next(pcap_handle, &protocol_header);

    printf("------------------*****------------------\n");
    printf("Capture a Packet from net_interface :\n");
    printf("%s \n", net_interface);
    printf("Capture Time is: \n");
    printf("%s", ctime((const time_t *) &protocol_header.ts.tv_sec));
    printf("Packet Length is: \n");
    printf("%d\n", protocol_header.len);
    //convert packet type to ethernet
    ethernet_protocol = (struct ether_header *) packet_content;
    printf("Ethernet type is :\n");
    //get ehernet's type, which shows IP_layer's protocol type;
    ethernet_type = ntohs(ethernet_protocol->ether_type);
    printf("%04x\n", ethernet_type);
    switch (ethernet_type) {
        case 0x0800:
            printf("the network layer is ip protocol\n");
            break;
        case 0x0806:
            printf("the network layer is arp protocol\n");
            break;
        case 0x8035:
            printf("the network layer is rarp protocol\n");
            break;
        default:
            break;
    }

    printf("Mac source Address is : \n");
    mac_string = ethernet_protocol->ether_shost;
    printf("%02x:%02x:%02x:%02x:%02x:%02x:\n", *mac_string, *(mac_string + 1), *(mac_string + 2)
            , *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));

    printf("Mac source Address is : \n");
    mac_string = ethernet_protocol->ether_dhost;
    printf("%02x:%02x:%02x:%02x:%02x:%02x:\n", *mac_string, *(mac_string + 1), *(mac_string + 2)
            , *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));
    printf("------------------*****------------------\n");
    pcap_close(pcap_handle);
}