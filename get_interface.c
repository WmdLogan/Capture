#include <stdio.h>
#include "pcap.h"

void main() {
    char error_content[PCAP_ERRBUF_SIZE];
    struct in_addr net_ip_address;
    struct in_addr net_mask_address;
    char *net_interface;
    char *net_ip_string;
    char *net_mask_string;
    u_int32_t net_ip;
    u_int32_t net_mask;
    net_interface = pcap_lookupdev(error_content);
    pcap_lookupnet(net_interface, &net_ip, &net_mask, error_content);
    printf("Network Interface is :%s\n", net_interface);
    net_ip_address.s_addr = net_ip;
    net_ip_string = inet_ntoa(net_ip_address);
    printf("Netword IP Address is :%s\n", net_ip_string);
    net_mask_address.s_addr = net_mask;
    net_mask_string = inet_ntoa(net_mask_address);
    printf("Netword Mask Address is :%s\n", net_mask_string);
}
