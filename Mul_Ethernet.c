#include "pcap.h"
#include "Ip_Capture.h"
struct ether_header {
    u_int8_t ether_dhost[6]; //des ether
    u_int8_t ether_shost[6];//src ether
    u_int16_t ether_type;//ether type
};

void ethernet_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header,
                                       const u_char *packet_content) {
    u_short ethernet_type;
    struct ether_header *ethernet_protocol;
    u_char *mac_string;
    static int packet_number = 1;
    printf("------------------*****------------------\n");
    printf("The %d Ethernet packet is captured.\n", packet_number);
    printf("-----------  Ethernet protocol (Link Layer) ------------\n");
    printf("The %d Ethernet packet is captured.\n", packet_number);
    //get ethernet protocol data
    ethernet_protocol = (struct ether_header *) packet_content;
    //get type
    printf("Ethernet type is: \n");
    ethernet_type = ntohs(ethernet_protocol->ether_type);
    printf("%04x\n", ethernet_type);

    printf("Mac Source Address is : \n");
    mac_string = ethernet_protocol->ether_shost;
    printf("%02x:%02x:%02x:%02x:%02x:%02x:\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3),
           *(mac_string + 4), *(mac_string + 5));

    printf("Mac Destination Address is : \n");
    mac_string = ethernet_protocol->ether_dhost;
    printf("%02x:%02x:%02x:%02x:%02x:%02x:\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3),
           *(mac_string + 4), *(mac_string + 5));
    printf("------------------*****------------------\n");

    switch (ethernet_type) {
        case 0x0800:
            printf("the network layer is ip protocol\n");
            ip_protocol_packet_callback(argument, packet_header, packet_content);
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

    packet_number++;
}

void main() {
    pcap_t *pcap_handle;
    char error_content[PCAP_ERRBUF_SIZE];
    char *net_interface;
    struct bpf_program bpf_filter;
    char bpf_filter_string[] = "ip";
    bpf_u_int32 net_mask;
    bpf_u_int32 net_ip;

    //get interface
    // net_interface = pcap_findalldevs(pcap_handle, error_content);

    net_interface = pcap_lookupdev(error_content);
    pcap_lookupnet(net_interface, &net_ip, &net_mask, error_content);
    //open interface
    pcap_handle = pcap_open_live(net_interface, BUFSIZ, 1, 0, error_content);
    //compile and set bpf rules
    pcap_compile(pcap_handle, &bpf_filter, bpf_filter_string, 0, net_ip);
    pcap_setfilter(pcap_handle, &bpf_filter);
    if (pcap_datalink(pcap_handle) != DLT_EN10MB)
        return;
    //-1 means endless capture
    pcap_loop(pcap_handle, -1, ethernet_protocol_packet_callback, NULL);
    pcap_close(pcap_handle);
}



