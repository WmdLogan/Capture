#include "pcap.h"
#include "Ethernet_Cap.h"
#include "ccl/ccl.h"
#include "Configure.h"
#include "string.h"
int main() {
    pcap_t *pcap_handle;
    char error_content[PCAP_ERRBUF_SIZE];
    struct bpf_program bpf_filter;
    char bpf_filter_string[] = "tcp port 80 && src 192.168.2.101 ";
    bpf_u_int32 net_mask;
    bpf_u_int32 net_ip;
    struct ccl_t re = configure();
    const struct ccl_pair_t *iter;
    while ((iter = ccl_iterate(&re)) != 0) {
        if (strcmp(iter->key, "net_interface") == 0) {
            printf("%s: %s\n", iter->key, iter->value);
            if(strcmp(iter->value, "") != 0){ //value is not null
                pcap_lookupnet(iter->value, &net_ip, &net_mask, error_content);
                pcap_handle = pcap_open_live(iter->value, BUFSIZ, 1, 1, error_content);

            } else{
                pcap_lookupnet("ens33", &net_ip, &net_mask, error_content);
                pcap_handle = pcap_open_live("ens33", BUFSIZ, 1, 1, error_content);
            }

        } else if (strcmp(iter->key, "source_address") == 0) {
            printf("%s: %s\n", iter->key, iter->value);
        } else if (strcmp(iter->key, "source_port") == 0) {
            printf("%s: %s\n", iter->key, iter->value);
        } else if (strcmp(iter->key, "destination_address") == 0) {
            printf("%s: %s\n", iter->key, iter->value);
        } else if (strcmp(iter->key, "destination_port") == 0) {
            printf("%s: %s\n", iter->key, iter->value);
        } else { continue; }

    }
    ccl_release(&re);
    //compile and set bpf rules
    pcap_compile(pcap_handle, &bpf_filter, bpf_filter_string, 0, net_ip);
    pcap_setfilter(pcap_handle, &bpf_filter);
    if (pcap_datalink(pcap_handle) != DLT_EN10MB)
        return 0;
    //-1 means endless capture
    pcap_loop(pcap_handle, -1, ethernet_protocol_packet_callback, NULL);
    pcap_close(pcap_handle);
    return 0;
}

