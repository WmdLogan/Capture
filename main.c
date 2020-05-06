#include "pcap.h"
#include "ccl/ccl.h"
#include "Configure.h"
#include "string.h"
#include "pthread.h"
#include "check_update.h"

int main() {
    pthread_t check;
    pthread_create(&check, NULL, (void *)check_update, NULL);
    int up_key = 0;
    char error_content[PCAP_ERRBUF_SIZE];
    struct bpf_program bpf_filter;
    char bpf_filter_string[] = "";
    bpf_u_int32 net_mask;
    bpf_u_int32 net_ip;
Restart:
//restart
    if (up_key == 1) {
        if (strcmp(net_interface, "") != 0) { //value is not null
            pcap_lookupnet(net_interface, &net_ip, &net_mask, error_content);
            pcap_handle = pcap_open_live(net_interface, BUFSIZ, 1, 1, error_content);
        } else {
            pcap_lookupnet("ens33", &net_ip, &net_mask, error_content);
            pcap_handle = pcap_open_live("ens33", BUFSIZ, 1, 1, error_content);
        }
    }
//first commit
    if (up_key == 0) {
        struct ccl_t re = configure();
        const struct ccl_pair_t *iter;
        // net_interface filter
        while ((iter = ccl_iterate(&re)) != 0) {
            if (strcmp(iter->key, "net_interface") == 0) {
                printf("配置%s为: %s\n", iter->key, iter->value);
                strcpy(net_interface, iter->value);
                if (strcmp(iter->value, "") != 0) { //value is not null
                    pcap_lookupnet(iter->value, &net_ip, &net_mask, error_content);
                    pcap_handle = pcap_open_live(iter->value, BUFSIZ, 1, 1, error_content);
                } else {
                    pcap_lookupnet("ens33", &net_ip, &net_mask, error_content);
                    pcap_handle = pcap_open_live("ens33", BUFSIZ, 1, 1, error_content);
                }
            } else if (strcmp(iter->key, "source_address") == 0) {
                strcpy(src_add, iter->value);
            } else if (strcmp(iter->key, "destination_address") == 0) {
                strcpy(des_add, iter->value);
            } else if (strcmp(iter->key, "source_port") == 0) {
                strcpy(s_port, iter->value);
            } else if (strcmp(iter->key, "destination_port") == 0) {
                strcpy(d_port, iter->value);
            }
        }
        ccl_release(&re);
        up_key = 1;
    }

    pcap_compile(pcap_handle, &bpf_filter, bpf_filter_string, 0, net_ip);
    pcap_setfilter(pcap_handle, &bpf_filter);
    if (pcap_datalink(pcap_handle) != DLT_EN10MB)
        return 0;
    out_pcap = pcap_dump_open(pcap_handle, "/home/logan/pack.cap");

    //-1 means endless capture
    pcap_loop(pcap_handle, -1, capture_callback, NULL);
    printf("end!!!!!!!\n");
    pcap_close(pcap_handle);
    printf("restart\n");
    goto Restart;

    return 0;
}
