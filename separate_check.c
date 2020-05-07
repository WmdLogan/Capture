#include "separate_check.h"
#include "Configure.h"
#include "string.h"
#include "stdlib.h"

void capture_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content) {
    printf("get new packet!!!\n");

    pcap_dump((u_char *) out_pcap1, packet_header, packet_content);
    pcap_dump_flush(out_pcap1);

    printf("Received Packet Size: %d\n", packet_header->len);
    current_size += packet_header->len + 16;
    printf("current size is = %d\n", current_size);
    if (current_size < atoi(file_size)) {
        pcap_dump((u_char *) out_pcap, packet_header, packet_content);
        pcap_dump_flush(out_pcap);
    } else {
        printf("new file!!!!!\n");
        next_file++;
        pcap_dump_close(out_pcap);
        //get new file path
        sprintf(final_path, "%s%s", path, "pcap");
        sprintf(final_path, "%s%d", final_path, next_file);
        sprintf(final_path, "%s%s", final_path, ".cap");
        printf("all path is:%s\n", final_path);
        //open new file
        out_pcap = pcap_dump_open(pcap_handle, final_path);
        pcap_dump((u_char *) out_pcap, packet_header, packet_content);
        pcap_dump_flush(out_pcap);

        current_size = packet_header->len + 24;
    }

}

int main() {
    current_size = 24;
    struct ccl_t re = configure();
    const struct ccl_pair_t *iter;
    while ((iter = ccl_iterate(&re)) != 0) {
        if (strcmp(iter->key, "file_size") == 0) {
            strcpy(file_size, iter->value);
        } else if (strcmp(iter->key, "save_path") == 0) {
            strcpy(path, iter->value);
        }

    ccl_release(&re);
    char error_content[PCAP_ERRBUF_SIZE];
    struct bpf_program bpf_filter;
    char bpf_filter_string[] = "";
    bpf_u_int32 net_mask;
    bpf_u_int32 net_ip;
    pcap_lookupnet("ens33", &net_ip, &net_mask, error_content);
    pcap_handle = pcap_open_live("ens33", BUFSIZ, 1, 1, error_content);

    pcap_compile(pcap_handle, &bpf_filter, bpf_filter_string, 0, net_ip);
    pcap_setfilter(pcap_handle, &bpf_filter);
    if (pcap_datalink(pcap_handle) != DLT_EN10MB)
        return 0;
    final_path = (char *) malloc(strlen(path) + 5);
    sprintf(final_path, "%s%s", path, "pcap");
    sprintf(final_path, "%s%d", final_path, next_file);
    sprintf(final_path, "%s%s", final_path, ".cap");
    printf("all path is:%s\n", final_path);
    out_pcap = pcap_dump_open(pcap_handle, final_path);
    out_pcap1 = pcap_dump_open(pcap_handle, "/home/logan/all.cap");

    pcap_loop(pcap_handle, -1, capture_callback, NULL);
    printf("exit!@!!!! next_file = %d\n", next_file);

    pcap_close(pcap_handle);

    return 0;
}