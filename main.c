#include "pcap.h"
#include "Ethernet_Cap.h"
#include "ccl/ccl.h"
#include "Configure.h"
#include "string.h"
#include "Capture.h"
#include <sys/stat.h>

int main() {
    struct stat buf;
    int result;
    //获得文件状态信息
    result =stat( "/home/logan/CLionProjects/Capture/mytest.conf", &buf );
    //显示文件状态信息
    if( result != 0 )
        perror( "显示文件状态信息出错" );//并提示出错的原因，如No such file or directory（无此文件或索引）
    else
    {
        printf("文件修改时间: %ld\n", buf.st_ctime);
        update_time = buf.st_ctime;
    }
    char error_content[PCAP_ERRBUF_SIZE];
    struct bpf_program bpf_filter;
    char bpf_filter_string[] = "";
    bpf_u_int32 net_mask;
    bpf_u_int32 net_ip;
    struct ccl_t re = configure();
    const struct ccl_pair_t *iter;
    // net_interface filter
    while ((iter = ccl_iterate(&re)) != 0) {
        if (strcmp(iter->key, "net_interface") == 0) {
            printf("配置%s为: %s\n", iter->key, iter->value);
            if(strcmp(iter->value, "") != 0){ //value is not null
                pcap_lookupnet(iter->value, &net_ip, &net_mask, error_content);
                pcap_handle = pcap_open_live(iter->value, BUFSIZ, 1, 1, error_content);
            } else{
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
    //compile and set bpf rules
    pcap_compile(pcap_handle, &bpf_filter, bpf_filter_string, 0, net_ip);
    pcap_setfilter(pcap_handle, &bpf_filter);
    if (pcap_datalink(pcap_handle) != DLT_EN10MB)
        return 0;
    //-1 means endless capture
    pcap_loop(pcap_handle, -1, capture_callback, (u_char *) buf.st_ctime);
    pcap_close(pcap_handle);
    return 0;
}

