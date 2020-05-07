
#include "check_update.h"

void check_update() {
//获得文件状态信息
    result = stat("/home/logan/CLionProjects/Capture/mytest.conf", &buf);
    int flag = 1;
//显示文件状态信息
    if (result != 0)
        perror("显示文件状态信息出错");//并提示出错的原因，如No such file or directory（无此文件或索引）
    else {
        printf("文件修改时间: %ld\n", buf.st_ctime);
        update_time = buf.st_ctime;
    }
    while (flag) {
        //check configure update
        result = stat("/home/logan/CLionProjects/Capture/mytest.conf", &buf);
        if (buf.st_mtime != update_time) {
            printf("config update!!!\n");
            struct ccl_t re = configure();
            const struct ccl_pair_t *iter;
            update_time = buf.st_mtime;
            while ((iter = ccl_iterate(&re)) != 0) {
                if (strcmp(iter->key, "net_interface") == 0 && strcmp(net_interface, iter->value) != 0) {
                    printf("net_interface update!!!!\n");
                    strcpy(net_interface, iter->value);
                    pcap_breakloop(pcap_handle);
                }
                if (strcmp(iter->key, "source_address") == 0) {
                    strcpy(src_add, iter->value);
                } else if (strcmp(iter->key, "destination_address") == 0) {
                    strcpy(des_add, iter->value);
                } else if (strcmp(iter->key, "source_port") == 0) {
                    strcpy(s_port, iter->value);
                } else if (strcmp(iter->key, "destination_port") == 0) {
                    strcpy(d_port, iter->value);
                } else if (strcmp(iter->key, "file_size") == 0) {
                    strcpy(file_size, iter->value);
                } else if (strcmp(iter->key, "save_path") == 0) {
                    strcpy(path, iter->value);
                }
            }
            printf("配置s_add为:%s\n", src_add);
            printf("配置d_add为:%s\n", des_add);
            printf("配置s_port为:%s\n", s_port);
            printf("配置d_port为:%s\n", d_port);
            printf("配置net_interface为%s\n", net_interface);
            printf("配置file_size为%s\n", file_size);
            printf("配置save_path为%s\n", path);
        }
    }
}
/*
int main(){
    check_update();
}
*/
