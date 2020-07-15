//
// Created by root on 20-5-6.
//
#include "delete_hash.h"

void *hash_analysis() {
    int flag = 0;
    int i;
   // printf("udp delete start\n");
    while (flag < 1) {
        for (i = 0; i < 65535; i++) {
            pthread_mutex_lock(&hash_mutex);
            if (TCAP_hash[i].first != NULL) {
                struct timeval end;
                gettimeofday(&end, NULL);
                if ((end.tv_sec - TCAP_hash[i].first->start.tv_sec) * 10000000 +
                    (end.tv_usec - TCAP_hash[i].first->start.tv_usec) >= 20000000) {
                    delete_hash(TCAP_hash, TCAP_hash[i].first->tupl4);
                }
            }
            pthread_mutex_unlock(&hash_mutex);
        }
    }
}

