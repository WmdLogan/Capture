//
// Created by root on 20-5-6.
//
#include "delete_hash.h"
void *hash_analysis()
{
    int flag=0;
    printf("udp delete start\n");
    while(flag<1)
    {
        for(int i=0; i < 65535 ; i++){
            if(TCAP_hash[i].first!=NULL)
            {
                struct timeval end;
                gettimeofday(&end,NULL);
                if((end.tv_sec-TCAP_hash[i].first->start.tv_sec)*1000000+(end.tv_usec-TCAP_hash[i].first->start.tv_usec)>=6000000)
                {
                    delete_hash(TCAP_hash,TCAP_hash[i].first->tupl4);
                }
            }
        }
    }
}

