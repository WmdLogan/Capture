//
// Created by root on 20-4-28.
//
#include "hash.h"

void init_hashlist(hash_list hash) {
    int i = 0;
    for (i; i < 65535; i++) {
        hash[i].first = NULL;
    }
    //printf("%s\n", "<--------------initialize hash_list succeed------------->");
}

//compute hashKey
unsigned int hash_key(struct ip_and_port tupl4) {
    unsigned int bsip, asip, bdip, adip, sport, dport, hash, hash1;
    bsip = tupl4.source_ip >> 16;
    bsip = bsip & 0x0000FFFF;
    asip = tupl4.source_ip & 0x0000FFFF;
    sport = tupl4.source_port;
    bdip = tupl4.dest_ip >> 16;
    bdip = bdip & 0x0000FFFF;
    adip = tupl4.dest_ip & 0x0000FFFF;
    dport = tupl4.dest_port;
    hash1 = asip << 3 | asip >> (16 - 3);
    hash1 = hash1 ^ adip;
    hash = hash1;
    hash1 = adip << 3 | adip >> (16 - 3);
    hash1 = hash1 ^ asip;
    hash ^= hash1;
    hash1 = bsip << 3 | bsip >> (16 - 3);
    hash1 = hash1 ^ sport;
    hash ^= hash1;
    hash1 = bdip << 3 | bdip >> (16 - 3);
    hash1 = hash1 ^ dport;
    hash ^= hash1;
    hash = hash & 0x0000FFFF;
    return hash;
}

int cmp_tuple(struct ip_and_port a, struct ip_and_port b) {
    if ((a.dest_ip == b.dest_ip && a.dest_port == b.dest_port && a.source_port == b.source_port &&
         a.source_ip == b.source_ip) ||
        (a.dest_ip == b.source_ip && a.dest_port == b.source_port && a.source_port == b.dest_port &&
         a.source_ip == b.dest_ip)) {
        return 1;
    }
    return 0;
}

void delete_hash(hash_list List, struct ip_and_port addr) {
    int hashKey;
    hashKey = hash_key(addr);
    struct hash_node *hashNode;
    struct hash_node *hashNodePre;
    hashNodePre = List[hashKey].first;
    hashNode = List[hashKey].first->next;
    if (hashNodePre && cmp_tuple(hashNodePre->tupl4, addr))//match first hashNode
    {
        //printf("<--------------delete hashKey = %d-------------->\n\n\n", hash_key(addr));
        List[hashKey].first = hashNode;
        free(hashNodePre);
        //printf("%s\n\n\n", "<--------------delete first hash_node-------------->");
        return;
    }
    while (hashNode) {
        if (cmp_tuple(hashNode->tupl4, addr)) {
            //printf("<--------------delete hashKey = %d-------------->\n\n\n", hash_key(addr));
            hashNodePre->next = hashNode->next;
            free(hashNode);
            //printf("%s\n\n\n", "<--------------delete a hash_node-------------->");
            return;
        }
        hashNode = hashNode->next;
        hashNodePre = hashNodePre->next;
    }
    //printf("%s\n\n\n", "<--------------hash_node doesn't exist-------------->");
}

void insert_hash(const u_char *packet_content, hash_list Hashlist, bpf_u_int32 length) {
    struct ip_and_port addr;
    u_short ethernet_type;
    struct ether_header *ethernet_protocol = (struct ether_header *) packet_content;
    //get type
    ethernet_type = ntohs(ethernet_protocol->ether_type);
    struct tcp_header *tcp_protocol;
    struct udp_header *udp_protocol;
    struct ip_hash_header *ip_protocol;
    switch (ethernet_type) {
        case 0x0800: {
            printf("\n");
            ip_protocol = (struct ip_hash_header *) (packet_content + 14);
            addr.dest_ip = ip_protocol->i_ip_destination_address;
            addr.source_ip = ip_protocol->i_ip_source_address;
            //printf("dest ip:%d source ip:%d\n",addr.dest_ip,addr.source_ip);
            switch (ip_protocol->ip_protocol) {
                case 6: {
                    tcp_protocol = (struct tcp_header *) (packet_content + 14 + 20);
                    u_char flags;
                    addr.source_port = ntohs(tcp_protocol->tcp_source_port);
                    addr.dest_port = ntohs(tcp_protocol->tcp_destination_port);
                    flags = tcp_protocol->tcp_flags;
                    //printf("addr %d %d %d %d\n", addr.source_ip, addr.dest_ip, addr.source_port, addr.dest_port);
                    unsigned int hashkey = hash_key(addr);
                    //printf("addr hashkey=%d\n", hashkey);
                    struct hash_node *hashnode;
                    if (Hashlist[hashkey].first == NULL) {
                        // //printf("first\n");
                        hashnode = (struct hash_node *) malloc(sizeof(hash_node));
                        Hashlist[hashkey].first = hashnode;
                        hashnode->next = NULL;
                        gettimeofday(&hashnode->start, NULL);
                        hashnode->tupl4.dest_ip = ip_protocol->i_ip_destination_address;
                        hashnode->tupl4.source_ip = ip_protocol->i_ip_source_address;
                        hashnode->tupl4.dest_port = addr.dest_port;
                        hashnode->tupl4.source_port = addr.source_port;
                        hashnode->number = 1;
                        hashnode->mask = 0;
                        hashnode->ttl = (int) ip_protocol->ip_ttl;
                        hashnode->len = length;
//                        printf("Source address: %s\n", inet_ntoa(*((struct in_addr *) &(ip_protocol->i_ip_source_address))));
  //                      printf("Destination address: %s\n", inet_ntoa(*((struct in_addr *) &(ip_protocol->i_ip_destination_address))));
    //                    printf("source port=%d dst port=%d\n", hashnode->tupl4.source_port, hashnode->tupl4.dest_port);
      //                  printf("ttl=%d\n", hashnode->ttl);
        //                printf("number=%d\n", hashnode->number);
          //              printf("len=%d\n", hashnode->len);
            //            printf("average_len=%d\n", hashnode->len / hashnode->number);
                        return;
                    } else {
                        hashnode = Hashlist[hashkey].first;
                        while (hashnode) {
                            //printf("second\n");
                            if (cmp_tuple(hashnode->tupl4, addr)) {
                                hashnode->number = hashnode->number + 1;
                                gettimeofday(&hashnode->start, NULL);
                                //printf("hashnode ttl=%d\n",hashnode->ttl);
                                //printf("ip ttl=%d\n",ip_protocol->ip_ttl);
                                hashnode->ttl = hashnode->ttl + (int) ip_protocol->ip_ttl;
                                hashnode->len = hashnode->len + length;
              //                  printf("Source address: %s\n",inet_ntoa(*((struct in_addr *) &(ip_protocol->i_ip_source_address))));
                //                printf("Destination address: %s\n",inet_ntoa(*((struct in_addr *) &(ip_protocol->i_ip_destination_address))));
                  //              printf("source port=%d dst port=%d\n", hashnode->tupl4.source_port,hashnode->tupl4.dest_port);
                    //            printf("ttl=%d\n", hashnode->ttl);
                      //          printf("number=%d\n", hashnode->number);
                        //        printf("len=%d\n", hashnode->len);
                          //      printf("average_len=%d\n", hashnode->len / hashnode->number);
//                                if (flags & 0x08) { //printf("PSH\n"); }
                                if (flags & 0x10) {
                                    //printf("ACK\n");
                                    if (hashnode->mask == 2) {
                                        delete_hash(TCAP_hash, addr);
                                    }
                                }
                      /*          if (flags & 0x02) { //printf("SYN\n"); }
                                if (flags & 0x20) { //printf("URG\n"); }*/
                                if (flags & 0x01 && flags & 0x10) {
                                    //printf("FIN ");
                                    hashnode->mask++;
                                }
                                if (flags & 0x04) {
                                    //printf("RST\n");
                                    delete_hash(TCAP_hash, addr);
                                }
                                return;
                            }
                            hashnode = hashnode->next;
                        }
                        hashnode = (struct hash_node *) malloc(sizeof(hash_node));
                        hashnode->next = Hashlist[hashkey].first;
                        Hashlist[hashkey].first = hashnode;
                        gettimeofday(&hashnode->start, NULL);
                        hashnode->tupl4.dest_ip = ip_protocol->i_ip_destination_address;
                        hashnode->tupl4.source_ip = ip_protocol->i_ip_source_address;
                        hashnode->tupl4.dest_port = addr.dest_port;
                        hashnode->tupl4.source_port = addr.source_port;
                        hashnode->number = 1;
                        hashnode->mask = 0;
                        hashnode->ttl = ip_protocol->ip_ttl;
                        hashnode->len = length;
      //                  printf("Source address: %s\n",inet_ntoa(*((struct in_addr *) &(ip_protocol->i_ip_source_address))));
        //                printf("Destination address: %s\n",inet_ntoa(*((struct in_addr *) &(ip_protocol->i_ip_destination_address))));
          //              printf("source port=%d dst port=%d\n", hashnode->tupl4.source_port, hashnode->tupl4.dest_port);
            //            printf("ttl=d\n", hashnode->ttl);
              //          printf("number=%d\n", hashnode->number);
                //        printf("len=%d\n", hashnode->len);
                  //      printf("average_len=%d\n", hashnode->len / hashnode->number);
                        return;
                    }
                }
                case 17: {
                    udp_protocol = (struct udp_header *) (packet_content + 14 + 20);
                    addr.source_port = ntohs(udp_protocol->udp_source_port);
                    addr.dest_port = ntohs(udp_protocol->udp_destination_port);
                    //printf("addr %d %d %d %d\n", addr.source_ip, addr.dest_ip, addr.source_port, addr.dest_port);
                    unsigned int hashkey = hash_key(addr);
                    //printf("addr hashkey=%d\n", hashkey);
                    struct hash_node *hashnode;
                    if (Hashlist[hashkey].first == NULL) {
                        //printf("first\n");
                        hashnode = (struct hash_node *) malloc(sizeof(hash_node));
                        Hashlist[hashkey].first = hashnode;
                        hashnode->next = NULL;
                        gettimeofday(&hashnode->start, NULL);
                        hashnode->tupl4.dest_ip = ip_protocol->i_ip_destination_address;
                        hashnode->tupl4.source_ip = ip_protocol->i_ip_source_address;
                        hashnode->tupl4.dest_port = addr.dest_port;
                        hashnode->tupl4.source_port = addr.source_port;
                        hashnode->number = 1;
                        hashnode->ttl = ip_protocol->ip_ttl;
                        hashnode->len = length;
                   //     printf("Source address: %s\n",inet_ntoa(*((struct in_addr *) &(ip_protocol->i_ip_source_address))));
                     //   printf("Destination address: %s\n",inet_ntoa(*((struct in_addr *) &(ip_protocol->i_ip_destination_address))));
          //              printf("source port=%d dst port=%d\n", hashnode->tupl4.source_port, hashnode->tupl4.dest_port);
            //            printf("ttl=%d\n", hashnode->ttl);
              //          printf("number=%d\n", hashnode->number);
                //        printf("len=%d\n", hashnode->len);
                  //      printf("average_len=%d\n", hashnode->len / hashnode->number);
                        return;
                    } else {
                        hashnode = Hashlist[hashkey].first;
                        // //printf("hashnode %d %d %d %d\n", hashnode->tupl4.source_ip, hashnode->tupl4.dest_ip, hashnode->tupl4.source_port, hashnode->tupl4.dest_port);
                        while (hashnode) {
                            //printf("hashnode %d %d %d %d\n",hashnode->tupl4.source_ip,hashnode->tupl4.dest_ip,hashnode->tupl4.source_port,hashnode->tupl4.dest_port);
                            //printf("addr %d %d %d %d\n",addr.source_ip,addr.dest_ip,addr.source_port,addr.dest_port);
                            int result = cmp_tuple(hashnode->tupl4, addr);
                            //printf("result=%d\n", result);
                            if (result == 1) {
                                gettimeofday(&hashnode->start, NULL);
                                hashnode->number = hashnode->number + 1;
                                hashnode->ttl = hashnode->ttl + ip_protocol->ip_ttl;
                                hashnode->len = hashnode->len + length;
                    //            printf("Source address: %s\n", inet_ntoa(*((struct in_addr *) &(ip_protocol->i_ip_source_address))));
                      //          printf("Destination address: %s\n", inet_ntoa(*((struct in_addr *) &(ip_protocol->i_ip_destination_address))));
               //                 printf("source port=%d dst port=%d\n", hashnode->tupl4.source_port, hashnode->tupl4.dest_port);
                 //               printf("ttl=%d\n", hashnode->ttl);
                   //             printf("number=%d\n", hashnode->number);
                     //           printf("len=%d\n", hashnode->len);
                       //         printf("!!average_len=%d\n", hashnode->len / hashnode->number);
                                return;
                            }
                            hashnode = hashnode->next;
                        }
                        hashnode = (struct hash_node *) malloc(sizeof(hash_node));
                        hashnode->next = Hashlist[hashkey].first;
                        Hashlist[hashkey].first = hashnode;
                        gettimeofday(&hashnode->start, NULL);
                        hashnode->tupl4.dest_ip = ip_protocol->i_ip_destination_address;
                        hashnode->tupl4.source_ip = ip_protocol->i_ip_source_address;
                        hashnode->tupl4.dest_port = addr.dest_port;
                        hashnode->tupl4.source_port = addr.source_port;
                        hashnode->number = 1;
                        hashnode->ttl = ip_protocol->ip_ttl;
                        hashnode->len = length;
         //               printf("Source address: %s\n",inet_ntoa(*((struct in_addr *) &(ip_protocol->i_ip_source_address))));
           //             printf("Destination address: %s\n",inet_ntoa(*((struct in_addr *) &(ip_protocol->i_ip_destination_address))));
             //           printf("source port=%d dst port=%d\n", hashnode->tupl4.source_port, hashnode->tupl4.dest_port);
               //         printf("ttl=%d\n", hashnode->ttl);
                 //       printf("number=%d\n", hashnode->number);
                   //     printf("len=%d\n", hashnode->len);
                     //   printf("average_len=%d\n", hashnode->len / hashnode->number);
                        return;
                    }
                }
                default:
                    break;
            }
            break;
        }
        default:
            break;
    }
}
