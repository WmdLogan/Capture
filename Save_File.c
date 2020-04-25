
#include "Save_File.h"
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

void processPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    pcap_dump(arg, pkthdr, packet);
    printf("Received Packet Size: %d\n", pkthdr->len);
}

int main() {
    char error_content[PCAP_ERRBUF_SIZE];
    char *net_interface;
    pcap_t *pcap_handle;

    net_interface = pcap_lookupdev(error_content);
    if (net_interface)
        printf("success: device: %s\n", net_interface);
    else {
        printf("error: %s\n", error_content);
        exit(1);
    }

    /* open a device, wait until a packet arrives */
    pcap_handle = pcap_open_live(net_interface, BUFSIZ, 1, 1, error_content);
    if (!pcap_handle) {
        printf("error: pcap_open_live(): %s\n", error_content);
        exit(1);
    }

    /*open pcap write output file*/
    pcap_dumper_t *out_pcap;
    out_pcap = pcap_dump_open(pcap_handle, "pack.cap");

    /*Loop forever & call processPacket() for every received packet.*/
    pcap_loop(pcap_handle, 20, processPacket, (u_char *) out_pcap);

    /*flush buff*/
    pcap_dump_flush(out_pcap);

    pcap_dump_close(out_pcap);
    pcap_close(pcap_handle);
    return 0;
}