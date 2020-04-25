#include "Icmp_Capture.h"

void icmp_protocol_packet_callback(u_char *argument,const struct pcap_pkthdr *packet_header,const u_char *packet_content)
{
	struct icmp_header *icmp_protocol;
	icmp_protocol=(struct icmp_header *)(packet_content+14+20);
	printf("---------- ICMP Protocol (Transport Layer) ----------\n");
	printf("ICMP Type:%d\n",icmp_protocol->icmp_type);
	switch(icmp_protocol->icmp_type)
	{
		case 8:
		printf("ICMP Echo Request Protocol\n");
		printf("ICMP Code:%d\n",icmp_protocol->icmp_code);
		printf("Identifier:%d\n",icmp_protocol->icmp_id);
		printf("Sequence Number:%d\n",icmp_protocol->icmp_sequence);
		break;
		case 0:
		printf("ICMP Echo Reply Protocol\n");
		printf("ICMP Code:%d\n",icmp_protocol->icmp_code);
		printf("Identifier:%d\n",icmp_protocol->icmp_id);
		printf("Sequence Number:%d\n",icmp_protocol->icmp_sequence);
		break;
		default: break; 
	}
	printf("ICMP Checksum %d\n",ntohs(icmp_protocol->icmp_checksum));
}