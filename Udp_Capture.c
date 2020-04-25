#include "Udp_Capture.h"
void udp_protocol_packet_callback(u_char *argument,const struct pcap_pkthdr *packet_header,const u_char *packet_content)
{
	struct udp_header *udp_protocol;
	u_short source_port;
	u_short destination_port;
	u_short length;
	udp_protocol=(struct udp_header *)(packet_content+14+20);
	source_port=ntohs(udp_protocol->udp_source_port);
	destination_port=ntohs(udp_protocol->udp_destination_port);
	length=ntohs(udp_protocol->udp_length);
	printf("---------- UDP Protocol (Transport Layer) ----------\n");
	printf("Source Port :%d\n",source_port);
	printf("Dest Port :%d\n",destination_port);
	switch(destination_port)
	{
		case 138:printf("NETBIOS Datagram Service \n");break;
		case 137:printf("NETBIOS Name Service\n");break;
		case 139:printf("NETBIOS session Service\n");break;
		case 53:printf("DNS Service\n");break;
		default :break;
	}
	printf("Length :%d\n",length);
	printf("Checksum :%d\n",ntohs(udp_protocol->udp_checksum));
}