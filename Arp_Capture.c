#include "Ethernet_Cap.h"
#include "Arp_Capture.h"
#include <string.h>
void arp_protocol_packet_callback(u_char *argument,const struct pcap_pkthdr *packet_header,const u_char *packet_content)
{
	struct arp_header *arp_protocol;
	u_short protocol_type;
	u_short hardware_type;
	u_short operation_code;
	u_char  *mac_string;
	struct  in_addr source_ip_address;
	struct  in_addr destination_ip_address;
	u_char  hardware_length;
	u_char  protocol_length;
	printf("---------- ARP Protocol (Network Layer) ----------\n");
	arp_protocol=(struct arp_header *)(packet_content+14);
	hardware_type=ntohs(arp_protocol->arp_hardware_type);
	protocol_type=ntohs(arp_protocol->arp_protocol_type);
	operation_code=ntohs(arp_protocol->arp_operation_code);
	hardware_length=arp_protocol->arp_hardware_length;
	protocol_length=arp_protocol->arp_protocol_length;
	printf("ARP Hareware Type :%d\n",hardware_type);
	printf("ARP Protocol Type :%d\n",protocol_type);
	printf("ARP Hareware Length:%d\n",hardware_length);
	printf("ARP Protocol Length:%d\n",protocol_length);
	printf("ARP Operation :%d\n",operation_code);
	switch(operation_code)
	{
		case 1:printf("ARP Request Protocol\n");break;
		case 2:printf("ARP Reply Protocol\n");break;
		case 3:printf("RARP Request Protocol\n");break;
		case 4:printf("RARP Reply Protocol\n");break;
		default :break;
	}
	printf("Ethernet Source Address is : \n");
	mac_string=arp_protocol->arp_source_ethernet_address;
	printf("%02x:%02x:%02x:%02x:%02x:%02x:\n",*mac_string,*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));
	memcpy((void *)&source_ip_address,(void *)&arp_protocol->arp_source_ip_address,sizeof(struct in_addr));
	printf("Source IP Address :%s\n",inet_ntoa(source_ip_address));
	printf("Ethernet Destination Address is : \n");
	mac_string=arp_protocol->arp_destination_ethernet_address;
	printf("%02x:%02x:%02x:%02x:%02x:%02x:\n",*mac_string,*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));
	memcpy((void *)&destination_ip_address,(void *)&arp_protocol->arp_destination_ip_address,sizeof(struct in_addr));
	printf("Destination IP Address :%s\n",inet_ntoa(destination_ip_address));
}