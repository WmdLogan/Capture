#include <pcap.h>
struct  arp_header
{
	u_int16_t arp_hardware_type;
	u_int16_t arp_protocol_type;
	u_int8_t  arp_hardware_length;
	u_int8_t  arp_protocol_length;
	u_int16_t arp_operation_code;
	u_int8_t  arp_source_ethernet_address[6];
	u_int8_t  arp_source_ip_address[4];
	u_int8_t  arp_destination_ethernet_address[6];
	u_int8_t  arp_destination_ip_address[4];
};
void arp_protocol_packet_callback(u_char *argument,const struct pcap_pkthdr *packet_header,const u_char *packet_content);