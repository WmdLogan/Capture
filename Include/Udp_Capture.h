#include <pcap.h>
struct udp_header
{
	u_int16_t udp_source_port;
	u_int16_t udp_destination_port;
	u_int16_t udp_length;
	u_int16_t udp_checksum;
};
void udp_protocol_packet_callback(u_char *argument,const struct pcap_pkthdr *packet_header,const u_char *packet_content);
