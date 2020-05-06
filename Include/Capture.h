#include "pcap.h"
#include "Ip_Capture.h"
#include "Tcp_Capture.h"
#include "Udp_Capture.h"
#include "string.h"
#include <sys/stat.h>
#include "Configure.h"
#include "Ethernet_Cap.h"

long int update_time;
char net_interface[5];
char src_add[16];
char des_add[16];
char s_port[5];
char d_port[5];
int file_size;
struct stat buf;
int result;
static int packet_number = 1;


pcap_t *pcap_handle;

pcap_dumper_t *out_pcap;

void capture_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content);