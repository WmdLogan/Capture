#include "pcap.h"
#include <sys/stat.h>

pcap_t *pcap_handle;

long int update_time;
struct stat buf1;
char src_add[16];
char des_add[16];
char s_port[5];
char d_port[5];

void capture_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content);