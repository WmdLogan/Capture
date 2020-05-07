#include "pcap.h"


pcap_t *pcap_handle;
pcap_dumper_t *out_pcap;
pcap_dumper_t *out_pcap1;
char file_size[5];
char path[50];//configure path
int next_file = 1;
char* final_path;//configure path + filename

unsigned int current_size;