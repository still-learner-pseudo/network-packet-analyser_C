#ifndef SNIFFER_H
#define SNIFFER_H

#include <stddef.h>
#include <stdint.h>
#include <pcap.h>

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif
