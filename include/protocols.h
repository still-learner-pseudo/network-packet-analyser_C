#ifndef PROTOCOLS_H
#define PROTOCOLS_H

// required includes or imports
#include <stdint.h>

// required macros
#define ETH_P_802_3_MIN 0x0600
#define ETH_P_IP 0x0800
#define ETH_P_ARP 0x0806
#define ETH_P_RARP 0x8035
#define ETH_P_IPV6 0x86DD

// IP Protocols
#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17

// Structure for Ethernet Header of 14 bytes
struct __attribute__((packed)) ethernet_header {
    uint8_t destination_mac[6];
    uint8_t source_mac[6];
    uint16_t ether_type;
};

// Structure for IPv4 Header of 20 bytes
struct __attribute__((packed)) ipv4_header {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;
    uint32_t source_ip;
    uint32_t destination_ip;
};

// Structure for IPv6 Header of 40 bytes
struct __attribute__((packed)) ipv6_header {
    uint32_t version_tc_flow;
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t source_ip[16];
    uint8_t destination_ip[16];
};

// Structure for TCP Header of 20 bytes minimum
struct __attribute__((packed)) tcp_header {
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t sequence_number;
    uint32_t acknowledgment_number;
    uint8_t data_offset_res; // 4 bits data offset, 4 bits reserved
    uint8_t flags;           // CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
};

// TCP Flags Macros
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20
#define TCP_ECE  0x40
#define TCP_CWR  0x80

// Structure for UDP Header of 8 bytes
struct __attribute__((packed)) udp_header {
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t length;
    uint16_t checksum;
};

// Structure for ICMP Header of 8 bytes
struct __attribute__((packed)) icmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t rest_of_header; // Varies based on type/code
};

#endif
