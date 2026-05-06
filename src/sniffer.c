#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ctype.h>
#include <pcap.h>
#include <string.h>
#include "../include/protocols.h"
#include "../include/sniffer.h"

// Utility function to print payload in Hex and ASCII
void print_payload(const uint8_t *payload, size_t len) {
    printf("    [+] Payload (%zu bytes):\n", len);
    if (len == 0) return;
    
    printf("        ");
    for (size_t i = 0; i < len; i++) {
        if (i > 0 && i % 16 == 0) {
            printf("  ");
            for (size_t j = i - 16; j < i; j++) {
                if (isprint(payload[j])) printf("%c", payload[j]);
                else printf(".");
            }
            printf("\n        ");
        }
        printf("%02X ", payload[i]);
    }
    
    // Print ascii for the last line
    int remaining = len % 16;
    if (remaining == 0) remaining = 16;
    int padding = (16 - remaining) * 3 + 2;
    for(int i = 0; i < padding; i++) printf(" ");
    
    for (size_t j = len - remaining; j < len; j++) {
        if (isprint(payload[j])) printf("%c", payload[j]);
        else printf(".");
    }
    printf("\n");
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)args; // Unused
    printf("\n========================================================================\n");
    printf("[*] Captured Packet | Length: %d bytes\n", header->len);
    
    struct ethernet_header* eth_header = (struct ethernet_header*)packet;
    uint16_t ether_type = ntohs(eth_header->ether_type);
    
    printf("[L2] Ethernet II -> src: %02X:%02X:%02X:%02X:%02X:%02X | dst: %02X:%02X:%02X:%02X:%02X:%02X | type: 0x%04X\n",
           eth_header->source_mac[0], eth_header->source_mac[1], eth_header->source_mac[2],
           eth_header->source_mac[3], eth_header->source_mac[4], eth_header->source_mac[5],
           eth_header->destination_mac[0], eth_header->destination_mac[1], eth_header->destination_mac[2],
           eth_header->destination_mac[3], eth_header->destination_mac[4], eth_header->destination_mac[5],
           ether_type);

    if (ether_type == ETH_P_IP) {
        struct ipv4_header* ip_header = (struct ipv4_header*)(packet + sizeof(struct ethernet_header));
        uint8_t ihl = (ip_header->version_ihl & 0x0F);
        int ip_header_length = ihl * 4;
        
        char source_ip[INET_ADDRSTRLEN];
        char dest_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->source_ip), source_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->destination_ip), dest_ip, INET_ADDRSTRLEN);
        
        printf("[L3] IPv4 -> src: %s | dst: %s | ttl: %d | protocol: %d\n", source_ip, dest_ip, ip_header->ttl, ip_header->protocol);
        
        uint8_t protocol = ip_header->protocol;
        const uint8_t *l4_ptr = packet + sizeof(struct ethernet_header) + ip_header_length;
        size_t l4_len = header->len - (sizeof(struct ethernet_header) + ip_header_length);

        if (protocol == IP_PROTO_TCP) {
            struct tcp_header* tcp = (struct tcp_header*)l4_ptr;
            uint16_t src_port = ntohs(tcp->source_port);
            uint16_t dst_port = ntohs(tcp->destination_port);
            uint8_t data_offset = (tcp->data_offset_res >> 4) * 4;
            uint8_t flags = tcp->flags;

            printf("[L4] TCP -> src port: %d | dst port: %d | seq: %u | ack: %u\n", 
                   src_port, dst_port, ntohl(tcp->sequence_number), ntohl(tcp->acknowledgment_number));
            
            // Flags parsing via bitwise operations
            printf("    [!] Flags: [ ");
            if (flags & TCP_CWR) printf("CWR ");
            if (flags & TCP_ECE) printf("ECE ");
            if (flags & TCP_URG) printf("URG ");
            if (flags & TCP_ACK) printf("ACK ");
            if (flags & TCP_PSH) printf("PSH ");
            if (flags & TCP_RST) printf("RST ");
            if (flags & TCP_SYN) printf("SYN ");
            if (flags & TCP_FIN) printf("FIN ");
            printf("]\n");

            // Anomaly Detection based on malicious TCP flag combinations
            if (flags == 0) {
                printf("    [WARN] Anomalous Traffic: TCP NULL Scan Detected!\n");
            }
            if ((flags & (TCP_FIN | TCP_PSH | TCP_URG)) == (TCP_FIN | TCP_PSH | TCP_URG)) {
                printf("    [WARN] Anomalous Traffic: TCP XMAS Scan Detected!\n");
            }
            if ((flags & TCP_SYN) && (flags & TCP_FIN)) {
                printf("    [WARN] Anomalous Traffic: TCP SYN/FIN Sequence Error!\n");
            }

            // Payload Inspector
            if (l4_len > data_offset) {
                print_payload(l4_ptr + data_offset, l4_len - data_offset);
            }
        } 
        else if (protocol == IP_PROTO_UDP) {
            struct udp_header* udp = (struct udp_header*)l4_ptr;
            printf("[L4] UDP -> src port: %d | dst port: %d | len: %d\n",
                   ntohs(udp->source_port), ntohs(udp->destination_port), ntohs(udp->length));
            
            if (l4_len > sizeof(struct udp_header)) {
                print_payload(l4_ptr + sizeof(struct udp_header), l4_len - sizeof(struct udp_header));
            }
        }
        else if (protocol == IP_PROTO_ICMP) {
            struct icmp_header* icmp = (struct icmp_header*)l4_ptr;
            printf("[L4] ICMP -> type: %d | code: %d\n", icmp->type, icmp->code);
            
            if (l4_len > sizeof(struct icmp_header)) {
                print_payload(l4_ptr + sizeof(struct icmp_header), l4_len - sizeof(struct icmp_header));
            }
        } else {
            printf("[L4] Unknown IP Protocol (%d)\n", protocol);
        }

    } else if (ether_type == ETH_P_IPV6) {
        struct ipv6_header* ip6 = (struct ipv6_header*)(packet + sizeof(struct ethernet_header));
        char source_ip[INET6_ADDRSTRLEN];
        char dest_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ip6->source_ip), source_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6->destination_ip), dest_ip, INET6_ADDRSTRLEN);
        
        printf("[L3] IPv6 -> src: %s | dst: %s | next header: %d\n", source_ip, dest_ip, ip6->next_header);
    } else if (ether_type == ETH_P_ARP) {
        printf("[L3] ARP Protocol\n");
    } else if (ether_type == ETH_P_RARP) {
        printf("[L3] RARP Protocol\n");
    } else {
        // Only print known standard ethertypes, omit lengths to avoid clutter
        if (ether_type >= 1536) {
            printf("[L3] Unknown EtherType: 0x%04X\n", ether_type);
        }
    }
}
