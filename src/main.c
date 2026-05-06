#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include "../include/sniffer.h"

void usage(const char* prog_name) {
    printf("Usage: %s <interface> [BPF filter expression]\n", prog_name);
    printf("Example: %s eth0 'tcp port 80'\n", prog_name);
    exit(1);
}

int main(int argc, char* argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    struct bpf_program fp;		/* The compiled filter expression */
    bpf_u_int32 mask;		/* The netmask of our sniffing device */
    bpf_u_int32 net;		/* The IP of our sniffing device */

    if (argc < 2) {
        usage(argv[0]);
    }

    char* dev = argv[1];
    printf("[*] Initializing Advanced CLI Packet Analyzer\n");
    printf("[*] Interface: %s\n", dev);

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "[-] Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }

    // Open the session in promiscuous mode
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "[-] Couldn't open device %s: %s\n", dev, errbuf);
        fprintf(stderr, "[!] Did you forget to run with sudo?\n");
        return 2;
    }

    // Compile and apply the filter
    if (argc > 2) {
        char filter_exp[256] = {0};
        for (int i = 2; i < argc; i++) {
            strncat(filter_exp, argv[i], sizeof(filter_exp) - strlen(filter_exp) - 2);
            strncat(filter_exp, " ", sizeof(filter_exp) - strlen(filter_exp) - 1);
        }

        printf("[*] Compiling BPF Filter: %s\n", filter_exp);
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
            fprintf(stderr, "[-] Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return 2;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "[-] Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return 2;
        }
        printf("[+] BPF Filter Applied Successfully.\n");
    } else {
        printf("[*] No BPF filter applied. Sniffing all traffic.\n");
    }

    // Capture packets
    printf("[+] Engine Active. Capturing packets... (Press Ctrl+C to stop)\n");
    pcap_loop(handle, -1, process_packet, NULL);

    if (argc > 2) pcap_freecode(&fp);
    pcap_close(handle);
    printf("\n[*] Capture Engine Terminated.\n");

    return 0;
}
