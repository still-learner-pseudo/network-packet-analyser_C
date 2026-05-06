# CLI Network Packet Analyzer

<div align="center">
  <img src="https://img.shields.io/badge/Language-C-blue.svg" alt="C">
  <img src="https://img.shields.io/badge/Library-libpcap-green.svg" alt="libpcap">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey.svg" alt="Platform">
</div>

## 📌 Overview

This project is a high-performance, command-line network packet sniffer and analyzer built entirely in C utilizing the `libpcap` library. Engineered for deep packet inspection, this tool parses network headers from Layer 2 up to Layer 4 (Ethernet, IPv4/v6, TCP/UDP, ICMP) in real-time, providing deep visibility into network traffic flows. 

Designed with security and protocol analysis in mind, it features custom bitwise parsing for TCP control flags, comprehensive Berkeley Packet Filter (BPF) syntax support, and heuristic anomaly detection to uncover stealthy network scanning techniques (such as NULL scans and XMAS scans).

## ✨ Core Features

- **Real-Time Traffic Capture**: Intercepts and logs network packets on specified interfaces dynamically.
- **Deep Protocol Decoding (L2-L4)**: 
  - **L2**: Ethernet II frame extraction.
  - **L3**: IPv4 and IPv6 header parsing (handles variable length headers, TTL, protocol demultiplexing).
  - **L4**: TCP, UDP, and ICMP protocol analysis (ports, sequence/acknowledgment numbers, ICMP types/codes).
- **Bitwise TCP Flag Parsing**: Explicit bitwise operations to detect complex TCP state combinations (SYN, FIN, RST, PSH, ACK, URG, ECE, CWR).
- **Network Anomaly Detection**: Proactively identifies malicious traffic patterns:
  - **NULL Scans**: Flags packets with no TCP control flags set.
  - **XMAS Scans**: Flags packets with FIN, PSH, and URG flags simultaneously lit.
  - **SYN/FIN Sequences**: Identifies illegal combinations typically used to bypass firewalls.
- **BPF Syntax Integration**: Enables highly granular traffic filtering (e.g., `tcp port 80 and host 192.168.1.1`).
- **Hex/ASCII Payload Inspector**: Beautifully formats and displays application-layer payloads for packet inspection.

## 🚀 Getting Started

### Prerequisites

You must have `libpcap` installed on your system.
- **Debian/Ubuntu**: `sudo apt-get install libpcap-dev`
- **RHEL/CentOS**: `sudo yum install libpcap-devel`
- **macOS**: `brew install libpcap`

### Build

A streamlined Makefile is provided for rapid compilation:

```bash
make
```

### Usage

The analyzer requires elevated privileges to put the network interface into promiscuous mode.

```bash
sudo ./packet_analyzer <interface> [optional: BPF filter]
```

**Examples:**

*Sniff all traffic on eth0:*
```bash
sudo ./packet_analyzer eth0
```

*Sniff only HTTP traffic:*
```bash
sudo ./packet_analyzer eth0 "tcp port 80"
```

*Sniff specific host traffic:*
```bash
sudo ./packet_analyzer eth0 "host 10.0.0.5"
```

## 🧠 Engineering Insights

### Handling Complex Network Stacks
Writing a parser from scratch means bypassing kernel-level abstractions to interpret raw bytes directly off the wire. Handling big-endian to little-endian conversions (`ntohs`, `ntohl`) and calculating variable header lengths using bit masking (`ihl & 0x0F`) ensures parsing accuracy.

### Stealth Anomaly Detection 
By inspecting TCP flag vectors at the bitwise level (`flags & (TCP_FIN | TCP_PSH | TCP_URG)`), the tool doesn't just display data—it interprets the *intent* behind the packets, immediately alerting on reconnaissance techniques utilized by tools like Nmap.

### BPF (Berkeley Packet Filter) Engine
Instead of filtering packets in user-space (which is CPU intensive), the tool compiles human-readable BPF expressions into bytecode that runs directly inside the kernel-level packet capture framework, dropping irrelevant packets before they ever reach our application. This dramatically improves performance in high-throughput environments.

---

*Authored by Saathvik*
