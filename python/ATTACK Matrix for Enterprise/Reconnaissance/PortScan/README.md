# Port Scanner & DNS Recon Tool (Scapy)

**Author:** B. Underhill  
**Date:** June 2026  
**Lab:** SANS 504

## Description

A Python tool using **Scapy** for TCP SYN port scanning and basic DNS server detection. Built and tested in the SANS 504 lab environment.

## Features
- TCP SYN (half-open) scanning
- DNS server detection
- Command-line options for ports and timeout
- Clean logging and summary output

## Attribution & Acknowledgments

- Base concepts and code examples are from the **Python for Cybersecurity Specialization** on Coursera (2020) by Howard Poston.
- Code significantly modernized, restructured, and enhanced with help from **Grok (xAI)**.
- All implementation, testing, and final code are my own.

**Disclaimer**: For educational purposes only. Use exclusively on authorized targets and lab environments.

## Usage

```bash
sudo python3 PortScan_DNS_Scan.py 10.10.0.1
```
# Sample output
=== Recon Scan: 10.10.0.1 ===

[+] Open port detected: 139
[+] Open port detected: 445
DNS server detected at 10.10.0.1

=== Scan Summary ===
Target: 10.10.0.1
Open ports: [139, 445]
DNS Server: Yes

## Lab Walkthrough

1. Set up Slingshot Linux and Windows 10 VMs in SANS 504 lab.
2. Configured lab networking between both VMs.
3. Installed Scapy and developed the reconnaissance script.
4. Tested against Windows 10 target (`10.10.0.1`).
5. Captured traffic with Wireshark for analysis.
6. Iterated on response handling to successfully detect open ports (139, 445).

## Key Learnings

- Packet crafting with Scapy
- TCP handshake behavior and firewall impact
- VM networking and troubleshooting
- Responsible use of offensive security tools


