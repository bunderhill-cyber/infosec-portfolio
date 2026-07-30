#!/usr/bin/env python3
"""
Port Scanner & DNS Recon Tool
Author: Bru Und
Date: 2026
Description: Basic SYN port scanner and DNS server detection using Scapy.
             For educational purposes only. Use only on authorized targets.
License: MIT (or your chosen license)
"""

from scapy.all import *
import argparse
import logging
import os
import sys

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

COMMON_PORTS = [25, 80, 53, 443, 445, 8080, 8443, 3389, 139]

def syn_scan(host: str, ports: list = None, timeout: int = 3) -> list:
    """Perform TCP SYN scan on target host."""
    if ports is None:
        ports = COMMON_PORTS
    
    logger.info(f"Starting SYN scan on {host}...")
    try:
        ans, unans = sr(
            IP(dst=host) / TCP(sport=RandShort(), dport=ports, flags="S"),
            timeout=timeout,
            verbose=0,
            retry=1
        )
        
        open_ports = []
        for sent, received in ans:
            if TCP in received:
                flags = received[TCP].flags
                if flags & 0x12 == 0x12:          # SYN-ACK received
                    open_ports.append(sent[TCP].dport)
                    logger.info(f"[+] Open port detected: {sent[TCP].dport}")
                elif flags & 0x04 == 0x04:
                    logger.debug(f"Closed port: {sent[TCP].dport}")
        
        open_ports = sorted(set(open_ports))
        if open_ports:
            logger.info(f"Open ports on {host}: {open_ports}")
        else:
            logger.info(f"No open ports found on {host} from scanned list.")
        
        return open_ports
    except Exception as e:
        logger.error(f"Scan error: {e}")
        return []

def dns_scan(host: str, timeout: int = 2) -> bool:
    """Check if target is running a DNS server."""
    logger.info(f"Checking DNS server on {host}...")
    try:
        ans, unans = sr(
            IP(dst=host) / UDP(sport=RandShort(), dport=53) / 
            DNS(rd=1, qd=DNSQR(qname="google.com")),
            timeout=timeout,
            verbose=0
        )
        
        if ans:
            logger.info(f"DNS server detected at {host}")
            return True
        return False
    except Exception as e:
        logger.error(f"DNS scan error: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Simple Scapy Recon Scanner - SANS 504 Lab")
    parser.add_argument("host", help="Target IP or hostname")
    parser.add_argument("-p", "--ports", type=int, nargs="+", default=COMMON_PORTS,
                        help="Ports to scan (default: common ports)")
    parser.add_argument("-t", "--timeout", type=int, default=3, help="Timeout in seconds")
    args = parser.parse_args()

    print(f"\n=== Recon Scan: {args.host} ===\n")
    
    open_ports = syn_scan(args.host, args.ports, args.timeout)
    dns_found = dns_scan(args.host, args.timeout)
    
    print("\n=== Scan Summary ===")
    print(f"Target: {args.host}")
    print(f"Open ports: {open_ports if open_ports else 'None detected'}")
    print(f"DNS Server: {'Yes' if dns_found else 'No'}")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Error: This script requires root privileges (sudo).")
        sys.exit(1)
    main()