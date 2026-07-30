#!/usr/bin/env python3
"""
Network Credential Sniffer (Educational Tool)
Uses Scapy to extract credentials from unencrypted legacy protocols:
- FTP (USER/PASS)
- SMTP (AUTH LOGIN base64)
- Telnet (login/password prompts)

WARNING: For authorized testing and educational purposes ONLY.
This tool only works on clear-text traffic. Modern networks use TLS.

Author: Bru Und
License: Educational / MIT (add your choice)
"""

from scapy.all import *
from base64 import b64decode
import re
import argparse
import logging
from typing import List, Tuple

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Connection state tracking (better as dict with timeout in production)
awaiting_login: List[Tuple] = []
awaiting_password: List[Tuple] = []
unmatched_smtp: List[Tuple] = []

def extract_ftp(packet) -> None:
    """Extract FTP credentials."""
    try:
        payload = packet[Raw].load.decode("utf-8", errors="ignore").strip()
        if payload.startswith("USER "):
            logger.info(f"[+] FTP Username: {payload[5:]} | Server: {packet[IP].dst}")
        elif payload.startswith("PASS "):
            logger.info(f"[+] FTP Password: {payload[5:]} | Server: {packet[IP].dst}")
    except Exception as e:
        logger.debug(f"FTP parsing error: {e}")


def extract_smtp(packet) -> None:
    """Extract SMTP AUTH LOGIN credentials."""
    try:
        payload = packet[Raw].load
        decoded = b64decode(payload, validate=False).decode("utf-8", errors="ignore").strip()
        conn_data = (packet[IP].src, packet[TCP].sport)

        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.match(email_regex, decoded):
            logger.info(f"[+] SMTP Username: {decoded} | Server: {packet[IP].dst}")
            unmatched_smtp.append(conn_data)
        elif conn_data in unmatched_smtp:
            logger.info(f"[+] SMTP Password: {decoded} | Server: {packet[IP].dst}")
            unmatched_smtp.remove(conn_data)
    except Exception as e:
        logger.debug(f"SMTP parsing error: {e}")


def extract_telnet(packet) -> None:
    """Extract Telnet credentials with basic state tracking."""
    try:
        payload = packet[Raw].load.decode("utf-8", errors="ignore").strip()
        conn_server = (packet[IP].src, packet[TCP].sport)
        conn_client = (packet[IP].dst, packet[TCP].dport)

        # Server prompts
        if "login" in payload.lower():
            awaiting_login.append(conn_server)
            return
        if "password" in payload.lower():
            awaiting_password.append(conn_server)
            return

        # Client responses
        if conn_client in awaiting_login:
            logger.info(f"[+] Telnet Username: {payload} | Server: {packet[IP].dst}")
            awaiting_login.remove(conn_client)
        elif conn_client in awaiting_password:
            logger.info(f"[+] Telnet Password: {payload} | Server: {packet[IP].dst}")
            awaiting_password.remove(conn_client)
    except Exception as e:
        logger.debug(f"Telnet parsing error: {e}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Network Credential Sniffer - Educational Tool")
    parser.add_argument("pcap_file", help="Path to the PCAP file to analyze")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    logger.info(f"[*] Starting credential sniffer on {args.pcap_file}")

    try:
        packets = rdpcap(args.pcap_file)
        logger.info(f"[*] Loaded {len(packets)} packets")
    except Exception as e:
        logger.error(f"Failed to read PCAP: {e}")
        return

    for packet in packets:
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            dport = packet[TCP].dport
            sport = packet[TCP].sport

            if dport == 21 or sport == 21:
                extract_ftp(packet)
            elif dport == 25 or sport == 25:
                extract_smtp(packet)
            elif dport == 23 or sport == 23:
                extract_telnet(packet)

    logger.info("[*] Analysis completed.")


if __name__ == "__main__":
    main()