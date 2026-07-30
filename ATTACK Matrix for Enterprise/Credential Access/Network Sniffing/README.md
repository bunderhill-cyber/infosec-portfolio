# Network Credential Sniffer

**MITRE ATT&CK Mapping**  
**Tactic**: Credential Access  
**Technique**: T1040 – Network Sniffing  
**Author:** B. Underhill  
**Date:** June 2026  
**Lab:** SANS 504

**Language**: Python 3 (Scapy)

## Description

Educational Python tool that demonstrates extraction of credentials from unencrypted legacy protocols (FTP, SMTP AUTH LOGIN, and Telnet) by parsing PCAP files.

## Features

- Extracts FTP usernames and passwords
- Parses base64-encoded SMTP AUTH LOGIN credentials
- Basic state tracking for Telnet login sequences
- Structured logging and error handling

## Ethical Disclaimer

> **This tool is for educational purposes only.**  
> It is intended to be used exclusively in authorized, isolated lab environments (e.g., SANS SEC504 Windows VM). Unauthorized use on networks you do not own or have explicit permission to test is strictly prohibited.

## Attribution & Acknowledgments

- Base concepts and code examples are from the **Python for Cybersecurity Specialization** on Coursera (2020) by Howard Poston.
- Code significantly modernized, restructured, and enhanced with help from **Grok (xAI)**.
- All implementation, testing, and final code are my own.

## Usage

```powershell
pip install scapy

python credential_sniffer.py test_pcaps/test_ftp.pcap
