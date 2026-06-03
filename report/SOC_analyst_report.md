# Network Traffic Analysis — SOC Analyst Report

**Analyst:** Michael Argaw  
**Date:** June 3, 2026  
**Lab Environment:** Kali Linux vs Windows 11 — VMware Workstation  
**Capture File:** lab_capture.pcap  
**Tool:** tcpdump, Wireshark, Nmap, curl, nslookup, ping
**Lab Note:** HTTP sites were deliberately selected to simulate plaintext data exposure risk in a controlled lab environment

---

## 1. Executive Summary

A network packet capture was performed between two virtual machines
— Kali Linux (192.168.126.129) and Windows 11 (192.168.126.128) —
using tcpdump on interface eth0. A total of 6,543 packets were
captured over the session duration. Analysis revealed five distinct
findings including plaintext data exposure, OS fingerprinting via
TTL analysis, DNS reconnaissance visibility, port scan detection,
and Windows Firewall effectiveness confirmation.

| Metric | Value |
|---|---|
| Total Packets Captured | 6,543 |
| Total Bytes | 4,389,456 |
| Capture Interface | eth0 |
| Attacker/Source VM | 192.168.126.129 (Kali Linux) |
| Target VM | 192.168.126.128 (Windows 11) |
| Protocols Observed | TCP, UDP, ICMP, HTTP, DNS, TLS, QUIC, ARP, DHCP |
| Packet Loss | 0% |

---

## 2. Protocol Breakdown

| Protocol | Packets | % of Capture | Notes |
|---|---|---|---|
| TCP | 3,624 | 55.4% | Dominant — includes HTTP, TLS, Nmap scan |
| QUIC | 2,695 | 41.2% | Encrypted UDP — Windows background traffic |
| TLS | 513 | 7.8% | Encrypted HTTPS sessions |
| DNS | 134 | 2.0% | All queried domains visible in plaintext |
| ICMP | 20 | 0.3% | Ping — used for OS fingerprinting |
| HTTP | 10 | 0.2% | Plaintext — fully readable content |
| ARP | 22 | 0.3% | Network layer discovery |
| DHCP | 4 | 0.0% | IP assignment traffic visible |

---

## 3. Findings

---

### Finding 1 — OS Fingerprinting via TTL Analysis

**Severity:** Medium  
**Protocol:** ICMP  
**Source IP:** 192.168.126.129 (Kali)  
**Destination IP:** 192.168.126.128 (Windows)  
**Wireshark Filter:** `icmp`  

**Description:**  
HTTP sessions were deliberately selected for this lab exercise to 
demonstrate the risk of unencrypted web traffic on a network. The 
sites neverssl.com and example.com were specifically chosen because 
they intentionally serve content over HTTP without encryption — 
making them ideal for illustrating what an analyst can observe when 
plaintext protocols are in use on a corporate network.

In a real-world SOC environment this finding would apply to scenarios
such as legacy internal applications still running on port 80, 
employees submitting credentials over unencrypted forms, or developer 
tools sending API keys in plaintext. The purpose of capturing this 
traffic is to demonstrate the analyst's ability to identify, extract, 
and document unencrypted data in transit as a security risk.

Using Wireshark Follow TCP Stream, the complete HTTP conversation was
reconstructed including request headers, server response headers,
server software version, and full HTML page content — all without
any decryption required.

| Host | IP Address | TTL Observed | OS Identified |
|---|---|---|---|
| Kali Linux | 192.168.126.129 | 64 | Linux / Unix |
| Windows 11 | 192.168.126.128 | 128 | Windows |

**Evidence:** screenshots/finding_1_ttl_fingerprinting.png  

**MITRE ATT&CK:** T1082 — System Information Discovery  

**Recommendation:**  
Configure perimeter firewalls to normalize TTL values on outbound
packets. Implement network segmentation to prevent passive
reconnaissance between hosts.

---

### Finding 2 — DNS Query Visibility

**Severity:** Medium  
**Protocol:** DNS (UDP Port 53)  
**Source IPs:** 192.168.126.129, 192.168.126.128  
**Wireshark Filter:** `dns`  

**Description:**  
All DNS queries from both machines were captured and visible in
plaintext. An analyst — or attacker — positioned on this network
could reconstruct a complete browsing history for both machines
purely from DNS traffic, even when the actual web sessions were
encrypted with TLS or QUIC.

Domains resolved during the capture included:

| Domain | Resolved By | IP Returned |
|---|---|---|
| example.com | Kali (192.168.126.129) | 104.20.23.154 |
| neverssl.com | Kali (192.168.126.129) | 34.223.124.45 |
| google.com | Kali (192.168.126.129) | 64.233.180.139 |
| microsoft.com | Kali (192.168.126.129) | 13.107.253.40 |
| facebook.com | Kali (192.168.126.129) | 31.13.66.35 |
| wpad.localdomain | Windows (192.168.126.128) | No such name |
| self.events.data.microsoft.com | Windows (192.168.126.128) | CNAME chain |

**Notable observation:** Windows 11 generated unsolicited DNS
queries for wpad.localdomain (Web Proxy Auto-Discovery) and
Microsoft telemetry endpoints without any user interaction,
demonstrating that endpoints generate background network activity
that is visible to network monitors.

**Evidence:** screenshots/finding_2_dns_queries.png  

**MITRE ATT&CK:** T1040 — Network Sniffing  

**Recommendation:**  
Deploy DNS over HTTPS (DoH) or DNS over TLS (DoT) to encrypt
DNS queries. Implement a DNS filtering solution to monitor and
log all domain lookups centrally.

---

### Finding 3 — Plaintext HTTP Data Exposure

**Severity:** High  
**Protocol:** HTTP (TCP Port 80)  
**Source IP:** 192.168.126.129 (Kali), 192.168.126.128 (Windows)  
**Destination:** 34.223.124.45 (neverssl.com), 104.20.23.154 (example.com)  
**Wireshark Filter:** `http`  

**Description:**  
HTTP sessions between both machines and external web servers
transmitted all data in cleartext with no encryption. Using
Wireshark Follow TCP Stream, the complete HTTP conversation was
reconstructed including request headers, server response headers,
server software version, and full HTML page content.

The following sensitive information was extracted without
any decryption:

| Data Exposed | Value |
|---|---|
| Website visited | neverssl.com |
| Tool used | curl/8.18.0 |
| Server software | Apache/2.4.66 |
| Server date/time | Wed, 03 Jun 2026 14:06:28 GMT |
| Content type | text/html |
| Full page HTML | 3,961 bytes — completely readable |

**Evidence:** screenshots/finding_3_http_plaintext_stream.png  

**MITRE ATT&CK:** T1040 — Network Sniffing  

**Recommendation:**  
Deprecate all HTTP services and enforce HTTPS with TLS 1.2
minimum. Implement HTTP Strict Transport Security (HSTS).
Block outbound port 80 at the perimeter firewall and redirect
all traffic to port 443.

---

### Finding 4 — Port Scan Detection (Nmap SYN Scan)

**Severity:** High  
**Protocol:** TCP  
**Source IP:** 192.168.126.129 (Kali)  
**Destination IP:** 192.168.126.128 (Windows)  
**Wireshark Filter:** `tcp.flags.syn == 1 and tcp.flags.ack == 0`  

**Description:**  
An Nmap SYN scan was executed from Kali Linux against the Windows
11 host. The scan generated 2,054 SYN packets (31.4% of total
capture) targeting sequential destination ports. The scan
signature was clearly identifiable in the capture by the following
characteristics:

| Indicator | Value |
|---|---|
| SYN packets sent | 2,054 |
| Ports targeted | 1,000 (standard Nmap default) |
| Window size | Win=1024 (Nmap default) |
| Completed handshakes | 0 |
| Result | All ports filtered by Windows Firewall |

**Notable observation:** Zero completed TCP handshakes from the
scan confirms Windows Firewall blocked all connection attempts.
This is documented as Finding 5.

**Evidence:** screenshots/finding_4_port_scan_syn.png  

**MITRE ATT&CK:** T1046 — Network Service Discovery  

**Recommendation:**  
Deploy an IDS/IPS (Snort or Suricata) with rules to detect and
alert on SYN scan patterns. Implement rate limiting on inbound
SYN packets. Configure alerts for any host sending SYN packets
to more than 15 unique ports within 1 second.

---

### Finding 5 — Windows Firewall Blocking Confirmed

**Severity:** Informational  
**Protocol:** TCP  
**Source IP:** 192.168.126.128 (Windows)  

**Description:**  
The Nmap SYN scan from Kali returned all 1,000 scanned ports
as filtered with no response packets. This confirms Windows
Defender Firewall was active and blocking unsolicited inbound
connection attempts. No open ports were discovered on the
Windows host from external scanning.

**Result:** Positive security control — firewall operating
as expected.

**MITRE ATT&CK:** M1037 — Filter Network Traffic (Mitigation)  

**Recommendation:**  
Maintain current firewall configuration. Document approved
inbound rules and review quarterly. Implement host-based
firewall logging to capture blocked connection attempts for
SIEM ingestion.

---

## 4. Summary of Findings

| # | Finding | Severity | Protocol | MITRE ATT&CK |
|---|---|---|---|---|
| 1 | OS Fingerprinting via TTL | Medium | ICMP | T1082 |
| 2 | DNS Query Visibility | Medium | DNS | T1040 |
| 3 | Plaintext HTTP Exposure | High | HTTP | T1040 |
| 4 | Port Scan Detected | High | TCP | T1046 |
| 5 | Windows Firewall Active | Info | TCP | M1037 |

---

## 5. Tools Used

| Tool | Purpose |
|---|---|
| tcpdump | Live packet capture to .pcap file |
| Wireshark | Packet analysis and stream reconstruction |
| Nmap | Port scanning and service enumeration |
| curl | HTTP request generation |
| nslookup | DNS query generation |
| ping | ICMP traffic and OS fingerprinting |

---

## 6. Recommendations Summary

1. Replace all HTTP with HTTPS — enforce at firewall level
2. Deploy DNS over HTTPS to encrypt DNS queries
3. Implement IDS rules to detect SYN scan patterns
4. Normalize TTL values at perimeter to prevent OS fingerprinting
5. Ingest firewall block logs into SIEM for centralized monitoring

---

*Report generated as part of SOC Analyst portfolio project.*  
*All testing performed in an isolated lab environment.*
