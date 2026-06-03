# Commands Used — Network Traffic Analysis Lab

## tcpdump Commands

```bash
# Check available network interfaces
tcpdump -D

# Basic live capture — print to screen
sudo tcpdump -i eth0 -v

# Capture all traffic and save to pcap file
sudo tcpdump -i eth0 -w captures/lab_capture.pcap

# Read and analyze saved pcap file
sudo tcpdump -r captures/lab_capture.pcap

# Count total packets captured
sudo tcpdump -r captures/lab_capture.pcap | wc -l

# Capture only ICMP traffic
sudo tcpdump -i eth0 icmp

# Capture only traffic from specific host
sudo tcpdump -i eth0 host 192.168.126.128

# Capture only HTTP traffic port 80
sudo tcpdump -i eth0 port 80

# Capture only DNS traffic port 53
sudo tcpdump -i eth0 port 53

# Combine filters — specific host and port
sudo tcpdump -i eth0 host 192.168.126.128 and port 80

# Show all unique source IPs in capture
sudo tcpdump -r captures/lab_capture.pcap -n | awk '{print $3}' | sort | uniq

# Show all destination ports contacted
sudo tcpdump -r captures/lab_capture.pcap -n 'tcp[tcpflags] & tcp-syn != 0' | awk '{print $5}' | sort -u
```

---

## Wireshark Display Filters

```bash
# Show only ICMP traffic
icmp

# Show only DNS traffic
dns

# Show only HTTP traffic
http

# Show only TLS traffic
tls

# Show only ARP traffic
arp

# Show traffic from specific source IP
ip.src == 192.168.126.129

# Show traffic to specific destination IP
ip.dst == 192.168.126.128

# Show only SYN packets — port scan detection
tcp.flags.syn == 1 and tcp.flags.ack == 0

# Show only completed TCP handshakes
tcp.flags.syn == 1 or tcp.flags.ack == 1

# Show packets with data payload only
tcp.len > 0

# Show HTTP GET requests only
http.request.method == "GET"

# Show HTTP responses only
http.response

# Filter by specific port
tcp.port == 80

# Combine filters
ip.src == 192.168.126.129 and tcp.flags.syn == 1
```

---

## Nmap Commands

```bash
# Basic SYN scan against target
sudo nmap -sS 192.168.126.128

# SYN scan with service version detection
sudo nmap -sS -sV 192.168.126.128

# SYN scan with OS detection
sudo nmap -sS -sV -O 192.168.126.128

# Scan specific port range
sudo nmap -sS -p 1-1000 192.168.126.128

# Scan all 65535 ports
sudo nmap -sS -p- 192.168.126.128
```

---

## Ping Commands

```bash
# Basic ping — 4 packets
ping -c 4 192.168.126.128

# Extended ping — 10 packets for more ICMP data
ping -c 10 192.168.126.128

# Flood ping — generates high volume ICMP traffic
sudo ping -f -c 100 192.168.126.128
```

---

## curl Commands

```bash
# HTTP GET request to example.com
curl http://example.com

# HTTP GET request to neverssl.com
curl http://neverssl.com

# Verbose output showing full headers
curl -v http://neverssl.com

# Save response to file
curl -o /tmp/response.html http://example.com
```

---

## nslookup Commands

```bash
# Basic DNS lookup
nslookup google.com
nslookup microsoft.com
nslookup facebook.com
nslookup example.com
nslookup neverssl.com

# Specify DNS server to query
nslookup google.com 8.8.8.8

# Look up IPv6 address
nslookup -type=AAAA google.com
```

---

