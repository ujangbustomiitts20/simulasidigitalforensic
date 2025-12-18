# Latihan 1: SQL Injection Analysis
## Forensik Digital & Manajemen Risiko

---

## Tujuan Pembelajaran

Setelah menyelesaikan latihan ini, mahasiswa akan mampu:
1. Mengidentifikasi serangan SQL Injection dari log
2. Merekonstruksi timeline serangan
3. Mengekstrak Indicator of Compromise (IOC)
4. Menulis laporan investigasi sederhana

---

## Skenario

Anda adalah anggota tim Security Operations Center (SOC) di PT. TechMart Indonesia. Pada pagi hari, SIEM mendeteksi anomali pada traffic web server. Tugas Anda adalah menganalisis log dan menentukan apakah terjadi serangan.

---

## Bagian A: Analisis Log Apache (40 poin)

### Data Log

Berikut adalah potongan log Apache yang perlu dianalisis:

```
192.168.56.20 - - [15/Jan/2024:02:15:33 +0700] "GET / HTTP/1.1" 200 4523
192.168.56.20 - - [15/Jan/2024:02:16:45 +0700] "GET /robots.txt HTTP/1.1" 200 123
192.168.56.20 - - [15/Jan/2024:02:17:22 +0700] "GET /admin HTTP/1.1" 404 234
192.168.56.20 - - [15/Jan/2024:02:17:30 +0700] "GET /phpmyadmin HTTP/1.1" 404 234
192.168.56.20 - - [15/Jan/2024:02:18:15 +0700] "GET /login.php HTTP/1.1" 200 1234
192.168.56.20 - - [15/Jan/2024:02:20:33 +0700] "POST /login.php HTTP/1.1" 200 892
192.168.56.20 - - [15/Jan/2024:02:21:45 +0700] "POST /login.php HTTP/1.1" 200 892
192.168.56.20 - - [15/Jan/2024:02:23:12 +0700] "GET /login.php?username='%20OR%20'1'='1'--&password=test HTTP/1.1" 200 2341
192.168.56.20 - - [15/Jan/2024:02:24:30 +0700] "GET /login.php?username='%20UNION%20SELECT%20null,null,null--&password= HTTP/1.1" 200 2567
192.168.56.20 - - [15/Jan/2024:02:25:45 +0700] "GET /login.php?username='%20UNION%20SELECT%201,2,3--&password= HTTP/1.1" 200 2890
192.168.56.20 - - [15/Jan/2024:02:27:00 +0700] "GET /login.php?username='%20UNION%20SELECT%20table_name,null,null%20FROM%20information_schema.tables--&password= HTTP/1.1" 200 15678
192.168.56.20 - - [15/Jan/2024:02:29:15 +0700] "GET /login.php?username='%20UNION%20SELECT%20column_name,null,null%20FROM%20information_schema.columns%20WHERE%20table_name='users'--&password= HTTP/1.1" 200 4567
192.168.56.20 - - [15/Jan/2024:02:31:30 +0700] "GET /login.php?username='%20UNION%20SELECT%20username,password,email%20FROM%20users--&password= HTTP/1.1" 200 8901
192.168.56.20 - - [15/Jan/2024:02:35:00 +0700] "GET /dashboard.php HTTP/1.1" 200 5678
192.168.56.20 - - [15/Jan/2024:02:36:22 +0700] "GET /customers.php HTTP/1.1" 200 125678
```

### Pertanyaan

**A1. (10 poin)** Identifikasi fase-fase serangan yang terlihat di log. Klasifikasikan berdasarkan MITRE ATT&CK framework.

**Jawaban:**
```
[Tuliskan jawaban Anda di sini]

Fase 1: _________________ (Waktu: _________)
Teknik: _________________
Evidence: _________________

Fase 2: _________________ (Waktu: _________)
Teknik: _________________
Evidence: _________________

[Lanjutkan untuk semua fase]
```

**A2. (10 poin)** Ekstrak semua payload SQL injection dari log. Decode URL-encoded characters.

**Jawaban:**
```
Payload 1: _________________
Decoded: _________________
Tujuan: _________________

Payload 2: _________________
Decoded: _________________
Tujuan: _________________

[Lanjutkan untuk semua payload]
```

**A3. (10 poin)** Buat timeline serangan dalam format tabel.

**Jawaban:**

| No | Waktu | Aktivitas | Severity |
|----|-------|-----------|----------|
| 1 | | | |
| 2 | | | |
| | | | |

**A4. (10 poin)** Identifikasi Indicator of Compromise (IOC) dari log.

**Jawaban:**
```
IOC Type: IP Address
Value: _________________

IOC Type: URL Pattern
Value: _________________

IOC Type: User-Agent (jika ada)
Value: _________________
```

---

## Bagian B: Analisis Database Log (30 poin)

### Data MySQL Query Log

```
2024-01-15T02:23:12.456789Z 12 Query    SELECT * FROM users WHERE username = '' OR '1'='1'-- ' AND password = 'test'
2024-01-15T02:24:30.123456Z 12 Query    SELECT * FROM users WHERE username = '' UNION SELECT null,null,null-- ' AND password = ''
2024-01-15T02:25:45.789012Z 12 Query    SELECT * FROM users WHERE username = '' UNION SELECT 1,2,3-- ' AND password = ''
2024-01-15T02:27:00.345678Z 12 Query    SELECT * FROM users WHERE username = '' UNION SELECT table_name,null,null FROM information_schema.tables-- ' AND password = ''
2024-01-15T02:29:15.901234Z 12 Query    SELECT * FROM users WHERE username = '' UNION SELECT column_name,null,null FROM information_schema.columns WHERE table_name='users'-- ' AND password = ''
2024-01-15T02:31:30.567890Z 12 Query    SELECT * FROM users WHERE username = '' UNION SELECT username,password,email FROM users-- ' AND password = ''
2024-01-15T02:33:00.123456Z 12 Query    SELECT * FROM customers LIMIT 0,1000
2024-01-15T02:34:00.234567Z 12 Query    SELECT * FROM customers LIMIT 1000,1000
2024-01-15T02:35:00.345678Z 12 Query    SELECT * FROM customers LIMIT 2000,1000
```

### Pertanyaan

**B1. (10 poin)** Jelaskan teknik SQL injection yang digunakan attacker. Apa langkah-langkah yang dilakukan?

**Jawaban:**
```
Teknik yang digunakan: _________________

Langkah 1: _________________
Tujuan: _________________

Langkah 2: _________________
Tujuan: _________________

[Lanjutkan]
```

**B2. (10 poin)** Berapa banyak data pelanggan yang berpotensi dicuri? Jelaskan bagaimana Anda menghitung ini.

**Jawaban:**
```
Estimasi jumlah data: _________________
Perhitungan: _________________
```

**B3. (10 poin)** Identifikasi kerentanan kode yang menyebabkan serangan ini berhasil. Tulis contoh kode yang rentan dan versi yang diperbaiki.

**Kode Rentan:**
```php
// Tuliskan kode yang kemungkinan digunakan
```

**Kode Diperbaiki:**
```php
// Tuliskan perbaikan kode
```

---

## Bagian C: Risk Assessment (30 poin)

**C1. (10 poin)** Lakukan penilaian risiko untuk kerentanan SQL Injection ini menggunakan matriks risiko.

**Jawaban:**

| Kriteria | Penilaian (1-5) | Justifikasi |
|----------|-----------------|-------------|
| Likelihood | | |
| Impact | | |
| **Risk Score** | | |
| **Risk Level** | | |

**C2. (10 poin)** Rekomendasikan 5 kontrol keamanan untuk mitigasi risiko ini. Prioritaskan berdasarkan efektivitas.

**Jawaban:**

| Prioritas | Kontrol | Deskripsi | Estimasi Biaya |
|-----------|---------|-----------|----------------|
| 1 | | | |
| 2 | | | |
| 3 | | | |
| 4 | | | |
| 5 | | | |

**C3. (10 poin)** Hitung residual risk setelah implementasi kontrol yang direkomendasikan.

**Jawaban:**
```
Risk Score Awal: _________________
Kontrol yang diterapkan: _________________
Pengurangan Likelihood: _________________
Pengurangan Impact: _________________
Residual Risk Score: _________________
Residual Risk Level: _________________
```

---

## Kriteria Penilaian

| Bagian | Poin Maksimal | Kriteria |
|--------|---------------|----------|
| A1 | 10 | Identifikasi fase lengkap dan akurat |
| A2 | 10 | Semua payload diidentifikasi dan decoded |
| A3 | 10 | Timeline lengkap dan terstruktur |
| A4 | 10 | IOC diidentifikasi dengan benar |
| B1 | 10 | Penjelasan teknik SQL injection akurat |
| B2 | 10 | Estimasi data dan perhitungan benar |
| B3 | 10 | Kode rentan dan perbaikan tepat |
| C1 | 10 | Risk assessment menggunakan metodologi benar |
| C2 | 10 | Rekomendasi kontrol relevan dan terprioritas |
| C3 | 10 | Perhitungan residual risk tepat |
| **Total** | **100** | |

---

## Panduan Pengerjaan

1. Kerjakan secara individu
2. Gunakan referensi yang tersedia (MITRE ATT&CK, OWASP, dll)
3. Jawaban harus dalam format yang diminta
4. Deadline: [TANGGAL]

---

## Referensi

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [NIST SP 800-30 Risk Assessment](https://csrc.nist.gov/publications/detail/sp/800-30/rev-1/final)
