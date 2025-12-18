# 🔍 SIMULASI FORENSIK DIGITAL & MANAJEMEN RISIKO

## Deskripsi Proyek
Simulasi lengkap untuk pembelajaran forensik digital dan manajemen risiko sesuai dengan:
- **CPL-2**: Keterampilan Khusus & Umum
- **CPMK-6**: Melakukan Analisis Forensik Digital & Manajemen Risiko

## 📋 Skenario Simulasi

### Latar Belakang
Sebuah perusahaan e-commerce "PT. TechMart Indonesia" mengalami insiden keamanan berupa:
1. Unauthorized access ke database pelanggan melalui SQL Injection
2. Data exfiltration sebanyak 50.000 record pelanggan
3. Pemasangan backdoor di web server
4. Potensi kerugian hingga Rp 2.8 miliar

### Tujuan Simulasi
1. Membuat environment VM untuk simulasi serangan
2. Melakukan simulasi serangan (attack simulation)
3. Melakukan forensik digital lengkap
4. Menyusun laporan forensik profesional
5. Melakukan risk assessment dan management

---

## 🚀 PANDUAN LENGKAP MENJALANKAN SIMULASI

### Prerequisites (Kebutuhan Sistem)
- **OS**: Ubuntu 20.04+ / Windows 10+ / macOS
- **Docker**: Versi 20.0+ (dengan Docker Compose)
- **Python**: 3.8+
- **RAM**: Minimal 4GB (8GB recommended)
- **Disk**: Minimal 10GB free space

### Cek Instalasi Docker
```bash
# Cek versi Docker
docker --version

# Cek Docker Compose
docker compose version
```

---

## 📖 TAHAP 1: SETUP ENVIRONMENT

### 1.1 Clone Repository
```bash
# Clone repository
git clone https://github.com/ujangbustomiitts20/simulasidigitalforensic.git

# Masuk ke direktori proyek
cd simulasidigitalforensic
```

### 1.2 Jalankan Docker Containers
```bash
# Masuk ke folder setup
cd 01-setup-environment

# Jalankan semua containers (victim, database, attacker, forensic)
docker compose up -d --build

# Tunggu 30-60 detik untuk inisialisasi database
```

### 1.3 Verifikasi Containers Berjalan
```bash
# Cek status containers
docker compose ps

# Output yang diharapkan:
# NAME                    STATUS
# forensik-victim-web     Up
# forensik-victim-db      Up (healthy)
# forensik-attacker       Up
# forensik-workstation    Up
```

### 1.4 Akses Web Application
Buka browser dan akses: **http://localhost:8888**

**Login credentials untuk testing:**
- Username: `admin`
- Password: `admin123`

---

## 📖 TAHAP 2: SIMULASI SERANGAN (ATTACK SIMULATION)

### 2.1 Install Python Dependencies
```bash
# Kembali ke root folder
cd ..

# Buat virtual environment (opsional tapi recommended)
python3 -m venv env
source env/bin/activate  # Linux/Mac
# atau: env\Scripts\activate  # Windows

# Install dependencies
pip install -r 06-tools/requirements.txt
```

### 2.2 Masuk ke Container Attacker
```bash
# Masuk ke container attacker
docker exec -it forensik-attacker bash
```

### 2.3 Jalankan Reconnaissance (Pengintaian)
```bash
# Di dalam container attacker, atau dari host:
cd /attack_scripts
python3 reconnaissance.py --target 172.28.0.10 --port 80

# Atau jalankan dari host (luar container):
cd 02-attack-simulation/attack_scripts
python3 reconnaissance.py --target localhost --port 8888
```

### 2.4 Jalankan SQL Injection Attack
```bash
# Di dalam container attacker:
python3 sql_injection.py --target http://172.28.0.10

# Atau dari host:
python3 sql_injection.py --target http://localhost:8888
```

### 2.5 Jalankan Data Exfiltration
```bash
# Di dalam container attacker:
python3 data_exfiltration.py

# Atau dari host:
python3 data_exfiltration.py
```

### 2.6 Simulasi Backdoor Installation
```bash
python3 backdoor_install.py
```

**⚠️ CATATAN:** Semua serangan akan meninggalkan jejak di log untuk analisis forensik.

---

## 📖 TAHAP 3: INVESTIGASI FORENSIK

### 3.1 Masuk ke Container Forensic Workstation
```bash
docker exec -it forensik-workstation bash
```

### 3.2 Kumpulkan Evidence (Bukti Digital)
```bash
# Di dalam forensic workstation:
cd /forensic/evidence_collection

# Jalankan disk imaging (simulasi)
bash disk_imaging.sh
```

### 3.3 Analisis Log
```bash
# Analisis Apache access log
cd /forensic/analysis
python3 log_analyzer.py

# Output akan menunjukkan:
# - IP addresses yang mencurigakan
# - Request patterns anomali
# - SQL injection attempts
# - Timeline serangan
```

### 3.4 Timeline Analysis
```bash
# Rekonstruksi timeline serangan berdasarkan MITRE ATT&CK
python3 timeline_analysis.py
```

### 3.5 Lihat Log dari Host
```bash
# Dari terminal host (bukan container):
# Lihat Apache access log
docker exec forensik-victim-web cat /var/log/apache2/access.log

# Lihat Apache error log
docker exec forensik-victim-web cat /var/log/apache2/error.log
```

---

## 📖 TAHAP 4: RISK MANAGEMENT

### 4.1 Jalankan Risk Assessment Tool
```bash
cd 04-risk-management
python3 risk_assessment.py
```

### 4.2 Review Risk Treatment Plan
Buka dan pelajari file: `04-risk-management/risk_treatment_plan.md`

---

## 📖 TAHAP 5: DOKUMENTASI & LAPORAN

### 5.1 Review Laporan Forensik
Buka file-file berikut:
- `05-reports/forensic_investigation_report.md` - Laporan investigasi lengkap
- `05-reports/executive_summary.md` - Ringkasan untuk manajemen

### 5.2 Chain of Custody
Review template di: `03-forensic-investigation/chain_of_custody/coc_template.md`

---

## 📖 TAHAP 6: LATIHAN MAHASISWA

### 6.1 Kerjakan Exercise
1. **Exercise 1**: `07-exercises/exercise_01_sql_injection_analysis.md`
   - Analisis SQL Injection yang terjadi
   
2. **Exercise 2**: `07-exercises/exercise_02_incident_response.md`
   - Simulasi incident response

### 6.2 Quiz
Kerjakan quiz di: `07-exercises/quiz_forensik_risiko.md`

---

## 📖 TAHAP 7: CLEANUP (SELESAI)

### 7.1 Stop Semua Containers
```bash
cd 01-setup-environment
docker compose down
```

### 7.2 Hapus Semua Data (Opsional)
```bash
# Hapus containers, networks, dan volumes
docker compose down -v

# Hapus images yang dibuat
docker rmi $(docker images -q "01-setup-environment*")
```

---

## 🔧 TROUBLESHOOTING

### Error: Port Already in Use
```bash
# Cek port yang digunakan
sudo lsof -i :8888
sudo lsof -i :3307

# Kill process yang menggunakan port
sudo kill -9 <PID>
```

### Error: Network Overlap
```bash
# Hapus network yang konflik
docker network prune

# Jalankan ulang
docker compose down
docker compose up -d
```

### Error: Container Not Starting
```bash
# Lihat logs
docker compose logs -f

# Lihat log specific container
docker logs forensik-victim-web
docker logs forensik-victim-db
```

### Error: Database Connection Failed
```bash
# Tunggu database ready (30-60 detik)
# Cek health status
docker compose ps

# Restart jika perlu
docker compose restart victim-db
```

---

## 🏗️ Struktur Proyek

```
simulasiforensik/
├── README.md                          # Dokumentasi utama (file ini)
│
├── 01-setup-environment/              # Setup environment
│   ├── docker-compose.yml             # Konfigurasi Docker (4 containers)
│   └── docker/
│       ├── victim/                    # Web server + database
│       │   ├── Dockerfile
│       │   ├── init.sql               # Database dengan 50 customer records
│       │   └── www/                   # PHP web application (vulnerable)
│       ├── attacker/                  # Attacker container
│       │   └── Dockerfile
│       └── forensic/                  # Forensic workstation
│           └── Dockerfile
│
├── 02-attack-simulation/              # Simulasi serangan
│   └── attack_scripts/
│       ├── reconnaissance.py          # Port scan & fingerprinting
│       ├── sql_injection.py           # SQL Injection attack
│       ├── data_exfiltration.py       # Data extraction
│       └── backdoor_install.py        # Persistence mechanism
│
├── 03-forensic-investigation/         # Investigasi forensik
│   ├── evidence_collection/
│   │   └── disk_imaging.sh
│   ├── analysis/
│   │   ├── log_analyzer.py
│   │   └── timeline_analysis.py
│   └── chain_of_custody/
│       └── coc_template.md
│
├── 04-risk-management/                # Manajemen risiko
│   ├── risk_assessment.py
│   └── risk_treatment_plan.md
│
├── 05-reports/                        # Laporan
│   ├── forensic_investigation_report.md
│   └── executive_summary.md
│
├── 06-tools/                          # Tools pendukung
│   ├── requirements.txt
│   └── forensic_toolkit.py
│
└── 07-exercises/                      # Latihan mahasiswa
    ├── exercise_01_sql_injection_analysis.md
    ├── exercise_02_incident_response.md
    └── quiz_forensik_risiko.md
```

---

## 🌐 Network Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Docker Network                           │
│                  172.28.0.0/24                              │
│                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │ victim-web  │    │  victim-db  │    │   attacker  │     │
│  │ 172.28.0.10 │◄──►│ 172.28.0.11 │    │ 172.28.0.20 │     │
│  │   :80/SSH   │    │   :3306     │    │  Kali Tools │     │
│  └─────────────┘    └─────────────┘    └─────────────┘     │
│         │                                     │             │
│         │           ┌─────────────┐          │             │
│         │           │  forensic   │          │             │
│         └──────────►│ 172.28.0.30 │◄─────────┘             │
│                     │ Sleuth Kit  │                        │
│                     └─────────────┘                        │
└─────────────────────────────────────────────────────────────┘

Port Mapping ke Host:
- Web Server: localhost:8888 → victim-web:80
- MySQL:      localhost:3307 → victim-db:3306
- SSH:        localhost:2222 → victim-web:22
```

---

## 📊 Framework & Standards yang Digunakan

| Framework | Penggunaan |
|-----------|------------|
| **NIST SP 800-61** | Incident Response Lifecycle |
| **ISO 27037** | Digital Evidence Handling |
| **MITRE ATT&CK** | Attack Classification |
| **ISO 27005** | Risk Management |
| **PCI-DSS** | Payment Card Security |
| **UU PDP** | Indonesian Data Protection |

---

## ⚠️ Disclaimer

**PENTING:** 
- Simulasi ini **HANYA** untuk tujuan pendidikan dalam lingkungan terkontrol
- **JANGAN** gunakan teknik yang dipelajari untuk aktivitas ilegal
- Selalu dapatkan **izin tertulis** sebelum melakukan pengujian keamanan
- Pelanggaran dapat dikenakan sanksi hukum sesuai UU ITE

---

## 📞 Kontak

Untuk pertanyaan, hubungi dosen pengampu mata kuliah **Forensik Digital & Manajemen Risiko**.

---

*Dibuat untuk memenuhi CPL-2, CPMK-6 - Forensik Digital & Manajemen Risiko*
