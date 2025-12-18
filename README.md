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

## 🏗️ Struktur Proyek

```
simulasiforensik/
├── README.md                          # Dokumentasi utama
│
├── 01-setup-environment/              # Setup VM dan environment
│   ├── Vagrantfile                    # Konfigurasi 3 VM (victim, attacker, forensic)
│   ├── setup-victim.sh                # Setup VM korban (Apache, PHP, MySQL)
│   ├── setup-attacker.sh              # Setup VM attacker (Kali tools)
│   ├── docker-compose.yml             # Alternative dengan Docker (6 services)
│   └── docker/
│       └── victim/
│           ├── Dockerfile
│           ├── start.sh
│           ├── init.sql               # Database dengan 50 customer records
│           └── www/
│               ├── index.php          # Web application
│               └── login.php          # Vulnerable login (SQL Injection)
│
├── 02-attack-simulation/              # Simulasi serangan
│   └── attack_scripts/
│       ├── reconnaissance.py          # Port scan, fingerprinting, enumeration
│       ├── sql_injection.py           # Auth bypass, UNION, error-based SQLi
│       ├── data_exfiltration.py       # Data extraction dengan forensic trail
│       └── backdoor_install.py        # Persistence mechanism
│
├── 03-forensic-investigation/         # Investigasi forensik
│   ├── evidence_collection/
│   │   └── disk_imaging.sh            # Disk imaging dengan dcfldd
│   ├── analysis/
│   │   ├── log_analyzer.py            # Apache log analysis, attack detection
│   │   └── timeline_analysis.py       # MITRE ATT&CK timeline reconstruction
│   └── chain_of_custody/
│       └── coc_template.md            # Template Chain of Custody
│
├── 04-risk-management/                # Manajemen risiko
│   ├── risk_assessment.py             # ISRM framework, risk matrix, scoring
│   └── risk_treatment_plan.md         # Comprehensive treatment plan
│
├── 05-reports/                        # Laporan
│   ├── forensic_investigation_report.md  # Laporan investigasi lengkap
│   └── executive_summary.md           # Ringkasan untuk eksekutif
│
├── 06-tools/                          # Tools pendukung
│   ├── requirements.txt               # Python dependencies
│   └── forensic_toolkit.py            # All-in-one forensic suite
│
└── 07-exercises/                      # Latihan mahasiswa
    ├── exercise_01_sql_injection_analysis.md   # Lab analisis SQLi
    ├── exercise_02_incident_response.md        # Lab incident response
    └── quiz_forensik_risiko.md                 # Quiz evaluasi
```

## 🚀 Cara Memulai

### Prerequisites
- VirtualBox atau VMware
- Vagrant (opsional)
- Docker & Docker Compose
- Python 3.8+

### Quick Start

#### Metode 1: Docker (Recommended)
```bash
cd simulasiforensik/01-setup-environment
docker-compose up -d

# Akses services:
# - Victim Web: http://localhost:8080
# - Kibana (ELK): http://localhost:5601
```

#### Metode 2: Vagrant
```bash
cd simulasiforensik/01-setup-environment
vagrant up

# VM IP Addresses:
# - Victim: 192.168.56.10
# - Attacker: 192.168.56.20
# - Forensic: 192.168.56.30
```

### Install Python Dependencies
```bash
cd simulasiforensik
pip install -r 06-tools/requirements.txt
```

## 📚 Modul Pembelajaran

### Modul 1: Setup Environment
- Vagrant & VirtualBox configuration
- Docker multi-container setup
- Vulnerable web application deployment

### Modul 2: Attack Simulation
- Reconnaissance techniques
- SQL Injection exploitation
- Data exfiltration methods
- Persistence mechanisms

### Modul 3: Digital Forensics
- Evidence collection (disk, memory, network)
- Log analysis and correlation
- Timeline reconstruction
- Chain of custody documentation

### Modul 4: Risk Management
- Asset identification
- Threat and vulnerability assessment
- Risk scoring (Likelihood × Impact)
- Treatment planning (Mitigate, Transfer, Avoid, Accept)

### Modul 5: Reporting
- Forensic investigation report
- Executive summary
- Incident notification

## 🛠️ Tools & Framework

| Category | Tools |
|----------|-------|
| Virtualization | VirtualBox, Docker |
| Forensics | Autopsy, Volatility, Sleuth Kit |
| Log Analysis | ELK Stack, Custom Python tools |
| Attack Simulation | Custom Python scripts |
| Risk Management | Custom Python ISRM tool |

## 📊 Framework & Standards

- **NIST SP 800-61**: Incident Response
- **ISO 27037**: Digital Evidence Handling
- **MITRE ATT&CK**: Attack Framework
- **ISO 27005**: Risk Management
- **PCI-DSS**: Payment Card Security
- **UU PDP**: Indonesian Data Protection

## 👨‍🎓 Untuk Mahasiswa

1. Baca README ini terlebih dahulu
2. Setup environment menggunakan Docker atau Vagrant
3. Jalankan attack simulation (baca script untuk memahami)
4. Lakukan forensic investigation
5. Kerjakan exercises di folder `07-exercises/`
6. Buat laporan sesuai template

## ⚠️ Disclaimer

**PENTING:** Simulasi ini HANYA untuk tujuan pendidikan dalam lingkungan terkontrol. Jangan gunakan teknik yang dipelajari untuk aktivitas ilegal. Selalu dapatkan izin tertulis sebelum melakukan pengujian keamanan pada sistem apapun.

## 📄 License

Educational use only - Not for commercial distribution

## 📞 Kontak

Untuk pertanyaan, hubungi dosen pengampu mata kuliah Forensik Digital & Manajemen Risiko.

---

*Dibuat untuk memenuhi CPL-2, CPMK-6 - Forensik Digital & Manajemen Risiko*
