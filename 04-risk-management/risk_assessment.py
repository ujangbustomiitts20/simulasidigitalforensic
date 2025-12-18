#!/usr/bin/env python3
"""
Risk Assessment Tool untuk Manajemen Risiko Keamanan Informasi
Implementasi framework ISRM (Information Security Risk Management)

Materi: CPMK-6 - Forensik Digital & Manajemen Risiko
"""

import json
import sys
import os
from datetime import datetime
from typing import List, Dict, Any
from dataclasses import dataclass, asdict, field
from enum import Enum

# ANSI Colors
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def banner():
    print(f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════╗
║{Colors.YELLOW}  📊 INFORMATION SECURITY RISK MANAGEMENT TOOL               {Colors.CYAN}║
║{Colors.GREEN}     Risk Assessment & Treatment Planning                     {Colors.CYAN}║
╚══════════════════════════════════════════════════════════════╝{Colors.RESET}
    """)

class Likelihood(Enum):
    """Skala kemungkinan risiko"""
    VERY_LOW = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    VERY_HIGH = 5
    
    @classmethod
    def from_value(cls, value: int):
        for item in cls:
            if item.value == value:
                return item
        return cls.MEDIUM

class Impact(Enum):
    """Skala dampak risiko"""
    NEGLIGIBLE = 1
    MINOR = 2
    MODERATE = 3
    MAJOR = 4
    CATASTROPHIC = 5
    
    @classmethod
    def from_value(cls, value: int):
        for item in cls:
            if item.value == value:
                return item
        return cls.MODERATE

class TreatmentStrategy(Enum):
    """Strategi penanganan risiko"""
    MITIGATE = "mitigate"      # Mengurangi risiko
    TRANSFER = "transfer"      # Mentransfer risiko (asuransi)
    AVOID = "avoid"            # Menghindari risiko
    ACCEPT = "accept"          # Menerima risiko

@dataclass
class Asset:
    """Representasi aset informasi"""
    id: str
    name: str
    category: str  # hardware, software, data, personnel, facility
    description: str
    owner: str
    value: float  # Nilai ekonomi dalam rupiah
    criticality: str  # low, medium, high, critical

@dataclass
class Threat:
    """Representasi ancaman"""
    id: str
    name: str
    category: str  # cyber, physical, natural, human
    description: str
    source: str  # internal, external, environmental

@dataclass
class Vulnerability:
    """Representasi kerentanan"""
    id: str
    name: str
    description: str
    affected_assets: List[str]
    cvss_score: float = 0.0

@dataclass
class Risk:
    """Representasi risiko"""
    id: str
    name: str
    description: str
    asset_id: str
    threat_id: str
    vulnerability_id: str
    likelihood: int  # 1-5
    impact: int      # 1-5
    risk_score: int = 0
    risk_level: str = ""
    treatment_strategy: str = ""
    treatment_plan: str = ""
    residual_risk: int = 0
    owner: str = ""
    status: str = "identified"  # identified, assessed, treated, monitored
    
    def calculate_risk_score(self):
        """Hitung risk score = likelihood × impact"""
        self.risk_score = self.likelihood * self.impact
        
        # Determine risk level
        if self.risk_score >= 20:
            self.risk_level = "CRITICAL"
        elif self.risk_score >= 15:
            self.risk_level = "HIGH"
        elif self.risk_score >= 8:
            self.risk_level = "MEDIUM"
        elif self.risk_score >= 4:
            self.risk_level = "LOW"
        else:
            self.risk_level = "MINIMAL"
        
        return self.risk_score

class RiskAssessmentTool:
    """
    Tool untuk melakukan risk assessment
    Mengimplementasikan framework ISRM
    """
    
    def __init__(self, organization: str = "PT. TechMart Indonesia"):
        self.organization = organization
        self.assets: Dict[str, Asset] = {}
        self.threats: Dict[str, Threat] = {}
        self.vulnerabilities: Dict[str, Vulnerability] = {}
        self.risks: Dict[str, Risk] = {}
        self.assessment_date = datetime.now()
        
    def log(self, message: str, level: str = "info"):
        colors = {
            "info": Colors.CYAN,
            "success": Colors.GREEN,
            "warning": Colors.YELLOW,
            "error": Colors.RED,
            "risk": Colors.PURPLE
        }
        color = colors.get(level, Colors.RESET)
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{Colors.BOLD}[{timestamp}]{Colors.RESET} {color}{message}{Colors.RESET}")
    
    def add_asset(self, asset: Asset):
        """Tambahkan aset ke inventory"""
        self.assets[asset.id] = asset
        
    def add_threat(self, threat: Threat):
        """Tambahkan threat ke catalog"""
        self.threats[threat.id] = threat
        
    def add_vulnerability(self, vuln: Vulnerability):
        """Tambahkan vulnerability"""
        self.vulnerabilities[vuln.id] = vuln
        
    def add_risk(self, risk: Risk):
        """Tambahkan dan hitung risk"""
        risk.calculate_risk_score()
        self.risks[risk.id] = risk
    
    def initialize_sample_data(self):
        """Initialize sample data untuk demonstrasi"""
        self.log("[*] Initializing sample data for PT. TechMart Indonesia...", "info")
        
        # Assets
        assets = [
            Asset("A001", "Customer Database", "data", 
                  "Database berisi data 50,000 pelanggan termasuk informasi pembayaran",
                  "IT Manager", 500000000, "critical"),
            Asset("A002", "Web Server", "hardware",
                  "Server utama menjalankan aplikasi e-commerce",
                  "System Admin", 150000000, "high"),
            Asset("A003", "E-Commerce Application", "software",
                  "Aplikasi web untuk transaksi online",
                  "Development Lead", 200000000, "critical"),
            Asset("A004", "Network Infrastructure", "hardware",
                  "Router, switch, firewall, dan perangkat jaringan",
                  "Network Admin", 100000000, "high"),
            Asset("A005", "Employee Workstations", "hardware",
                  "50 unit komputer untuk staff",
                  "IT Support", 250000000, "medium"),
            Asset("A006", "Backup Storage", "hardware",
                  "NAS untuk backup data",
                  "System Admin", 50000000, "high"),
            Asset("A007", "Source Code Repository", "data",
                  "Git repository berisi source code aplikasi",
                  "Development Lead", 300000000, "critical"),
            Asset("A008", "Payment Gateway Integration", "software",
                  "API integrasi dengan payment provider",
                  "IT Manager", 400000000, "critical"),
        ]
        
        for asset in assets:
            self.add_asset(asset)
        
        # Threats
        threats = [
            Threat("T001", "SQL Injection Attack", "cyber",
                   "Serangan injeksi SQL untuk akses database tidak sah",
                   "external"),
            Threat("T002", "Ransomware", "cyber",
                   "Malware yang mengenkripsi data dan meminta tebusan",
                   "external"),
            Threat("T003", "DDoS Attack", "cyber",
                   "Distributed Denial of Service attack",
                   "external"),
            Threat("T004", "Insider Threat", "human",
                   "Ancaman dari karyawan atau kontraktor internal",
                   "internal"),
            Threat("T005", "Phishing", "cyber",
                   "Social engineering via email atau website palsu",
                   "external"),
            Threat("T006", "Data Theft", "cyber",
                   "Pencurian data sensitif oleh pihak tidak berwenang",
                   "external"),
            Threat("T007", "Power Outage", "environmental",
                   "Gangguan listrik yang mempengaruhi operasional",
                   "environmental"),
            Threat("T008", "Physical Intrusion", "physical",
                   "Akses fisik tidak sah ke fasilitas",
                   "external"),
        ]
        
        for threat in threats:
            self.add_threat(threat)
        
        # Vulnerabilities
        vulnerabilities = [
            Vulnerability("V001", "Weak Input Validation", 
                         "Aplikasi tidak memvalidasi input user dengan benar",
                         ["A003"], 8.5),
            Vulnerability("V002", "Outdated Software",
                         "Server menjalankan software dengan versi lama",
                         ["A002", "A004"], 7.2),
            Vulnerability("V003", "Weak Password Policy",
                         "Tidak ada enforcement password yang kuat",
                         ["A001", "A003", "A005"], 6.8),
            Vulnerability("V004", "Missing Encryption",
                         "Data sensitif tidak dienkripsi",
                         ["A001", "A006"], 8.0),
            Vulnerability("V005", "No Multi-Factor Authentication",
                         "Autentikasi hanya menggunakan password",
                         ["A003", "A007"], 7.5),
            Vulnerability("V006", "Insufficient Logging",
                         "Logging tidak memadai untuk deteksi insiden",
                         ["A002", "A003", "A004"], 5.5),
            Vulnerability("V007", "No Network Segmentation",
                         "Jaringan tidak tersegmentasi dengan benar",
                         ["A004"], 6.5),
            Vulnerability("V008", "Unpatched Systems",
                         "Sistem tidak di-patch secara reguler",
                         ["A002", "A005"], 7.8),
        ]
        
        for vuln in vulnerabilities:
            self.add_vulnerability(vuln)
        
        # Risks
        risks = [
            Risk("R001", "Customer Data Breach via SQL Injection",
                 "Attacker dapat mengakses database pelanggan melalui SQL injection",
                 "A001", "T001", "V001",
                 likelihood=4, impact=5,
                 owner="IT Security Manager"),
            Risk("R002", "Ransomware Infection",
                 "Server terinfeksi ransomware menyebabkan downtime dan potensi kehilangan data",
                 "A002", "T002", "V002",
                 likelihood=3, impact=5,
                 owner="IT Manager"),
            Risk("R003", "Website Downtime from DDoS",
                 "Serangan DDoS menyebabkan website tidak dapat diakses",
                 "A003", "T003", "V007",
                 likelihood=3, impact=4,
                 owner="Network Admin"),
            Risk("R004", "Insider Data Theft",
                 "Karyawan mencuri data sensitif untuk dijual",
                 "A001", "T004", "V003",
                 likelihood=2, impact=5,
                 owner="HR Manager"),
            Risk("R005", "Account Takeover via Phishing",
                 "Staff terkena phishing dan kredensial dicuri",
                 "A005", "T005", "V005",
                 likelihood=4, impact=3,
                 owner="IT Security Manager"),
            Risk("R006", "Source Code Leak",
                 "Source code aplikasi bocor ke publik atau kompetitor",
                 "A007", "T006", "V003",
                 likelihood=2, impact=4,
                 owner="Development Lead"),
            Risk("R007", "Service Disruption from Power Failure",
                 "Pemadaman listrik menyebabkan layanan offline",
                 "A002", "T007", "V006",
                 likelihood=3, impact=3,
                 owner="Facility Manager"),
            Risk("R008", "Payment Data Compromise",
                 "Data pembayaran pelanggan dicuri saat transmisi",
                 "A008", "T006", "V004",
                 likelihood=3, impact=5,
                 owner="IT Security Manager"),
        ]
        
        for risk in risks:
            self.add_risk(risk)
        
        self.log(f"[✓] Loaded {len(self.assets)} assets, {len(self.threats)} threats, "
                f"{len(self.vulnerabilities)} vulnerabilities, {len(self.risks)} risks", "success")
    
    def print_risk_matrix(self):
        """Print visual risk matrix"""
        print(f"""
{Colors.BOLD}═══════════════════════════════════════════════════════════════
                         RISK MATRIX
═══════════════════════════════════════════════════════════════{Colors.RESET}

                              IMPACT
           │ Negligible │   Minor   │ Moderate  │   Major   │Catastrophic│
           │     (1)    │    (2)    │    (3)    │    (4)    │    (5)     │
    ───────┼────────────┼───────────┼───────────┼───────────┼────────────┤
    Very   │            │           │           │           │            │
    High(5)│   {self._get_cell_color(5)}  LOW    {Colors.RESET}│  {self._get_cell_color(10)} MEDIUM {Colors.RESET}│  {self._get_cell_color(15)}  HIGH  {Colors.RESET}│ {self._get_cell_color(20)}CRITICAL{Colors.RESET}│ {self._get_cell_color(25)}CRITICAL{Colors.RESET}│
    ───────┼────────────┼───────────┼───────────┼───────────┼────────────┤
L   High   │            │           │           │           │            │
I   (4)    │   {self._get_cell_color(4)}  LOW    {Colors.RESET}│  {self._get_cell_color(8)} MEDIUM {Colors.RESET}│  {self._get_cell_color(12)}  HIGH  {Colors.RESET}│ {self._get_cell_color(16)}CRITICAL{Colors.RESET}│ {self._get_cell_color(20)}CRITICAL{Colors.RESET}│
K   ───────┼────────────┼───────────┼───────────┼───────────┼────────────┤
E  Medium  │            │           │           │           │            │
L   (3)    │  {self._get_cell_color(3)} MINIMAL{Colors.RESET}│   {self._get_cell_color(6)}  LOW   {Colors.RESET}│  {self._get_cell_color(9)} MEDIUM {Colors.RESET}│  {self._get_cell_color(12)}  HIGH  {Colors.RESET}│  {self._get_cell_color(15)}  HIGH  {Colors.RESET}│
I   ───────┼────────────┼───────────┼───────────┼───────────┼────────────┤
H   Low    │            │           │           │           │            │
O   (2)    │  {self._get_cell_color(2)} MINIMAL{Colors.RESET}│  {self._get_cell_color(4)} MINIMAL{Colors.RESET}│   {self._get_cell_color(6)}  LOW   {Colors.RESET}│  {self._get_cell_color(8)} MEDIUM {Colors.RESET}│  {self._get_cell_color(10)} MEDIUM {Colors.RESET}│
O   ───────┼────────────┼───────────┼───────────┼───────────┼────────────┤
D  Very    │            │           │           │           │            │
    Low(1) │  {self._get_cell_color(1)} MINIMAL{Colors.RESET}│  {self._get_cell_color(2)} MINIMAL{Colors.RESET}│  {self._get_cell_color(3)} MINIMAL{Colors.RESET}│   {self._get_cell_color(4)}  LOW   {Colors.RESET}│   {self._get_cell_color(5)}  LOW   {Colors.RESET}│
    ───────┴────────────┴───────────┴───────────┴───────────┴────────────┘

{Colors.CYAN}Legend:{Colors.RESET}
  {Colors.RED}■ CRITICAL (20-25){Colors.RESET} - Immediate action required
  {Colors.PURPLE}■ HIGH (15-19){Colors.RESET}     - Priority treatment needed
  {Colors.YELLOW}■ MEDIUM (8-14){Colors.RESET}    - Treatment planning required
  {Colors.CYAN}■ LOW (4-7){Colors.RESET}        - Monitor and review
  {Colors.GREEN}■ MINIMAL (1-3){Colors.RESET}    - Acceptable risk level
        """)
    
    def _get_cell_color(self, score: int) -> str:
        """Get color based on risk score"""
        if score >= 20:
            return Colors.RED
        elif score >= 15:
            return Colors.PURPLE
        elif score >= 8:
            return Colors.YELLOW
        elif score >= 4:
            return Colors.CYAN
        else:
            return Colors.GREEN
    
    def assess_risks(self):
        """Perform risk assessment"""
        self.log("\n[*] Performing Risk Assessment...", "info")
        
        # Calculate all risk scores
        for risk_id, risk in self.risks.items():
            risk.calculate_risk_score()
        
        # Sort by risk score (descending)
        sorted_risks = sorted(self.risks.values(), 
                             key=lambda r: r.risk_score, reverse=True)
        
        print(f"""
{Colors.BOLD}═══════════════════════════════════════════════════════════════
                      RISK ASSESSMENT RESULTS
═══════════════════════════════════════════════════════════════{Colors.RESET}

{Colors.CYAN}Organization:{Colors.RESET} {self.organization}
{Colors.CYAN}Assessment Date:{Colors.RESET} {self.assessment_date.strftime('%Y-%m-%d')}
{Colors.CYAN}Total Risks Identified:{Colors.RESET} {len(self.risks)}

{Colors.YELLOW}Risk Register (Sorted by Score):{Colors.RESET}
""")
        
        print(f"{'ID':<8} {'Risk Name':<40} {'L':>3} {'I':>3} {'Score':>6} {'Level':<10}")
        print("-" * 75)
        
        for risk in sorted_risks:
            level_color = self._get_cell_color(risk.risk_score)
            print(f"{risk.id:<8} {risk.name[:40]:<40} {risk.likelihood:>3} {risk.impact:>3} "
                  f"{risk.risk_score:>6} {level_color}{risk.risk_level:<10}{Colors.RESET}")
        
        # Summary statistics
        critical_count = sum(1 for r in self.risks.values() if r.risk_level == "CRITICAL")
        high_count = sum(1 for r in self.risks.values() if r.risk_level == "HIGH")
        medium_count = sum(1 for r in self.risks.values() if r.risk_level == "MEDIUM")
        low_count = sum(1 for r in self.risks.values() if r.risk_level in ["LOW", "MINIMAL"])
        
        print(f"""
{Colors.BOLD}Risk Level Distribution:{Colors.RESET}
  {Colors.RED}• CRITICAL:{Colors.RESET} {critical_count}
  {Colors.PURPLE}• HIGH:{Colors.RESET}     {high_count}
  {Colors.YELLOW}• MEDIUM:{Colors.RESET}   {medium_count}
  {Colors.GREEN}• LOW:{Colors.RESET}      {low_count}
        """)
        
        return sorted_risks
    
    def recommend_treatments(self):
        """Generate treatment recommendations"""
        self.log("\n[*] Generating Treatment Recommendations...", "info")
        
        recommendations = []
        
        for risk in sorted(self.risks.values(), 
                          key=lambda r: r.risk_score, reverse=True):
            treatment = self._determine_treatment(risk)
            recommendations.append({
                "risk_id": risk.id,
                "risk_name": risk.name,
                "risk_score": risk.risk_score,
                "risk_level": risk.risk_level,
                "recommended_strategy": treatment["strategy"],
                "recommended_controls": treatment["controls"],
                "estimated_cost": treatment["cost"],
                "implementation_priority": treatment["priority"]
            })
            
            # Update risk with treatment
            risk.treatment_strategy = treatment["strategy"]
            risk.treatment_plan = "; ".join(treatment["controls"])
        
        print(f"""
{Colors.BOLD}═══════════════════════════════════════════════════════════════
                    TREATMENT RECOMMENDATIONS
═══════════════════════════════════════════════════════════════{Colors.RESET}
        """)
        
        for rec in recommendations[:5]:  # Top 5 risks
            print(f"""
{Colors.YELLOW}Risk:{Colors.RESET} {rec['risk_name']}
{Colors.CYAN}Level:{Colors.RESET} {rec['risk_level']} (Score: {rec['risk_score']})
{Colors.GREEN}Strategy:{Colors.RESET} {rec['recommended_strategy']}
{Colors.PURPLE}Priority:{Colors.RESET} {rec['implementation_priority']}
{Colors.CYAN}Recommended Controls:{Colors.RESET}""")
            for control in rec['recommended_controls']:
                print(f"  • {control}")
            print(f"{Colors.YELLOW}Estimated Cost:{Colors.RESET} Rp {rec['estimated_cost']:,.0f}")
            print("-" * 60)
        
        return recommendations
    
    def _determine_treatment(self, risk: Risk) -> Dict:
        """Determine appropriate treatment for a risk"""
        
        # Default treatment templates based on risk characteristics
        treatments = {
            "R001": {  # SQL Injection
                "strategy": TreatmentStrategy.MITIGATE.value,
                "controls": [
                    "Implement parameterized queries / prepared statements",
                    "Deploy Web Application Firewall (WAF)",
                    "Conduct regular security code reviews",
                    "Implement input validation and sanitization",
                    "Enable SQL query logging and monitoring"
                ],
                "cost": 75000000,
                "priority": "IMMEDIATE"
            },
            "R002": {  # Ransomware
                "strategy": TreatmentStrategy.MITIGATE.value,
                "controls": [
                    "Implement endpoint detection and response (EDR)",
                    "Maintain offline backups (3-2-1 rule)",
                    "Deploy email security gateway",
                    "Regular security awareness training",
                    "Network segmentation"
                ],
                "cost": 150000000,
                "priority": "HIGH"
            },
            "R003": {  # DDoS
                "strategy": TreatmentStrategy.TRANSFER.value,
                "controls": [
                    "Subscribe to DDoS protection service",
                    "Implement CDN with DDoS mitigation",
                    "Configure rate limiting",
                    "Develop DDoS response playbook"
                ],
                "cost": 50000000,
                "priority": "MEDIUM"
            },
            "R004": {  # Insider Threat
                "strategy": TreatmentStrategy.MITIGATE.value,
                "controls": [
                    "Implement Data Loss Prevention (DLP)",
                    "User activity monitoring",
                    "Principle of least privilege",
                    "Regular access reviews",
                    "Background checks for sensitive positions"
                ],
                "cost": 100000000,
                "priority": "MEDIUM"
            },
            "R005": {  # Phishing
                "strategy": TreatmentStrategy.MITIGATE.value,
                "controls": [
                    "Implement Multi-Factor Authentication (MFA)",
                    "Deploy email security with anti-phishing",
                    "Regular phishing simulation exercises",
                    "Security awareness training"
                ],
                "cost": 30000000,
                "priority": "HIGH"
            },
            "R006": {  # Source Code Leak
                "strategy": TreatmentStrategy.MITIGATE.value,
                "controls": [
                    "Implement repository access controls",
                    "Enable audit logging for code access",
                    "Use secrets management solution",
                    "Code signing and integrity verification"
                ],
                "cost": 25000000,
                "priority": "MEDIUM"
            },
            "R007": {  # Power Failure
                "strategy": TreatmentStrategy.MITIGATE.value,
                "controls": [
                    "Install UPS systems",
                    "Backup generator",
                    "Redundant power supply",
                    "Cloud failover capability"
                ],
                "cost": 75000000,
                "priority": "LOW"
            },
            "R008": {  # Payment Data Compromise
                "strategy": TreatmentStrategy.MITIGATE.value,
                "controls": [
                    "Implement TLS 1.3 for all transmissions",
                    "PCI DSS compliance assessment",
                    "Tokenization for payment data",
                    "Regular penetration testing"
                ],
                "cost": 100000000,
                "priority": "IMMEDIATE"
            },
        }
        
        # Return specific treatment or default
        if risk.id in treatments:
            return treatments[risk.id]
        
        # Default treatment based on risk level
        if risk.risk_level == "CRITICAL":
            return {
                "strategy": TreatmentStrategy.MITIGATE.value,
                "controls": ["Immediate security assessment required", 
                            "Implement emergency controls"],
                "cost": 100000000,
                "priority": "IMMEDIATE"
            }
        elif risk.risk_level == "HIGH":
            return {
                "strategy": TreatmentStrategy.MITIGATE.value,
                "controls": ["Security review required", 
                            "Implement compensating controls"],
                "cost": 50000000,
                "priority": "HIGH"
            }
        else:
            return {
                "strategy": TreatmentStrategy.ACCEPT.value,
                "controls": ["Continue monitoring", 
                            "Review in next assessment cycle"],
                "cost": 0,
                "priority": "LOW"
            }
    
    def generate_report(self, output_file: str = None) -> Dict:
        """Generate comprehensive risk assessment report"""
        self.log("\n[*] Generating Risk Assessment Report...", "info")
        
        report = {
            "report_info": {
                "title": "Information Security Risk Assessment Report",
                "organization": self.organization,
                "assessment_date": self.assessment_date.isoformat(),
                "generated_at": datetime.now().isoformat(),
                "assessor": "Risk Assessment Tool v1.0"
            },
            "executive_summary": {
                "total_assets": len(self.assets),
                "total_threats": len(self.threats),
                "total_vulnerabilities": len(self.vulnerabilities),
                "total_risks": len(self.risks),
                "risk_distribution": {
                    "critical": sum(1 for r in self.risks.values() if r.risk_level == "CRITICAL"),
                    "high": sum(1 for r in self.risks.values() if r.risk_level == "HIGH"),
                    "medium": sum(1 for r in self.risks.values() if r.risk_level == "MEDIUM"),
                    "low": sum(1 for r in self.risks.values() if r.risk_level in ["LOW", "MINIMAL"])
                }
            },
            "assets": {aid: asdict(a) for aid, a in self.assets.items()},
            "threats": {tid: asdict(t) for tid, t in self.threats.items()},
            "vulnerabilities": {vid: asdict(v) for vid, v in self.vulnerabilities.items()},
            "risks": {rid: asdict(r) for rid, r in self.risks.items()},
            "recommendations": self._generate_summary_recommendations()
        }
        
        if not output_file:
            output_file = f"risk_assessment_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        self.log(f"[✓] Report saved: {output_file}", "success")
        
        return report
    
    def _generate_summary_recommendations(self) -> List[Dict]:
        """Generate summary recommendations"""
        recs = []
        
        critical_risks = [r for r in self.risks.values() if r.risk_level == "CRITICAL"]
        if critical_risks:
            recs.append({
                "priority": 1,
                "category": "Critical Risks",
                "recommendation": f"Immediately address {len(critical_risks)} critical risks that pose significant threat to the organization",
                "affected_risks": [r.id for r in critical_risks]
            })
        
        high_risks = [r for r in self.risks.values() if r.risk_level == "HIGH"]
        if high_risks:
            recs.append({
                "priority": 2,
                "category": "High Risks",
                "recommendation": f"Develop treatment plans for {len(high_risks)} high-level risks within 30 days",
                "affected_risks": [r.id for r in high_risks]
            })
        
        recs.append({
            "priority": 3,
            "category": "General",
            "recommendation": "Conduct follow-up risk assessment in 6 months",
            "affected_risks": []
        })
        
        return recs


def main():
    banner()
    
    org_name = sys.argv[1] if len(sys.argv) > 1 else "PT. TechMart Indonesia"
    
    print(f"{Colors.BOLD}Organization: {org_name}{Colors.RESET}\n")
    
    # Initialize tool
    tool = RiskAssessmentTool(org_name)
    
    # Load sample data
    tool.initialize_sample_data()
    
    # Print risk matrix
    tool.print_risk_matrix()
    
    # Perform assessment
    tool.assess_risks()
    
    # Generate recommendations
    tool.recommend_treatments()
    
    # Generate report
    report = tool.generate_report()
    
    print(f"""
{Colors.CYAN}Risk Assessment Complete!{Colors.RESET}

{Colors.GREEN}Key Actions Required:{Colors.RESET}
1. Review and prioritize critical risks
2. Develop treatment plans for high-priority risks
3. Allocate budget for security controls
4. Assign risk owners and deadlines
5. Schedule follow-up assessment

{Colors.YELLOW}For detailed analysis, review the generated JSON report.{Colors.RESET}
    """)


if __name__ == "__main__":
    main()
