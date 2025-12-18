#!/usr/bin/env python3
"""
Reconnaissance Script - Information Gathering
PT. TechMart Indonesia Attack Simulation

DISCLAIMER: This script is for EDUCATIONAL PURPOSES ONLY!
Only use on systems you have permission to test.

Materi: CPMK-6 - Forensik Digital & Manajemen Risiko
"""

import requests
import socket
import sys
import json
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
║{Colors.YELLOW}  🔍 RECONNAISSANCE TOOL - Simulasi Forensik Digital          {Colors.RED}║
║{Colors.CYAN}     PT. TechMart Indonesia - Educational Purpose Only        {Colors.RED}║
╚══════════════════════════════════════════════════════════════╝{Colors.RESET}
    """)

class Reconnaissance:
    def __init__(self, target_ip, target_port=80):
        self.target_ip = target_ip
        self.target_port = target_port
        self.base_url = f"http://{target_ip}:{target_port}"
        self.findings = {
            "target": target_ip,
            "timestamp": datetime.now().isoformat(),
            "open_ports": [],
            "web_info": {},
            "directories": [],
            "forms": [],
            "potential_vulns": []
        }
    
    def log(self, message, level="info"):
        colors = {
            "info": Colors.CYAN,
            "success": Colors.GREEN,
            "warning": Colors.YELLOW,
            "error": Colors.RED,
            "finding": Colors.PURPLE
        }
        color = colors.get(level, Colors.RESET)
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{Colors.BOLD}[{timestamp}]{Colors.RESET} {color}{message}{Colors.RESET}")
    
    def port_scan(self, ports=[21, 22, 23, 25, 53, 80, 443, 3306, 5432, 8080, 8443]):
        """Scan common ports"""
        self.log(f"[*] Starting port scan on {self.target_ip}...", "info")
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.target_ip, port))
                if result == 0:
                    service = self.get_service_name(port)
                    self.log(f"    [+] Port {port}/tcp OPEN ({service})", "success")
                    self.findings["open_ports"].append({
                        "port": port,
                        "service": service,
                        "state": "open"
                    })
                sock.close()
            except Exception as e:
                pass
        
        self.log(f"[✓] Port scan complete. Found {len(self.findings['open_ports'])} open ports.", "success")
    
    def get_service_name(self, port):
        """Get common service name for port"""
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 443: "HTTPS", 3306: "MySQL",
            5432: "PostgreSQL", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
        }
        return services.get(port, "Unknown")
    
    def web_fingerprint(self):
        """Gather web server information"""
        self.log(f"[*] Fingerprinting web server...", "info")
        
        try:
            response = requests.get(self.base_url, timeout=10)
            headers = response.headers
            
            # Server header
            server = headers.get('Server', 'Unknown')
            self.log(f"    [+] Server: {server}", "finding")
            self.findings["web_info"]["server"] = server
            
            # X-Powered-By
            powered_by = headers.get('X-Powered-By', 'Not disclosed')
            self.log(f"    [+] X-Powered-By: {powered_by}", "finding")
            self.findings["web_info"]["powered_by"] = powered_by
            
            # Check security headers
            security_headers = {
                "X-Frame-Options": headers.get('X-Frame-Options', 'MISSING'),
                "X-XSS-Protection": headers.get('X-XSS-Protection', 'MISSING'),
                "X-Content-Type-Options": headers.get('X-Content-Type-Options', 'MISSING'),
                "Content-Security-Policy": headers.get('Content-Security-Policy', 'MISSING'),
                "Strict-Transport-Security": headers.get('Strict-Transport-Security', 'MISSING')
            }
            
            self.log(f"[*] Security Headers Analysis:", "info")
            for header, value in security_headers.items():
                if value == 'MISSING':
                    self.log(f"    [!] {header}: {value}", "warning")
                    self.findings["potential_vulns"].append(f"Missing security header: {header}")
                else:
                    self.log(f"    [+] {header}: {value}", "success")
            
            self.findings["web_info"]["security_headers"] = security_headers
            
        except Exception as e:
            self.log(f"[!] Error fingerprinting web server: {e}", "error")
    
    def directory_bruteforce(self):
        """Simple directory bruteforce"""
        self.log(f"[*] Starting directory enumeration...", "info")
        
        common_dirs = [
            '', 'admin', 'login', 'dashboard', 'api', 'backup',
            'config', 'upload', 'uploads', 'images', 'css', 'js',
            'includes', 'inc', 'lib', 'tmp', 'temp', 'logs',
            'test', 'debug', 'old', 'new', 'data', 'database',
            'db', 'sql', 'mysql', 'phpmyadmin', 'adminer',
            'wp-admin', 'wp-content', 'administrator',
            'customers', 'users', 'export', 'search', 'products',
            '.git', '.svn', '.htaccess', 'robots.txt', 'sitemap.xml',
            '.hidden', 'secret', 'private', 'internal'
        ]
        
        found_dirs = []
        for directory in common_dirs:
            url = urljoin(self.base_url + '/', directory)
            try:
                response = requests.get(url, timeout=5, allow_redirects=False)
                if response.status_code in [200, 301, 302, 403]:
                    status_text = {200: "OK", 301: "Redirect", 302: "Redirect", 403: "Forbidden"}
                    self.log(f"    [+] /{directory} - {response.status_code} {status_text.get(response.status_code, '')}", "success")
                    found_dirs.append({
                        "path": f"/{directory}",
                        "status": response.status_code,
                        "url": url
                    })
            except:
                pass
        
        self.findings["directories"] = found_dirs
        self.log(f"[✓] Found {len(found_dirs)} accessible paths.", "success")
    
    def find_forms(self):
        """Find and analyze HTML forms for potential injection points"""
        self.log(f"[*] Searching for HTML forms...", "info")
        
        pages_to_check = ['/', '/login.php', '/search.php', '/search_customers.php', '/index.php']
        
        for page in pages_to_check:
            url = urljoin(self.base_url, page)
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    # Simple form detection
                    forms = re.findall(r'<form[^>]*>(.*?)</form>', response.text, re.DOTALL | re.IGNORECASE)
                    for i, form in enumerate(forms):
                        # Find input fields
                        inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', form, re.IGNORECASE)
                        method = re.search(r'method=["\']([^"\']+)["\']', form, re.IGNORECASE)
                        action = re.search(r'action=["\']([^"\']+)["\']', form, re.IGNORECASE)
                        
                        form_info = {
                            "page": page,
                            "method": method.group(1) if method else "GET",
                            "action": action.group(1) if action else page,
                            "inputs": inputs
                        }
                        
                        self.log(f"    [+] Form found at {page}", "finding")
                        self.log(f"        Method: {form_info['method']}, Inputs: {', '.join(inputs)}", "info")
                        
                        # Check for potential SQL injection points
                        if any(inp in ['username', 'password', 'user', 'pass', 'id', 'search', 'q', 'query'] for inp in inputs):
                            self.log(f"        [!] Potential SQL injection point detected!", "warning")
                            self.findings["potential_vulns"].append(f"SQL Injection candidate at {page}: {inputs}")
                        
                        self.findings["forms"].append(form_info)
            except:
                pass
    
    def check_robots_txt(self):
        """Check robots.txt for sensitive paths"""
        self.log(f"[*] Checking robots.txt...", "info")
        
        try:
            response = requests.get(f"{self.base_url}/robots.txt", timeout=5)
            if response.status_code == 200:
                self.log(f"    [+] robots.txt found:", "success")
                disallowed = re.findall(r'Disallow:\s*(.+)', response.text)
                for path in disallowed:
                    self.log(f"        Disallow: {path.strip()}", "finding")
                    self.findings["directories"].append({
                        "path": path.strip(),
                        "source": "robots.txt",
                        "status": "unknown"
                    })
            else:
                self.log(f"    [-] robots.txt not found", "info")
        except:
            pass
    
    def generate_report(self, output_file="recon_report.json"):
        """Generate JSON report"""
        self.log(f"\n[*] Generating report...", "info")
        
        with open(output_file, 'w') as f:
            json.dump(self.findings, f, indent=2)
        
        self.log(f"[✓] Report saved to {output_file}", "success")
        
        # Print summary
        print(f"""
{Colors.BOLD}═══════════════════════════════════════════════════════════════
                    RECONNAISSANCE SUMMARY
═══════════════════════════════════════════════════════════════{Colors.RESET}

{Colors.CYAN}Target:{Colors.RESET} {self.target_ip}
{Colors.CYAN}Timestamp:{Colors.RESET} {self.findings['timestamp']}

{Colors.GREEN}Open Ports:{Colors.RESET} {len(self.findings['open_ports'])}
{Colors.GREEN}Directories Found:{Colors.RESET} {len(self.findings['directories'])}
{Colors.GREEN}Forms Found:{Colors.RESET} {len(self.findings['forms'])}
{Colors.YELLOW}Potential Vulnerabilities:{Colors.RESET} {len(self.findings['potential_vulns'])}

{Colors.RED}Potential Vulnerabilities:{Colors.RESET}
""")
        for vuln in self.findings['potential_vulns']:
            print(f"  • {vuln}")
        
        print(f"""
{Colors.BOLD}═══════════════════════════════════════════════════════════════{Colors.RESET}
        """)
        
        return self.findings
    
    def run_full_recon(self):
        """Run complete reconnaissance"""
        self.port_scan()
        print()
        self.web_fingerprint()
        print()
        self.check_robots_txt()
        print()
        self.directory_bruteforce()
        print()
        self.find_forms()
        print()
        return self.generate_report()


def main():
    banner()
    
    # Default target (Docker/Vagrant)
    target_ip = sys.argv[1] if len(sys.argv) > 1 else "172.20.0.10"
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    
    print(f"{Colors.BOLD}Target: {target_ip}:{target_port}{Colors.RESET}\n")
    
    recon = Reconnaissance(target_ip, target_port)
    findings = recon.run_full_recon()
    
    print(f"""
{Colors.YELLOW}Next Steps:{Colors.RESET}
1. Review potential vulnerabilities
2. Run sql_injection.py for SQL injection testing
3. Run data_exfiltration.py for data extraction simulation
4. Document all findings for forensic analysis
    """)


if __name__ == "__main__":
    main()
