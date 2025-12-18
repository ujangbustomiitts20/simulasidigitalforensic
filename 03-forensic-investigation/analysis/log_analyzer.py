#!/usr/bin/env python3
"""
Log Analyzer untuk Forensik Digital
Menganalisis Apache access logs, error logs, dan system logs

Materi: CPMK-6 - Forensik Digital & Manajemen Risiko
Prinsip: Comprehensive Analysis
"""

import re
import json
import sys
import os
from datetime import datetime
from collections import defaultdict, Counter
from typing import List, Dict, Any
import hashlib

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
║{Colors.YELLOW}  📊 FORENSIC LOG ANALYZER                                    {Colors.CYAN}║
║{Colors.GREEN}     Digital Forensics - Comprehensive Analysis               {Colors.CYAN}║
╚══════════════════════════════════════════════════════════════╝{Colors.RESET}
    """)

class LogAnalyzer:
    """
    Forensic Log Analyzer
    Menganalisis berbagai jenis log untuk investigasi keamanan
    """
    
    # Apache Combined Log Format regex
    APACHE_LOG_PATTERN = re.compile(
        r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        r' - (?P<user>\S+)'
        r' \[(?P<timestamp>[^\]]+)\]'
        r' "(?P<method>\w+) (?P<url>\S+) (?P<protocol>[^"]+)"'
        r' (?P<status>\d{3})'
        r' (?P<size>\d+|-)'
        r'(?: "(?P<referer>[^"]*)")?'
        r'(?: "(?P<user_agent>[^"]*)")?'
    )
    
    # SQL Injection patterns
    SQLI_PATTERNS = [
        r"('|\")\s*(or|and)\s*('|\"|\d)",
        r"union\s+(all\s+)?select",
        r"select\s+.+\s+from",
        r"drop\s+(table|database)",
        r"insert\s+into",
        r"delete\s+from",
        r"update\s+.+\s+set",
        r"--\s*$",
        r"#\s*$",
        r"/\*.*\*/",
        r"1\s*=\s*1",
        r"'\s*=\s*'",
        r"sleep\s*\(",
        r"benchmark\s*\(",
        r"load_file\s*\(",
        r"into\s+outfile",
        r"information_schema",
        r"@@version",
        r"concat\s*\(",
        r"char\s*\(",
    ]
    
    # XSS patterns
    XSS_PATTERNS = [
        r"<script",
        r"javascript:",
        r"onerror\s*=",
        r"onload\s*=",
        r"onclick\s*=",
        r"onmouseover\s*=",
        r"<iframe",
        r"<img\s+src\s*=",
        r"document\.cookie",
        r"alert\s*\(",
        r"eval\s*\(",
    ]
    
    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e/",
        r"%2e%2e\\",
        r"/etc/passwd",
        r"/etc/shadow",
        r"c:\\windows",
        r"boot\.ini",
    ]
    
    # Suspicious User Agents
    SUSPICIOUS_UA = [
        "sqlmap",
        "nikto",
        "nmap",
        "masscan",
        "hydra",
        "burp",
        "owasp",
        "dirbuster",
        "gobuster",
        "wfuzz",
        "curl",
        "wget",
        "python-requests",
    ]
    
    def __init__(self, case_id: str = "CASE_001"):
        self.case_id = case_id
        self.findings = {
            "case_id": case_id,
            "analysis_timestamp": datetime.now().isoformat(),
            "logs_analyzed": [],
            "suspicious_ips": defaultdict(list),
            "attack_attempts": [],
            "timeline": [],
            "statistics": {},
            "recommendations": []
        }
        self.parsed_logs = []
    
    def log(self, message: str, level: str = "info"):
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
    
    def parse_apache_log(self, log_line: str) -> Dict[str, Any]:
        """Parse single Apache log line"""
        match = self.APACHE_LOG_PATTERN.match(log_line)
        if match:
            return match.groupdict()
        return None
    
    def analyze_log_file(self, filepath: str, log_type: str = "apache"):
        """Analyze a log file"""
        self.log(f"\n[*] Analyzing: {filepath}", "info")
        
        if not os.path.exists(filepath):
            self.log(f"[!] File not found: {filepath}", "error")
            return
        
        self.findings["logs_analyzed"].append({
            "file": filepath,
            "type": log_type,
            "analyzed_at": datetime.now().isoformat()
        })
        
        line_count = 0
        attack_count = 0
        
        with open(filepath, 'r', errors='ignore') as f:
            for line in f:
                line_count += 1
                
                if log_type == "apache":
                    parsed = self.parse_apache_log(line)
                    if parsed:
                        self.parsed_logs.append(parsed)
                        
                        # Check for attacks
                        attacks = self.detect_attacks(parsed, line)
                        if attacks:
                            attack_count += len(attacks)
                            for attack in attacks:
                                self.findings["attack_attempts"].append({
                                    "line_number": line_count,
                                    "log_file": filepath,
                                    **attack
                                })
                else:
                    # Generic log analysis
                    self.analyze_generic_log_line(line, line_count, filepath)
        
        self.log(f"[✓] Analyzed {line_count} lines", "success")
        self.log(f"[!] Found {attack_count} potential attack indicators", "warning" if attack_count > 0 else "info")
    
    def detect_attacks(self, parsed_log: Dict, raw_line: str) -> List[Dict]:
        """Detect various attack patterns"""
        attacks = []
        url = parsed_log.get('url', '')
        user_agent = parsed_log.get('user_agent', '')
        ip = parsed_log.get('ip', '')
        
        # Check SQL Injection
        for pattern in self.SQLI_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                attacks.append({
                    "type": "SQL Injection",
                    "pattern": pattern,
                    "ip": ip,
                    "url": url,
                    "timestamp": parsed_log.get('timestamp'),
                    "severity": "HIGH"
                })
                break
        
        # Check XSS
        for pattern in self.XSS_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                attacks.append({
                    "type": "Cross-Site Scripting (XSS)",
                    "pattern": pattern,
                    "ip": ip,
                    "url": url,
                    "timestamp": parsed_log.get('timestamp'),
                    "severity": "MEDIUM"
                })
                break
        
        # Check Path Traversal
        for pattern in self.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                attacks.append({
                    "type": "Path Traversal",
                    "pattern": pattern,
                    "ip": ip,
                    "url": url,
                    "timestamp": parsed_log.get('timestamp'),
                    "severity": "HIGH"
                })
                break
        
        # Check Suspicious User Agents
        for ua in self.SUSPICIOUS_UA:
            if ua.lower() in user_agent.lower():
                attacks.append({
                    "type": "Suspicious Tool Detected",
                    "tool": ua,
                    "ip": ip,
                    "user_agent": user_agent,
                    "timestamp": parsed_log.get('timestamp'),
                    "severity": "MEDIUM"
                })
                break
        
        # Track suspicious IPs
        if attacks:
            self.findings["suspicious_ips"][ip].extend([a["type"] for a in attacks])
        
        return attacks
    
    def analyze_generic_log_line(self, line: str, line_num: int, filepath: str):
        """Analyze generic log lines"""
        suspicious_keywords = [
            "failed", "error", "denied", "unauthorized", "invalid",
            "attack", "injection", "malicious", "blocked", "suspicious"
        ]
        
        line_lower = line.lower()
        for keyword in suspicious_keywords:
            if keyword in line_lower:
                self.findings["attack_attempts"].append({
                    "type": "Suspicious Log Entry",
                    "keyword": keyword,
                    "line_number": line_num,
                    "log_file": filepath,
                    "content": line.strip()[:200],
                    "severity": "LOW"
                })
                break
    
    def calculate_statistics(self):
        """Calculate analysis statistics"""
        self.log("\n[*] Calculating statistics...", "info")
        
        # IP statistics
        ip_counter = Counter(log.get('ip') for log in self.parsed_logs if log)
        
        # Status code distribution
        status_counter = Counter(log.get('status') for log in self.parsed_logs if log)
        
        # Request method distribution
        method_counter = Counter(log.get('method') for log in self.parsed_logs if log)
        
        # Most accessed URLs
        url_counter = Counter(log.get('url') for log in self.parsed_logs if log)
        
        # Attack type distribution
        attack_types = Counter(a.get('type') for a in self.findings["attack_attempts"])
        
        self.findings["statistics"] = {
            "total_requests": len(self.parsed_logs),
            "unique_ips": len(ip_counter),
            "top_ips": ip_counter.most_common(10),
            "status_codes": dict(status_counter),
            "request_methods": dict(method_counter),
            "top_urls": url_counter.most_common(10),
            "attack_type_distribution": dict(attack_types),
            "total_attacks_detected": len(self.findings["attack_attempts"]),
            "suspicious_ip_count": len(self.findings["suspicious_ips"])
        }
    
    def generate_timeline(self):
        """Generate attack timeline"""
        self.log("[*] Generating attack timeline...", "info")
        
        timeline = []
        for attack in sorted(self.findings["attack_attempts"], 
                           key=lambda x: x.get('timestamp', '')):
            timeline.append({
                "timestamp": attack.get('timestamp'),
                "type": attack.get('type'),
                "ip": attack.get('ip'),
                "severity": attack.get('severity'),
                "details": attack.get('url', attack.get('content', ''))[:100]
            })
        
        self.findings["timeline"] = timeline
    
    def generate_recommendations(self):
        """Generate security recommendations based on findings"""
        self.log("[*] Generating recommendations...", "info")
        
        recommendations = []
        
        # Check for SQL Injection
        sqli_attacks = [a for a in self.findings["attack_attempts"] 
                       if a.get('type') == "SQL Injection"]
        if sqli_attacks:
            recommendations.append({
                "priority": "HIGH",
                "issue": "SQL Injection attempts detected",
                "count": len(sqli_attacks),
                "recommendation": "Implement parameterized queries, input validation, and WAF rules"
            })
        
        # Check for XSS
        xss_attacks = [a for a in self.findings["attack_attempts"] 
                      if a.get('type') == "Cross-Site Scripting (XSS)"]
        if xss_attacks:
            recommendations.append({
                "priority": "MEDIUM",
                "issue": "XSS attempts detected",
                "count": len(xss_attacks),
                "recommendation": "Implement output encoding, Content Security Policy, and input sanitization"
            })
        
        # Check for scanning tools
        tool_detections = [a for a in self.findings["attack_attempts"] 
                         if a.get('type') == "Suspicious Tool Detected"]
        if tool_detections:
            recommendations.append({
                "priority": "MEDIUM",
                "issue": "Security scanning tools detected",
                "count": len(tool_detections),
                "recommendation": "Review firewall rules, implement rate limiting, consider blocking known scanner signatures"
            })
        
        # High volume from single IP
        stats = self.findings.get("statistics", {})
        top_ips = stats.get("top_ips", [])
        for ip, count in top_ips[:3]:
            if count > 100:
                recommendations.append({
                    "priority": "MEDIUM",
                    "issue": f"High request volume from IP: {ip}",
                    "count": count,
                    "recommendation": f"Investigate IP {ip}, consider rate limiting or blocking"
                })
        
        self.findings["recommendations"] = recommendations
    
    def generate_report(self, output_file: str = None):
        """Generate forensic analysis report"""
        self.calculate_statistics()
        self.generate_timeline()
        self.generate_recommendations()
        
        if not output_file:
            output_file = f"log_analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Calculate report hash
        report_content = json.dumps(self.findings, indent=2, default=str)
        report_hash = hashlib.sha256(report_content.encode()).hexdigest()
        self.findings["report_hash"] = report_hash
        
        with open(output_file, 'w') as f:
            json.dump(self.findings, f, indent=2, default=str)
        
        self.log(f"\n[✓] Report saved: {output_file}", "success")
        self.log(f"[✓] Report SHA-256: {report_hash}", "info")
        
        # Print summary
        self.print_summary()
        
        return self.findings
    
    def print_summary(self):
        """Print analysis summary"""
        stats = self.findings.get("statistics", {})
        
        print(f"""
{Colors.BOLD}═══════════════════════════════════════════════════════════════
                    LOG ANALYSIS SUMMARY
═══════════════════════════════════════════════════════════════{Colors.RESET}

{Colors.CYAN}Case ID:{Colors.RESET} {self.case_id}
{Colors.CYAN}Analysis Time:{Colors.RESET} {self.findings['analysis_timestamp']}

{Colors.GREEN}Statistics:{Colors.RESET}
  • Total Requests Analyzed: {stats.get('total_requests', 0):,}
  • Unique IP Addresses: {stats.get('unique_ips', 0):,}
  • Total Attacks Detected: {stats.get('total_attacks_detected', 0):,}
  • Suspicious IPs: {stats.get('suspicious_ip_count', 0):,}

{Colors.RED}Attack Summary:{Colors.RESET}
""")
        
        for attack_type, count in stats.get('attack_type_distribution', {}).items():
            print(f"  • {attack_type}: {count}")
        
        print(f"""
{Colors.YELLOW}Top Suspicious IPs:{Colors.RESET}
""")
        for ip, attacks in list(self.findings["suspicious_ips"].items())[:5]:
            print(f"  • {ip}: {len(attacks)} attack indicators")
        
        print(f"""
{Colors.PURPLE}Recommendations:{Colors.RESET}
""")
        for rec in self.findings.get("recommendations", []):
            print(f"  [{rec['priority']}] {rec['issue']}")
            print(f"       → {rec['recommendation']}")
        
        print(f"""
{Colors.BOLD}═══════════════════════════════════════════════════════════════{Colors.RESET}
        """)


def create_sample_logs(output_dir: str = "."):
    """Create sample log files for demonstration"""
    sample_logs = """192.168.56.20 - - [18/Dec/2025:10:15:23 +0700] "GET /index.php HTTP/1.1" 200 5234 "-" "Mozilla/5.0"
192.168.56.20 - - [18/Dec/2025:10:15:25 +0700] "GET /login.php HTTP/1.1" 200 3456 "-" "Mozilla/5.0"
192.168.56.20 - - [18/Dec/2025:10:15:30 +0700] "POST /login.php HTTP/1.1" 200 3456 "-" "sqlmap/1.5"
192.168.56.20 - - [18/Dec/2025:10:15:35 +0700] "POST /login.php HTTP/1.1" 302 0 "-" "sqlmap/1.5"
192.168.56.20 - - [18/Dec/2025:10:16:00 +0700] "GET /search_customers.php?q=' OR '1'='1 HTTP/1.1" 200 45678 "-" "sqlmap/1.5"
192.168.56.20 - - [18/Dec/2025:10:16:05 +0700] "GET /search_customers.php?q=' UNION SELECT * FROM users-- HTTP/1.1" 200 12345 "-" "sqlmap/1.5"
192.168.56.20 - - [18/Dec/2025:10:16:10 +0700] "GET /search_customers.php?q=' UNION SELECT NULL,@@version,NULL,NULL-- HTTP/1.1" 200 8765 "-" "sqlmap/1.5"
192.168.56.20 - - [18/Dec/2025:10:17:00 +0700] "GET /customers.php HTTP/1.1" 200 98765 "-" "sqlmap/1.5"
192.168.56.20 - - [18/Dec/2025:10:17:30 +0700] "GET /export.php HTTP/1.1" 200 234567 "-" "Python-requests/2.28.0"
192.168.56.20 - - [18/Dec/2025:10:18:00 +0700] "GET /.hidden/shell.php?cmd=id HTTP/1.1" 404 1234 "-" "curl/7.68.0"
10.0.0.50 - - [18/Dec/2025:10:20:00 +0700] "GET /admin/../../../etc/passwd HTTP/1.1" 403 567 "-" "Nikto/2.1.6"
10.0.0.50 - - [18/Dec/2025:10:20:05 +0700] "GET /index.php?page=<script>alert(1)</script> HTTP/1.1" 200 5234 "-" "Nikto/2.1.6"
10.0.0.50 - - [18/Dec/2025:10:20:10 +0700] "GET /index.php?id=1;DROP TABLE users HTTP/1.1" 500 234 "-" "Nikto/2.1.6"
192.168.1.100 - - [18/Dec/2025:10:25:00 +0700] "GET /index.php HTTP/1.1" 200 5234 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
192.168.1.100 - - [18/Dec/2025:10:25:05 +0700] "GET /products.php HTTP/1.1" 200 8765 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
"""
    
    log_file = os.path.join(output_dir, "sample_access.log")
    with open(log_file, 'w') as f:
        f.write(sample_logs)
    
    return log_file


def main():
    banner()
    
    case_id = sys.argv[1] if len(sys.argv) > 1 else f"CASE_{datetime.now().strftime('%Y%m%d')}"
    log_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    print(f"{Colors.BOLD}Case ID: {case_id}{Colors.RESET}\n")
    
    analyzer = LogAnalyzer(case_id)
    
    if log_file and os.path.exists(log_file):
        analyzer.analyze_log_file(log_file, "apache")
    else:
        # Create and analyze sample logs for demonstration
        print(f"{Colors.YELLOW}[*] No log file specified. Creating sample logs for demonstration...{Colors.RESET}\n")
        sample_log = create_sample_logs()
        analyzer.analyze_log_file(sample_log, "apache")
    
    # Generate report
    analyzer.generate_report()
    
    print(f"""
{Colors.CYAN}Next Steps:{Colors.RESET}
1. Review detected attack patterns
2. Investigate suspicious IPs
3. Correlate with other evidence sources
4. Document findings in forensic report
5. Implement recommended security measures
    """)


if __name__ == "__main__":
    main()
