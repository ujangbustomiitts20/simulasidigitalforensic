#!/usr/bin/env python3
"""
Forensic Toolkit - All-in-One Forensic Investigation Tool
Menggabungkan berbagai fungsi forensik dalam satu interface

Materi: CPMK-6 - Forensik Digital & Manajemen Risiko
"""

import os
import sys
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, asdict
import argparse

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
║{Colors.YELLOW}  🔍 FORENSIC TOOLKIT v1.0                                   {Colors.CYAN}║
║{Colors.GREEN}     Digital Forensics Investigation Suite                    {Colors.CYAN}║
╚══════════════════════════════════════════════════════════════╝{Colors.RESET}
    """)

@dataclass
class FileHash:
    """File hash information"""
    filepath: str
    filename: str
    size: int
    md5: str
    sha1: str
    sha256: str
    sha512: str
    created: str
    modified: str
    accessed: str

@dataclass
class IOC:
    """Indicator of Compromise"""
    ioc_type: str
    value: str
    description: str
    confidence: str
    source: str
    timestamp: str

class HashVerifier:
    """Hash calculation and verification"""
    
    @staticmethod
    def calculate_file_hash(filepath: str) -> Optional[FileHash]:
        """Calculate all hashes for a file"""
        try:
            path = Path(filepath)
            if not path.exists():
                print(f"{Colors.RED}[!] File not found: {filepath}{Colors.RESET}")
                return None
            
            # Calculate hashes
            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()
            sha512 = hashlib.sha512()
            
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
                    sha512.update(chunk)
            
            stat = path.stat()
            
            return FileHash(
                filepath=str(path.absolute()),
                filename=path.name,
                size=stat.st_size,
                md5=md5.hexdigest(),
                sha1=sha1.hexdigest(),
                sha256=sha256.hexdigest(),
                sha512=sha512.hexdigest(),
                created=datetime.fromtimestamp(stat.st_ctime).isoformat(),
                modified=datetime.fromtimestamp(stat.st_mtime).isoformat(),
                accessed=datetime.fromtimestamp(stat.st_atime).isoformat()
            )
        except Exception as e:
            print(f"{Colors.RED}[!] Error calculating hash: {e}{Colors.RESET}")
            return None
    
    @staticmethod
    def verify_hash(filepath: str, expected_hash: str, hash_type: str = "sha256") -> bool:
        """Verify file hash against expected value"""
        file_hash = HashVerifier.calculate_file_hash(filepath)
        if not file_hash:
            return False
        
        actual_hash = getattr(file_hash, hash_type, None)
        if not actual_hash:
            print(f"{Colors.RED}[!] Invalid hash type: {hash_type}{Colors.RESET}")
            return False
        
        return actual_hash.lower() == expected_hash.lower()
    
    @staticmethod
    def hash_directory(directory: str, output_file: str = None) -> List[FileHash]:
        """Hash all files in a directory"""
        hashes = []
        path = Path(directory)
        
        if not path.exists():
            print(f"{Colors.RED}[!] Directory not found: {directory}{Colors.RESET}")
            return hashes
        
        for filepath in path.rglob('*'):
            if filepath.is_file():
                file_hash = HashVerifier.calculate_file_hash(str(filepath))
                if file_hash:
                    hashes.append(file_hash)
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump([asdict(h) for h in hashes], f, indent=2)
            print(f"{Colors.GREEN}[✓] Hash report saved: {output_file}{Colors.RESET}")
        
        return hashes


class IOCExtractor:
    """Extract Indicators of Compromise from logs and files"""
    
    # Regex patterns for IOC extraction
    PATTERNS = {
        'ipv4': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        'ipv6': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'url': r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*',
        'domain': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
        'md5': r'\b[a-fA-F0-9]{32}\b',
        'sha1': r'\b[a-fA-F0-9]{40}\b',
        'sha256': r'\b[a-fA-F0-9]{64}\b',
        'base64': r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
        'cve': r'CVE-\d{4}-\d{4,}',
        'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
    }
    
    # SQL injection patterns
    SQLI_PATTERNS = [
        r"(?i)'.*?(?:or|and).*?'",
        r"(?i)union\s+select",
        r"(?i)select\s+.*\s+from",
        r"(?i)insert\s+into",
        r"(?i)delete\s+from",
        r"(?i)drop\s+table",
        r"(?i)--\s*$",
        r"(?i)/\*.*?\*/",
        r"(?i)xp_cmdshell",
        r"(?i)waitfor\s+delay",
        r"(?i)benchmark\s*\(",
    ]
    
    # XSS patterns
    XSS_PATTERNS = [
        r"(?i)<script[^>]*>",
        r"(?i)javascript:",
        r"(?i)on\w+\s*=",
        r"(?i)<iframe",
        r"(?i)<object",
        r"(?i)<embed",
    ]
    
    def __init__(self):
        self.iocs: List[IOC] = []
    
    def extract_from_file(self, filepath: str) -> List[IOC]:
        """Extract IOCs from a file"""
        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read()
            return self.extract_from_text(content, source=filepath)
        except Exception as e:
            print(f"{Colors.RED}[!] Error reading file: {e}{Colors.RESET}")
            return []
    
    def extract_from_text(self, text: str, source: str = "unknown") -> List[IOC]:
        """Extract IOCs from text"""
        iocs = []
        timestamp = datetime.now().isoformat()
        
        for ioc_type, pattern in self.PATTERNS.items():
            matches = re.findall(pattern, text)
            for match in set(matches):
                # Filter out common false positives
                if ioc_type == 'ipv4' and match.startswith(('0.0.', '127.0.', '255.255.')):
                    continue
                if ioc_type == 'domain' and match in ['example.com', 'localhost', 'test.com']:
                    continue
                
                iocs.append(IOC(
                    ioc_type=ioc_type,
                    value=match,
                    description=f"Extracted {ioc_type} from {source}",
                    confidence="medium",
                    source=source,
                    timestamp=timestamp
                ))
        
        # Check for SQL injection patterns
        for pattern in self.SQLI_PATTERNS:
            matches = re.findall(pattern, text)
            for match in set(matches):
                iocs.append(IOC(
                    ioc_type="sqli_pattern",
                    value=match[:200],  # Truncate long matches
                    description="Potential SQL injection pattern",
                    confidence="high",
                    source=source,
                    timestamp=timestamp
                ))
        
        # Check for XSS patterns
        for pattern in self.XSS_PATTERNS:
            matches = re.findall(pattern, text)
            for match in set(matches):
                iocs.append(IOC(
                    ioc_type="xss_pattern",
                    value=match[:200],
                    description="Potential XSS pattern",
                    confidence="high",
                    source=source,
                    timestamp=timestamp
                ))
        
        self.iocs.extend(iocs)
        return iocs
    
    def export_iocs(self, output_file: str, format: str = "json"):
        """Export IOCs to file"""
        if format == "json":
            with open(output_file, 'w') as f:
                json.dump([asdict(ioc) for ioc in self.iocs], f, indent=2)
        elif format == "csv":
            with open(output_file, 'w') as f:
                f.write("type,value,description,confidence,source,timestamp\n")
                for ioc in self.iocs:
                    f.write(f'"{ioc.ioc_type}","{ioc.value}","{ioc.description}",'
                           f'"{ioc.confidence}","{ioc.source}","{ioc.timestamp}"\n')
        elif format == "stix":
            stix_bundle = self._to_stix()
            with open(output_file, 'w') as f:
                json.dump(stix_bundle, f, indent=2)
        
        print(f"{Colors.GREEN}[✓] IOCs exported to: {output_file}{Colors.RESET}")
    
    def _to_stix(self) -> Dict:
        """Convert IOCs to STIX format"""
        objects = []
        for ioc in self.iocs:
            if ioc.ioc_type == 'ipv4':
                objects.append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "pattern_type": "stix",
                    "pattern": f"[ipv4-addr:value = '{ioc.value}']",
                    "valid_from": ioc.timestamp,
                    "description": ioc.description
                })
            elif ioc.ioc_type == 'domain':
                objects.append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "pattern_type": "stix",
                    "pattern": f"[domain-name:value = '{ioc.value}']",
                    "valid_from": ioc.timestamp,
                    "description": ioc.description
                })
            elif ioc.ioc_type in ['md5', 'sha1', 'sha256']:
                objects.append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "pattern_type": "stix",
                    "pattern": f"[file:hashes.{ioc.ioc_type.upper()} = '{ioc.value}']",
                    "valid_from": ioc.timestamp,
                    "description": ioc.description
                })
        
        return {
            "type": "bundle",
            "id": f"bundle--forensic-toolkit-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "objects": objects
        }


class LogAnalyzer:
    """Quick log analysis for common patterns"""
    
    APACHE_LOG_PATTERN = re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[(?P<datetime>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<url>\S+) (?P<protocol>\S+)" '
        r'(?P<status>\d+) (?P<size>\S+)'
    )
    
    def __init__(self):
        self.entries = []
        self.suspicious = []
    
    def analyze_apache_log(self, filepath: str) -> Dict[str, Any]:
        """Analyze Apache access log"""
        print(f"{Colors.CYAN}[*] Analyzing Apache log: {filepath}{Colors.RESET}")
        
        stats = {
            'total_requests': 0,
            'unique_ips': set(),
            'status_codes': {},
            'top_urls': {},
            'suspicious_requests': [],
            'potential_attacks': []
        }
        
        try:
            with open(filepath, 'r', errors='ignore') as f:
                for line in f:
                    match = self.APACHE_LOG_PATTERN.match(line)
                    if match:
                        stats['total_requests'] += 1
                        data = match.groupdict()
                        
                        stats['unique_ips'].add(data['ip'])
                        
                        status = data['status']
                        stats['status_codes'][status] = stats['status_codes'].get(status, 0) + 1
                        
                        url = data['url'][:100]
                        stats['top_urls'][url] = stats['top_urls'].get(url, 0) + 1
                        
                        # Check for suspicious patterns
                        if self._is_suspicious(data['url']):
                            stats['suspicious_requests'].append({
                                'ip': data['ip'],
                                'datetime': data['datetime'],
                                'url': data['url'][:200],
                                'status': data['status']
                            })
        except Exception as e:
            print(f"{Colors.RED}[!] Error: {e}{Colors.RESET}")
        
        stats['unique_ips'] = len(stats['unique_ips'])
        stats['top_urls'] = dict(sorted(stats['top_urls'].items(), 
                                        key=lambda x: x[1], reverse=True)[:10])
        
        return stats
    
    def _is_suspicious(self, url: str) -> bool:
        """Check if URL contains suspicious patterns"""
        patterns = [
            'union', 'select', 'insert', 'delete', 'drop',
            '<script', 'javascript:', 'onerror=', 'onload=',
            '../', '..\\', '/etc/passwd', 'cmd.exe',
            'eval(', 'base64_decode', 'exec('
        ]
        url_lower = url.lower()
        return any(p in url_lower for p in patterns)


class ArtifactCollector:
    """Collect forensic artifacts from system"""
    
    LINUX_ARTIFACTS = {
        'auth_logs': ['/var/log/auth.log', '/var/log/secure'],
        'system_logs': ['/var/log/syslog', '/var/log/messages'],
        'apache_logs': ['/var/log/apache2/access.log', '/var/log/httpd/access_log'],
        'mysql_logs': ['/var/log/mysql/mysql.log', '/var/log/mariadb/mariadb.log'],
        'bash_history': ['~/.bash_history', '/root/.bash_history'],
        'cron': ['/etc/crontab', '/var/spool/cron/crontabs/'],
        'passwd': ['/etc/passwd'],
        'shadow': ['/etc/shadow'],
        'hosts': ['/etc/hosts'],
        'sudoers': ['/etc/sudoers'],
        'ssh_config': ['/etc/ssh/sshd_config', '~/.ssh/authorized_keys'],
    }
    
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.collected = []
    
    def collect_artifact(self, filepath: str) -> Optional[Dict]:
        """Collect a single artifact"""
        path = Path(filepath).expanduser()
        
        if not path.exists():
            return None
        
        try:
            # Calculate hash
            file_hash = HashVerifier.calculate_file_hash(str(path))
            
            # Copy to output
            dest = self.output_dir / path.name
            if path.is_file():
                with open(path, 'rb') as src, open(dest, 'wb') as dst:
                    dst.write(src.read())
            
            artifact = {
                'source': str(path),
                'destination': str(dest),
                'collected_at': datetime.now().isoformat(),
                'hash': asdict(file_hash) if file_hash else None
            }
            
            self.collected.append(artifact)
            return artifact
        except PermissionError:
            print(f"{Colors.YELLOW}[!] Permission denied: {filepath}{Colors.RESET}")
            return None
        except Exception as e:
            print(f"{Colors.RED}[!] Error collecting {filepath}: {e}{Colors.RESET}")
            return None
    
    def collect_standard_artifacts(self):
        """Collect standard Linux forensic artifacts"""
        print(f"{Colors.CYAN}[*] Collecting standard forensic artifacts...{Colors.RESET}")
        
        for category, paths in self.LINUX_ARTIFACTS.items():
            print(f"\n{Colors.YELLOW}[*] Collecting {category}...{Colors.RESET}")
            for filepath in paths:
                result = self.collect_artifact(filepath)
                if result:
                    print(f"  {Colors.GREEN}[✓]{Colors.RESET} {filepath}")
        
        # Save collection manifest
        manifest_path = self.output_dir / 'collection_manifest.json'
        with open(manifest_path, 'w') as f:
            json.dump({
                'collection_date': datetime.now().isoformat(),
                'artifacts': self.collected
            }, f, indent=2)
        
        print(f"\n{Colors.GREEN}[✓] Collection complete. Manifest: {manifest_path}{Colors.RESET}")


class ForensicReport:
    """Generate forensic reports"""
    
    def __init__(self, case_name: str, investigator: str):
        self.case_name = case_name
        self.investigator = investigator
        self.created = datetime.now()
        self.findings = []
        self.evidence = []
        self.timeline = []
        self.iocs = []
    
    def add_finding(self, title: str, description: str, severity: str, evidence_ref: str = None):
        """Add a finding to the report"""
        self.findings.append({
            'id': f"F-{len(self.findings)+1:03d}",
            'title': title,
            'description': description,
            'severity': severity,
            'evidence_ref': evidence_ref,
            'timestamp': datetime.now().isoformat()
        })
    
    def add_evidence(self, evidence_id: str, description: str, hash_value: str, location: str):
        """Add evidence to the report"""
        self.evidence.append({
            'id': evidence_id,
            'description': description,
            'hash': hash_value,
            'location': location,
            'collected_at': datetime.now().isoformat()
        })
    
    def add_timeline_event(self, timestamp: str, event: str, source: str):
        """Add event to timeline"""
        self.timeline.append({
            'timestamp': timestamp,
            'event': event,
            'source': source
        })
    
    def generate_html_report(self, output_file: str):
        """Generate HTML report"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Forensic Report - {self.case_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; border-bottom: 2px solid #007bff; }}
        h2 {{ color: #007bff; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #007bff; color: white; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        .critical {{ color: red; font-weight: bold; }}
        .high {{ color: orange; font-weight: bold; }}
        .medium {{ color: #cc0; font-weight: bold; }}
        .low {{ color: green; }}
        .header {{ background-color: #f8f9fa; padding: 20px; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Digital Forensic Investigation Report</h1>
        <p><strong>Case:</strong> {self.case_name}</p>
        <p><strong>Investigator:</strong> {self.investigator}</p>
        <p><strong>Date:</strong> {self.created.strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <h2>Executive Summary</h2>
    <p>Total Findings: {len(self.findings)}</p>
    <p>Evidence Items: {len(self.evidence)}</p>
    <p>Timeline Events: {len(self.timeline)}</p>
    
    <h2>Findings</h2>
    <table>
        <tr><th>ID</th><th>Title</th><th>Severity</th><th>Description</th></tr>
        {"".join(f'<tr><td>{f["id"]}</td><td>{f["title"]}</td><td class="{f["severity"].lower()}">{f["severity"]}</td><td>{f["description"]}</td></tr>' for f in self.findings)}
    </table>
    
    <h2>Evidence</h2>
    <table>
        <tr><th>ID</th><th>Description</th><th>Hash (SHA-256)</th><th>Location</th></tr>
        {"".join(f'<tr><td>{e["id"]}</td><td>{e["description"]}</td><td style="font-family: monospace; font-size: 10px;">{e["hash"][:32]}...</td><td>{e["location"]}</td></tr>' for e in self.evidence)}
    </table>
    
    <h2>Timeline</h2>
    <table>
        <tr><th>Timestamp</th><th>Event</th><th>Source</th></tr>
        {"".join(f'<tr><td>{t["timestamp"]}</td><td>{t["event"]}</td><td>{t["source"]}</td></tr>' for t in self.timeline)}
    </table>
    
    <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666;">
        <p>Generated by Forensic Toolkit v1.0</p>
        <p>Report Classification: CONFIDENTIAL</p>
    </footer>
</body>
</html>"""
        
        with open(output_file, 'w') as f:
            f.write(html)
        
        print(f"{Colors.GREEN}[✓] HTML report generated: {output_file}{Colors.RESET}")
    
    def generate_json_report(self, output_file: str):
        """Generate JSON report"""
        report = {
            'case_info': {
                'name': self.case_name,
                'investigator': self.investigator,
                'created': self.created.isoformat()
            },
            'findings': self.findings,
            'evidence': self.evidence,
            'timeline': self.timeline,
            'iocs': self.iocs
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"{Colors.GREEN}[✓] JSON report generated: {output_file}{Colors.RESET}")


def main():
    banner()
    
    parser = argparse.ArgumentParser(description='Forensic Toolkit - Digital Forensics Suite')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Hash command
    hash_parser = subparsers.add_parser('hash', help='Calculate file hashes')
    hash_parser.add_argument('path', help='File or directory to hash')
    hash_parser.add_argument('-o', '--output', help='Output file for hash report')
    hash_parser.add_argument('-v', '--verify', help='Verify against expected hash')
    
    # IOC command
    ioc_parser = subparsers.add_parser('ioc', help='Extract IOCs from files')
    ioc_parser.add_argument('input', help='Input file or directory')
    ioc_parser.add_argument('-o', '--output', default='iocs.json', help='Output file')
    ioc_parser.add_argument('-f', '--format', choices=['json', 'csv', 'stix'], default='json')
    
    # Log analysis command
    log_parser = subparsers.add_parser('log', help='Analyze log files')
    log_parser.add_argument('logfile', help='Log file to analyze')
    log_parser.add_argument('-t', '--type', choices=['apache', 'auth', 'mysql'], default='apache')
    
    # Collect command
    collect_parser = subparsers.add_parser('collect', help='Collect forensic artifacts')
    collect_parser.add_argument('-o', '--output', default='./artifacts', help='Output directory')
    
    # Report command
    report_parser = subparsers.add_parser('report', help='Generate forensic report')
    report_parser.add_argument('--case', required=True, help='Case name')
    report_parser.add_argument('--investigator', required=True, help='Investigator name')
    report_parser.add_argument('-o', '--output', default='report.html', help='Output file')
    report_parser.add_argument('-f', '--format', choices=['html', 'json'], default='html')
    
    args = parser.parse_args()
    
    if args.command == 'hash':
        path = Path(args.path)
        if path.is_file():
            result = HashVerifier.calculate_file_hash(args.path)
            if result:
                print(f"\n{Colors.CYAN}File:{Colors.RESET} {result.filename}")
                print(f"{Colors.CYAN}Size:{Colors.RESET} {result.size} bytes")
                print(f"{Colors.CYAN}MD5:{Colors.RESET} {result.md5}")
                print(f"{Colors.CYAN}SHA1:{Colors.RESET} {result.sha1}")
                print(f"{Colors.CYAN}SHA256:{Colors.RESET} {result.sha256}")
                print(f"{Colors.CYAN}SHA512:{Colors.RESET} {result.sha512}")
                
                if args.verify:
                    if HashVerifier.verify_hash(args.path, args.verify):
                        print(f"\n{Colors.GREEN}[✓] Hash verification: PASSED{Colors.RESET}")
                    else:
                        print(f"\n{Colors.RED}[✗] Hash verification: FAILED{Colors.RESET}")
        elif path.is_dir():
            hashes = HashVerifier.hash_directory(args.path, args.output)
            print(f"\n{Colors.GREEN}[✓] Hashed {len(hashes)} files{Colors.RESET}")
    
    elif args.command == 'ioc':
        extractor = IOCExtractor()
        path = Path(args.input)
        
        if path.is_file():
            iocs = extractor.extract_from_file(args.input)
        elif path.is_dir():
            for filepath in path.rglob('*'):
                if filepath.is_file():
                    extractor.extract_from_file(str(filepath))
        
        print(f"\n{Colors.CYAN}[*] Found {len(extractor.iocs)} IOCs{Colors.RESET}")
        
        # Print summary by type
        ioc_types = {}
        for ioc in extractor.iocs:
            ioc_types[ioc.ioc_type] = ioc_types.get(ioc.ioc_type, 0) + 1
        
        for ioc_type, count in sorted(ioc_types.items(), key=lambda x: x[1], reverse=True):
            print(f"  - {ioc_type}: {count}")
        
        extractor.export_iocs(args.output, args.format)
    
    elif args.command == 'log':
        analyzer = LogAnalyzer()
        if args.type == 'apache':
            stats = analyzer.analyze_apache_log(args.logfile)
            
            print(f"\n{Colors.BOLD}Log Analysis Results:{Colors.RESET}")
            print(f"  Total Requests: {stats['total_requests']}")
            print(f"  Unique IPs: {stats['unique_ips']}")
            print(f"  Suspicious Requests: {len(stats['suspicious_requests'])}")
            
            print(f"\n{Colors.YELLOW}Status Codes:{Colors.RESET}")
            for code, count in sorted(stats['status_codes'].items()):
                print(f"  {code}: {count}")
            
            if stats['suspicious_requests']:
                print(f"\n{Colors.RED}Suspicious Requests:{Colors.RESET}")
                for req in stats['suspicious_requests'][:10]:
                    print(f"  [{req['datetime']}] {req['ip']} - {req['url'][:80]}")
    
    elif args.command == 'collect':
        collector = ArtifactCollector(args.output)
        collector.collect_standard_artifacts()
    
    elif args.command == 'report':
        report = ForensicReport(args.case, args.investigator)
        
        # Add sample findings for demonstration
        report.add_finding(
            "SQL Injection Vulnerability",
            "Critical SQL injection vulnerability found in login.php",
            "CRITICAL",
            "EVD-001"
        )
        report.add_finding(
            "Weak Password Storage",
            "Passwords stored using MD5 without salt",
            "HIGH",
            "EVD-002"
        )
        
        # Add sample evidence
        report.add_evidence(
            "EVD-001",
            "Web server access log",
            "abc123def456...",
            "/var/log/apache2/access.log"
        )
        
        # Add timeline
        report.add_timeline_event(
            "2024-01-15T02:15:33",
            "First reconnaissance attempt detected",
            "Apache access log"
        )
        report.add_timeline_event(
            "2024-01-15T02:45:22",
            "SQL injection attack successful",
            "MySQL query log"
        )
        
        if args.format == 'html':
            report.generate_html_report(args.output)
        else:
            report.generate_json_report(args.output)
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
