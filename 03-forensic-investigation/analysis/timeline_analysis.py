#!/usr/bin/env python3
"""
Timeline Analysis Tool untuk Forensik Digital
Membuat timeline kronologis dari berbagai sumber bukti

Materi: CPMK-6 - Forensik Digital & Manajemen Risiko
Prinsip: Comprehensive Analysis - Timeline Reconstruction
"""

import os
import sys
import json
import hashlib
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
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
║{Colors.YELLOW}  ⏱️  FORENSIC TIMELINE ANALYZER                              {Colors.CYAN}║
║{Colors.GREEN}     Reconstructing Attack Chronology                         {Colors.CYAN}║
╚══════════════════════════════════════════════════════════════╝{Colors.RESET}
    """)

class EventType(Enum):
    """Jenis-jenis event dalam timeline forensik"""
    NETWORK_ACCESS = "network_access"
    AUTHENTICATION = "authentication"
    FILE_ACCESS = "file_access"
    FILE_MODIFICATION = "file_modification"
    PROCESS_EXECUTION = "process_execution"
    DATA_EXFILTRATION = "data_exfiltration"
    MALWARE_ACTIVITY = "malware_activity"
    SYSTEM_CHANGE = "system_change"
    DATABASE_QUERY = "database_query"
    USER_ACTION = "user_action"

class Severity(Enum):
    """Tingkat keparahan event"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class TimelineEvent:
    """Representasi single event dalam timeline"""
    timestamp: str
    event_type: str
    source: str
    description: str
    severity: str
    details: Dict[str, Any]
    evidence_reference: str = ""
    
    def to_dict(self) -> Dict:
        return asdict(self)

class TimelineAnalyzer:
    """
    Forensic Timeline Analyzer
    Menggabungkan dan menganalisis event dari berbagai sumber
    """
    
    def __init__(self, case_id: str):
        self.case_id = case_id
        self.events: List[TimelineEvent] = []
        self.analysis_start = datetime.now()
        
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
    
    def add_event(self, event: TimelineEvent):
        """Tambahkan event ke timeline"""
        self.events.append(event)
    
    def parse_apache_timestamp(self, ts_str: str) -> Optional[datetime]:
        """Parse Apache log timestamp format"""
        try:
            # Format: 18/Dec/2025:10:15:23 +0700
            return datetime.strptime(ts_str.split()[0], "%d/%b/%Y:%H:%M:%S")
        except:
            return None
    
    def import_from_log_analysis(self, log_analysis_file: str):
        """Import events dari hasil log analysis"""
        self.log(f"[*] Importing from log analysis: {log_analysis_file}", "info")
        
        try:
            with open(log_analysis_file, 'r') as f:
                data = json.load(f)
            
            for attack in data.get("attack_attempts", []):
                event = TimelineEvent(
                    timestamp=attack.get("timestamp", "Unknown"),
                    event_type=EventType.NETWORK_ACCESS.value,
                    source="Apache Access Log",
                    description=f"{attack.get('type', 'Unknown')} attack detected",
                    severity=attack.get("severity", "medium").lower(),
                    details={
                        "ip": attack.get("ip"),
                        "url": attack.get("url"),
                        "pattern": attack.get("pattern")
                    },
                    evidence_reference=attack.get("log_file", "")
                )
                self.add_event(event)
            
            self.log(f"[✓] Imported {len(data.get('attack_attempts', []))} events", "success")
        except Exception as e:
            self.log(f"[!] Error importing log analysis: {e}", "error")
    
    def import_from_attack_log(self, attack_log_file: str):
        """Import events dari attack simulation log"""
        self.log(f"[*] Importing from attack log: {attack_log_file}", "info")
        
        try:
            with open(attack_log_file, 'r') as f:
                data = json.load(f)
            
            for log_entry in data.get("attack_log", []):
                severity = "high" if log_entry.get("level") == "attack" else "medium"
                
                event = TimelineEvent(
                    timestamp=log_entry.get("timestamp", ""),
                    event_type=EventType.MALWARE_ACTIVITY.value,
                    source="Attack Simulation Log",
                    description=log_entry.get("message", ""),
                    severity=severity,
                    details=log_entry,
                    evidence_reference=attack_log_file
                )
                self.add_event(event)
            
            self.log(f"[✓] Imported {len(data.get('attack_log', []))} events", "success")
        except Exception as e:
            self.log(f"[!] Error importing attack log: {e}", "error")
    
    def create_simulated_timeline(self):
        """
        Create simulated timeline untuk demonstrasi
        Berdasarkan skenario: Data breach di PT. TechMart Indonesia
        """
        self.log("[*] Creating simulated attack timeline...", "info")
        
        # Base time: hari ini jam 10:00
        base_time = datetime.now().replace(hour=10, minute=0, second=0, microsecond=0)
        
        simulated_events = [
            # Fase 1: Reconnaissance
            {
                "offset_minutes": 0,
                "type": EventType.NETWORK_ACCESS.value,
                "source": "Firewall Log",
                "description": "Port scan detected from external IP 203.0.113.50",
                "severity": Severity.MEDIUM.value,
                "details": {"src_ip": "203.0.113.50", "ports_scanned": "21,22,80,443,3306,8080"}
            },
            {
                "offset_minutes": 5,
                "type": EventType.NETWORK_ACCESS.value,
                "source": "Apache Access Log",
                "description": "Directory enumeration attempt (gobuster)",
                "severity": Severity.MEDIUM.value,
                "details": {"src_ip": "203.0.113.50", "user_agent": "gobuster/3.1.0", "requests": 1247}
            },
            {
                "offset_minutes": 10,
                "type": EventType.NETWORK_ACCESS.value,
                "source": "Apache Access Log",
                "description": "Nikto vulnerability scanner detected",
                "severity": Severity.MEDIUM.value,
                "details": {"src_ip": "203.0.113.50", "user_agent": "Nikto/2.1.6"}
            },
            
            # Fase 2: Initial Access - SQL Injection
            {
                "offset_minutes": 15,
                "type": EventType.AUTHENTICATION.value,
                "source": "Apache Access Log",
                "description": "SQL Injection attempt on login page",
                "severity": Severity.HIGH.value,
                "details": {"src_ip": "203.0.113.50", "payload": "' OR '1'='1", "url": "/login.php"}
            },
            {
                "offset_minutes": 15,
                "type": EventType.DATABASE_QUERY.value,
                "source": "MySQL Query Log",
                "description": "Malicious SQL query executed",
                "severity": Severity.CRITICAL.value,
                "details": {"query": "SELECT * FROM users WHERE username='' OR '1'='1' AND password=MD5('x')"}
            },
            {
                "offset_minutes": 16,
                "type": EventType.AUTHENTICATION.value,
                "source": "Application Log",
                "description": "Successful login bypass - admin session created",
                "severity": Severity.CRITICAL.value,
                "details": {"src_ip": "203.0.113.50", "user": "admin", "method": "SQL Injection"}
            },
            
            # Fase 3: Discovery & Data Access
            {
                "offset_minutes": 18,
                "type": EventType.FILE_ACCESS.value,
                "source": "Apache Access Log",
                "description": "Dashboard page accessed",
                "severity": Severity.INFO.value,
                "details": {"src_ip": "203.0.113.50", "url": "/dashboard.php", "session_id": "abc123xyz"}
            },
            {
                "offset_minutes": 20,
                "type": EventType.DATABASE_QUERY.value,
                "source": "MySQL Query Log",
                "description": "Customer table enumeration via UNION injection",
                "severity": Severity.HIGH.value,
                "details": {"query": "UNION SELECT NULL,table_name,NULL FROM information_schema.tables"}
            },
            {
                "offset_minutes": 22,
                "type": EventType.FILE_ACCESS.value,
                "source": "Apache Access Log",
                "description": "Customer data page accessed",
                "severity": Severity.HIGH.value,
                "details": {"src_ip": "203.0.113.50", "url": "/customers.php", "response_size": 98765}
            },
            
            # Fase 4: Data Exfiltration
            {
                "offset_minutes": 25,
                "type": EventType.DATA_EXFILTRATION.value,
                "source": "Apache Access Log",
                "description": "Bulk data export initiated",
                "severity": Severity.CRITICAL.value,
                "details": {"src_ip": "203.0.113.50", "url": "/export.php", "data_size": "2.3MB"}
            },
            {
                "offset_minutes": 25,
                "type": EventType.DATABASE_QUERY.value,
                "source": "MySQL Audit Log",
                "description": "Full customer table dump executed",
                "severity": Severity.CRITICAL.value,
                "details": {"query": "SELECT * FROM customers", "rows_returned": 50000}
            },
            {
                "offset_minutes": 26,
                "type": EventType.DATA_EXFILTRATION.value,
                "source": "Network Monitor",
                "description": "Large data transfer to external IP detected",
                "severity": Severity.CRITICAL.value,
                "details": {"dst_ip": "203.0.113.50", "data_transferred": "2.3MB", "protocol": "HTTP"}
            },
            
            # Fase 5: Persistence & Cleanup
            {
                "offset_minutes": 30,
                "type": EventType.FILE_MODIFICATION.value,
                "source": "File Integrity Monitor",
                "description": "New PHP file created in hidden directory",
                "severity": Severity.CRITICAL.value,
                "details": {"file": "/var/www/techmart/.hidden/shell.php", "action": "created"}
            },
            {
                "offset_minutes": 31,
                "type": EventType.MALWARE_ACTIVITY.value,
                "source": "Apache Access Log",
                "description": "Webshell access attempt",
                "severity": Severity.CRITICAL.value,
                "details": {"src_ip": "203.0.113.50", "url": "/.hidden/shell.php?cmd=id"}
            },
            {
                "offset_minutes": 35,
                "type": EventType.PROCESS_EXECUTION.value,
                "source": "Linux Audit Log",
                "description": "Suspicious command execution via web server",
                "severity": Severity.CRITICAL.value,
                "details": {"command": "whoami", "user": "www-data", "parent": "apache2"}
            },
            {
                "offset_minutes": 40,
                "type": EventType.AUTHENTICATION.value,
                "source": "Application Log",
                "description": "Session logout - attacker covering tracks",
                "severity": Severity.MEDIUM.value,
                "details": {"src_ip": "203.0.113.50", "session_id": "abc123xyz"}
            },
        ]
        
        for event_data in simulated_events:
            event_time = base_time + timedelta(minutes=event_data["offset_minutes"])
            
            event = TimelineEvent(
                timestamp=event_time.isoformat(),
                event_type=event_data["type"],
                source=event_data["source"],
                description=event_data["description"],
                severity=event_data["severity"],
                details=event_data["details"],
                evidence_reference=f"Simulated Event #{len(self.events) + 1}"
            )
            self.add_event(event)
        
        self.log(f"[✓] Created {len(simulated_events)} simulated events", "success")
    
    def sort_timeline(self):
        """Sort events by timestamp"""
        self.events.sort(key=lambda e: e.timestamp)
    
    def filter_by_severity(self, min_severity: str) -> List[TimelineEvent]:
        """Filter events by minimum severity"""
        severity_order = ["info", "low", "medium", "high", "critical"]
        min_index = severity_order.index(min_severity.lower())
        
        return [e for e in self.events 
                if severity_order.index(e.severity.lower()) >= min_index]
    
    def filter_by_type(self, event_type: str) -> List[TimelineEvent]:
        """Filter events by type"""
        return [e for e in self.events if e.event_type == event_type]
    
    def identify_attack_phases(self) -> Dict[str, List[TimelineEvent]]:
        """
        Identify attack phases using MITRE ATT&CK framework concepts
        """
        phases = {
            "Reconnaissance": [],
            "Initial Access": [],
            "Execution": [],
            "Persistence": [],
            "Discovery": [],
            "Collection": [],
            "Exfiltration": [],
            "Impact": []
        }
        
        for event in self.events:
            # Classify based on event type and description
            desc_lower = event.description.lower()
            
            if any(x in desc_lower for x in ["scan", "enumeration", "nikto", "gobuster"]):
                phases["Reconnaissance"].append(event)
            elif any(x in desc_lower for x in ["injection", "bypass", "login"]):
                phases["Initial Access"].append(event)
            elif event.event_type == EventType.PROCESS_EXECUTION.value:
                phases["Execution"].append(event)
            elif any(x in desc_lower for x in ["webshell", "backdoor", "persistence"]):
                phases["Persistence"].append(event)
            elif any(x in desc_lower for x in ["dashboard", "accessed", "enumeration"]):
                phases["Discovery"].append(event)
            elif any(x in desc_lower for x in ["customer", "data", "dump"]):
                phases["Collection"].append(event)
            elif event.event_type == EventType.DATA_EXFILTRATION.value:
                phases["Exfiltration"].append(event)
        
        return phases
    
    def generate_report(self, output_file: str = None) -> Dict:
        """Generate timeline analysis report"""
        self.log("\n[*] Generating timeline report...", "info")
        
        self.sort_timeline()
        
        # Identify attack phases
        phases = self.identify_attack_phases()
        
        # Calculate statistics
        severity_counts = {}
        type_counts = {}
        source_counts = {}
        
        for event in self.events:
            severity_counts[event.severity] = severity_counts.get(event.severity, 0) + 1
            type_counts[event.event_type] = type_counts.get(event.event_type, 0) + 1
            source_counts[event.source] = source_counts.get(event.source, 0) + 1
        
        # Build report
        report = {
            "case_id": self.case_id,
            "analysis_timestamp": datetime.now().isoformat(),
            "analysis_duration": str(datetime.now() - self.analysis_start),
            "summary": {
                "total_events": len(self.events),
                "time_span": {
                    "first_event": self.events[0].timestamp if self.events else None,
                    "last_event": self.events[-1].timestamp if self.events else None
                },
                "severity_distribution": severity_counts,
                "event_type_distribution": type_counts,
                "source_distribution": source_counts
            },
            "attack_phases": {
                phase: {
                    "event_count": len(events),
                    "first_event": events[0].timestamp if events else None,
                    "events": [e.to_dict() for e in events]
                }
                for phase, events in phases.items()
            },
            "timeline": [e.to_dict() for e in self.events],
            "critical_events": [e.to_dict() for e in self.filter_by_severity("critical")],
            "indicators_of_compromise": self._extract_iocs()
        }
        
        # Calculate report hash
        report_json = json.dumps(report, indent=2, default=str)
        report["report_hash"] = hashlib.sha256(report_json.encode()).hexdigest()
        
        # Save report
        if not output_file:
            output_file = f"timeline_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        self.log(f"[✓] Report saved: {output_file}", "success")
        
        # Print visual timeline
        self._print_visual_timeline(phases)
        
        return report
    
    def _extract_iocs(self) -> Dict[str, List[str]]:
        """Extract Indicators of Compromise from timeline"""
        iocs = {
            "ip_addresses": set(),
            "urls": set(),
            "files": set(),
            "user_agents": set(),
            "queries": set()
        }
        
        for event in self.events:
            details = event.details
            
            if "src_ip" in details:
                iocs["ip_addresses"].add(details["src_ip"])
            if "dst_ip" in details:
                iocs["ip_addresses"].add(details["dst_ip"])
            if "url" in details:
                iocs["urls"].add(details["url"])
            if "file" in details:
                iocs["files"].add(details["file"])
            if "user_agent" in details:
                iocs["user_agents"].add(details["user_agent"])
            if "query" in details:
                iocs["queries"].add(details["query"][:100])
        
        return {k: list(v) for k, v in iocs.items()}
    
    def _print_visual_timeline(self, phases: Dict):
        """Print visual representation of timeline"""
        print(f"""
{Colors.BOLD}═══════════════════════════════════════════════════════════════
                    ATTACK TIMELINE VISUALIZATION
═══════════════════════════════════════════════════════════════{Colors.RESET}
        """)
        
        # Print attack phases
        print(f"{Colors.CYAN}Attack Phases (MITRE ATT&CK):{Colors.RESET}\n")
        
        phase_icons = {
            "Reconnaissance": "🔍",
            "Initial Access": "🚪",
            "Execution": "⚡",
            "Persistence": "🔄",
            "Discovery": "🗺️",
            "Collection": "📦",
            "Exfiltration": "📤",
            "Impact": "💥"
        }
        
        for phase, events in phases.items():
            if events:
                icon = phase_icons.get(phase, "•")
                first_time = events[0].timestamp.split("T")[1][:8] if "T" in events[0].timestamp else events[0].timestamp
                print(f"  {icon} {phase}")
                print(f"     └─ {len(events)} events (first: {first_time})")
        
        print(f"""
{Colors.YELLOW}Severity Distribution:{Colors.RESET}
""")
        severity_colors = {
            "critical": Colors.RED,
            "high": Colors.PURPLE,
            "medium": Colors.YELLOW,
            "low": Colors.CYAN,
            "info": Colors.GREEN
        }
        
        severity_counts = {}
        for event in self.events:
            severity_counts[event.severity] = severity_counts.get(event.severity, 0) + 1
        
        for severity, count in sorted(severity_counts.items(), 
                                      key=lambda x: ["critical", "high", "medium", "low", "info"].index(x[0])):
            color = severity_colors.get(severity, Colors.RESET)
            bar = "█" * min(count, 30)
            print(f"  {color}{severity.upper():10} {bar} {count}{Colors.RESET}")
        
        # Print critical events
        critical_events = self.filter_by_severity("critical")
        if critical_events:
            print(f"""
{Colors.RED}Critical Events:{Colors.RESET}
""")
            for i, event in enumerate(critical_events[:5], 1):
                time_str = event.timestamp.split("T")[1][:8] if "T" in event.timestamp else event.timestamp
                print(f"  {i}. [{time_str}] {event.description[:60]}...")
        
        print(f"""
{Colors.BOLD}═══════════════════════════════════════════════════════════════{Colors.RESET}
        """)


def main():
    banner()
    
    case_id = sys.argv[1] if len(sys.argv) > 1 else f"CASE_{datetime.now().strftime('%Y%m%d')}"
    
    print(f"{Colors.BOLD}Case ID: {case_id}{Colors.RESET}\n")
    
    analyzer = TimelineAnalyzer(case_id)
    
    # Check for existing log analysis files
    log_analysis_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    if log_analysis_file and os.path.exists(log_analysis_file):
        analyzer.import_from_log_analysis(log_analysis_file)
    else:
        # Create simulated timeline for demonstration
        print(f"{Colors.YELLOW}[*] Creating simulated timeline for demonstration...{Colors.RESET}\n")
        analyzer.create_simulated_timeline()
    
    # Generate report
    report = analyzer.generate_report()
    
    print(f"""
{Colors.CYAN}Timeline Analysis Complete!{Colors.RESET}

{Colors.GREEN}Key Findings:{Colors.RESET}
• Total Events: {report['summary']['total_events']}
• Critical Events: {len(report['critical_events'])}
• Attack Duration: {report['summary']['time_span']['first_event']} to {report['summary']['time_span']['last_event']}

{Colors.YELLOW}Indicators of Compromise:{Colors.RESET}
• IP Addresses: {len(report['indicators_of_compromise']['ip_addresses'])}
• Suspicious URLs: {len(report['indicators_of_compromise']['urls'])}
• Malicious Files: {len(report['indicators_of_compromise']['files'])}

{Colors.CYAN}Next Steps:{Colors.RESET}
1. Review critical events in detail
2. Correlate IOCs with threat intelligence
3. Document attack chain for incident report
4. Prepare evidence for legal proceedings
    """)


if __name__ == "__main__":
    main()
