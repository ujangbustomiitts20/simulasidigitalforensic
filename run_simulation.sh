#!/bin/bash
# ============================================
# Run Simulation Script
# PT. TechMart Indonesia - Digital Forensics Lab
# ============================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  🔍 SIMULASI FORENSIK DIGITAL - PT. TechMart Indonesia       ║"
echo "║     Setup & Run Script                                        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check Docker
check_docker() {
    echo -e "${YELLOW}[*] Checking Docker installation...${NC}"
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}[!] Docker is not installed. Please install Docker first.${NC}"
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        echo -e "${RED}[!] Docker Compose is not installed. Please install Docker Compose first.${NC}"
        exit 1
    fi
    echo -e "${GREEN}[✓] Docker is installed${NC}"
}

# Start environment
start_environment() {
    echo -e "${YELLOW}[*] Starting Docker environment...${NC}"
    cd "$(dirname "$0")/01-setup-environment"
    
    # Use docker compose (new) or docker-compose (legacy)
    if docker compose version &> /dev/null; then
        docker compose up -d --build
    else
        docker-compose up -d --build
    fi
    
    echo -e "${GREEN}[✓] Environment started${NC}"
    echo ""
    echo -e "${BLUE}Services:${NC}"
    echo "  - Victim Web: http://localhost:8080"
    echo "  - MySQL: localhost:3307"
    echo "  - Kibana (ELK): http://localhost:5601"
    echo ""
}

# Stop environment
stop_environment() {
    echo -e "${YELLOW}[*] Stopping Docker environment...${NC}"
    cd "$(dirname "$0")/01-setup-environment"
    
    if docker compose version &> /dev/null; then
        docker compose down
    else
        docker-compose down
    fi
    
    echo -e "${GREEN}[✓] Environment stopped${NC}"
}

# Wait for services
wait_for_services() {
    echo -e "${YELLOW}[*] Waiting for services to be ready...${NC}"
    
    # Wait for web server
    echo -n "  Waiting for web server"
    for i in {1..30}; do
        if curl -s http://localhost:8080 > /dev/null 2>&1; then
            echo -e " ${GREEN}[Ready]${NC}"
            break
        fi
        echo -n "."
        sleep 2
    done
    
    # Wait for MySQL
    echo -n "  Waiting for MySQL"
    for i in {1..30}; do
        if docker exec forensik-victim-db mysqladmin ping -h localhost -u root -prootpassword123 > /dev/null 2>&1; then
            echo -e " ${GREEN}[Ready]${NC}"
            break
        fi
        echo -n "."
        sleep 2
    done
    
    echo -e "${GREEN}[✓] All services ready${NC}"
}

# Run attack simulation
run_attack_simulation() {
    echo -e "${YELLOW}[*] Running attack simulation...${NC}"
    echo -e "${RED}[!] WARNING: This is for educational purposes only!${NC}"
    echo ""
    
    cd "$(dirname "$0")"
    
    # Install Python dependencies if needed
    if [ -f "06-tools/requirements.txt" ]; then
        pip3 install -q -r 06-tools/requirements.txt 2>/dev/null || true
    fi
    
    # Run attack scripts
    echo -e "${BLUE}[1/4] Running Reconnaissance...${NC}"
    python3 02-attack-simulation/attack_scripts/reconnaissance.py http://localhost:8080 2>/dev/null || echo "  Skipped (run manually)"
    
    echo -e "${BLUE}[2/4] Running SQL Injection...${NC}"
    python3 02-attack-simulation/attack_scripts/sql_injection.py http://localhost:8080 2>/dev/null || echo "  Skipped (run manually)"
    
    echo -e "${BLUE}[3/4] Running Data Exfiltration...${NC}"
    python3 02-attack-simulation/attack_scripts/data_exfiltration.py http://localhost:8080 2>/dev/null || echo "  Skipped (run manually)"
    
    echo -e "${GREEN}[✓] Attack simulation complete${NC}"
}

# Run forensic analysis
run_forensic_analysis() {
    echo -e "${YELLOW}[*] Running forensic analysis...${NC}"
    
    cd "$(dirname "$0")"
    
    echo -e "${BLUE}[1/3] Running Log Analysis...${NC}"
    python3 03-forensic-investigation/analysis/log_analyzer.py 2>/dev/null || echo "  Run manually with: python3 03-forensic-investigation/analysis/log_analyzer.py"
    
    echo -e "${BLUE}[2/3] Running Timeline Analysis...${NC}"
    python3 03-forensic-investigation/analysis/timeline_analysis.py 2>/dev/null || echo "  Run manually with: python3 03-forensic-investigation/analysis/timeline_analysis.py"
    
    echo -e "${BLUE}[3/3] Running Risk Assessment...${NC}"
    python3 04-risk-management/risk_assessment.py 2>/dev/null || echo "  Run manually with: python3 04-risk-management/risk_assessment.py"
    
    echo -e "${GREEN}[✓] Forensic analysis complete${NC}"
}

# Show help
show_help() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  start       Start the Docker environment"
    echo "  stop        Stop the Docker environment"
    echo "  restart     Restart the Docker environment"
    echo "  status      Show status of containers"
    echo "  attack      Run attack simulation scripts"
    echo "  forensic    Run forensic analysis scripts"
    echo "  full        Run full simulation (start + attack + forensic)"
    echo "  logs        Show container logs"
    echo "  shell       Open shell in attacker container"
    echo "  help        Show this help message"
    echo ""
}

# Show status
show_status() {
    echo -e "${YELLOW}[*] Container Status:${NC}"
    docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "forensik|NAMES"
}

# Show logs
show_logs() {
    cd "$(dirname "$0")/01-setup-environment"
    if docker compose version &> /dev/null; then
        docker compose logs -f --tail=50
    else
        docker-compose logs -f --tail=50
    fi
}

# Open shell in attacker container
attacker_shell() {
    echo -e "${YELLOW}[*] Opening shell in attacker container...${NC}"
    docker exec -it forensik-attacker /bin/bash
}

# Main
case "${1:-help}" in
    start)
        check_docker
        start_environment
        wait_for_services
        ;;
    stop)
        stop_environment
        ;;
    restart)
        stop_environment
        start_environment
        wait_for_services
        ;;
    status)
        show_status
        ;;
    attack)
        run_attack_simulation
        ;;
    forensic)
        run_forensic_analysis
        ;;
    full)
        check_docker
        start_environment
        wait_for_services
        sleep 5
        run_attack_simulation
        run_forensic_analysis
        ;;
    logs)
        show_logs
        ;;
    shell)
        attacker_shell
        ;;
    help|*)
        show_help
        ;;
esac
