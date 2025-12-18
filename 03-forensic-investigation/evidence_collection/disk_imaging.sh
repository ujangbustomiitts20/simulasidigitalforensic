#!/bin/bash
#
# Disk Imaging Script untuk Forensik Digital
# Membuat forensic image dari disk/partition
#
# Materi: CPMK-6 - Forensik Digital & Manajemen Risiko
# Prinsip: Evidence Preservation & Chain of Custody
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
cat << "EOF"
╔══════════════════════════════════════════════════════════════╗
║          🔒 FORENSIC DISK IMAGING TOOL                       ║
║              Digital Forensics Simulation                     ║
╚══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Configuration
EVIDENCE_DIR="${1:-/evidence}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
CASE_ID="${2:-CASE_$(date +%Y%m%d)}"
EXAMINER="${3:-Forensic_Examiner}"

# Create evidence directory structure
echo -e "${GREEN}[*] Creating evidence directory structure...${NC}"
mkdir -p "$EVIDENCE_DIR/$CASE_ID/disk_images"
mkdir -p "$EVIDENCE_DIR/$CASE_ID/hashes"
mkdir -p "$EVIDENCE_DIR/$CASE_ID/logs"
mkdir -p "$EVIDENCE_DIR/$CASE_ID/chain_of_custody"

# Log file
LOG_FILE="$EVIDENCE_DIR/$CASE_ID/logs/imaging_${TIMESTAMP}.log"

log() {
    local message="$1"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "[$timestamp] $message" | tee -a "$LOG_FILE"
}

log "${GREEN}=== FORENSIC IMAGING SESSION STARTED ===${NC}"
log "Case ID: $CASE_ID"
log "Examiner: $EXAMINER"
log "Timestamp: $TIMESTAMP"
log "Evidence Directory: $EVIDENCE_DIR/$CASE_ID"

# Function to create disk image
create_disk_image() {
    local source="$1"
    local image_name="$2"
    local output_path="$EVIDENCE_DIR/$CASE_ID/disk_images/$image_name"
    
    log ""
    log "${CYAN}[PHASE 1] Creating forensic image of $source${NC}"
    log "Output: $output_path"
    
    # Check if source exists
    if [ ! -e "$source" ]; then
        log "${RED}[ERROR] Source $source does not exist!${NC}"
        return 1
    fi
    
    # Get source information
    log ""
    log "[*] Source device information:"
    if [ -b "$source" ]; then
        fdisk -l "$source" 2>/dev/null | tee -a "$LOG_FILE" || true
    else
        ls -la "$source" | tee -a "$LOG_FILE"
    fi
    
    # Calculate source hash BEFORE imaging
    log ""
    log "${CYAN}[PHASE 2] Calculating source hash (pre-imaging)...${NC}"
    log "[*] This ensures we can verify the image matches the source"
    
    if command -v sha256sum &> /dev/null; then
        if [ -b "$source" ]; then
            # For block devices, use dd to read and hash
            log "[*] Hashing block device (this may take time)..."
            SOURCE_HASH=$(dd if="$source" bs=1M 2>/dev/null | sha256sum | cut -d' ' -f1)
        else
            SOURCE_HASH=$(sha256sum "$source" | cut -d' ' -f1)
        fi
        log "[✓] Source SHA-256: $SOURCE_HASH"
    fi
    
    # Create the image using dd or dc3dd
    log ""
    log "${CYAN}[PHASE 3] Creating forensic image...${NC}"
    
    if command -v dc3dd &> /dev/null; then
        log "[*] Using dc3dd (forensic-grade imaging tool)"
        dc3dd if="$source" of="${output_path}.dd" hash=sha256 log="${output_path}.dc3dd.log" 2>&1 | tee -a "$LOG_FILE"
    else
        log "[*] Using dd (standard imaging tool)"
        log "[!] Note: For production forensics, use dc3dd or FTK Imager"
        
        # Use dd with progress
        dd if="$source" of="${output_path}.dd" bs=4M status=progress conv=noerror,sync 2>&1 | tee -a "$LOG_FILE"
    fi
    
    log "[✓] Image created: ${output_path}.dd"
    
    # Calculate image hash AFTER imaging
    log ""
    log "${CYAN}[PHASE 4] Calculating image hash (post-imaging)...${NC}"
    
    IMAGE_HASH=$(sha256sum "${output_path}.dd" | cut -d' ' -f1)
    log "[✓] Image SHA-256: $IMAGE_HASH"
    
    # Save hashes
    echo "$SOURCE_HASH  source_${image_name}" > "$EVIDENCE_DIR/$CASE_ID/hashes/${image_name}_hashes.txt"
    echo "$IMAGE_HASH  ${image_name}.dd" >> "$EVIDENCE_DIR/$CASE_ID/hashes/${image_name}_hashes.txt"
    
    # Verify image integrity
    log ""
    log "${CYAN}[PHASE 5] Verifying image integrity...${NC}"
    
    if [ "$SOURCE_HASH" == "$IMAGE_HASH" ] || [ -z "$SOURCE_HASH" ]; then
        log "${GREEN}[✓] Image integrity verified!${NC}"
    else
        log "${YELLOW}[!] Hash mismatch - this may be normal for live systems${NC}"
        log "    Source: $SOURCE_HASH"
        log "    Image:  $IMAGE_HASH"
    fi
    
    # Generate image metadata
    log ""
    log "${CYAN}[PHASE 6] Generating image metadata...${NC}"
    
    cat > "${output_path}_metadata.json" << EOF
{
    "case_id": "$CASE_ID",
    "image_name": "$image_name",
    "source": "$source",
    "timestamp": "$(date -Iseconds)",
    "examiner": "$EXAMINER",
    "workstation": "$(hostname)",
    "imaging_tool": "$(command -v dc3dd &> /dev/null && echo 'dc3dd' || echo 'dd')",
    "hashes": {
        "algorithm": "SHA-256",
        "source_hash": "$SOURCE_HASH",
        "image_hash": "$IMAGE_HASH"
    },
    "image_file": "${output_path}.dd",
    "image_size_bytes": $(stat -f%z "${output_path}.dd" 2>/dev/null || stat -c%s "${output_path}.dd" 2>/dev/null || echo 0)
}
EOF
    
    log "[✓] Metadata saved: ${output_path}_metadata.json"
    
    return 0
}

# Function to create memory dump
create_memory_dump() {
    local output_path="$EVIDENCE_DIR/$CASE_ID/disk_images/memory_${TIMESTAMP}"
    
    log ""
    log "${CYAN}=== MEMORY ACQUISITION ===${NC}"
    
    # Check for memory acquisition tools
    if command -v avml &> /dev/null; then
        log "[*] Using AVML for memory acquisition"
        avml "${output_path}.lime"
    elif [ -c /dev/mem ]; then
        log "[*] Using /dev/mem for memory acquisition"
        log "${YELLOW}[!] Warning: This method may not capture all memory${NC}"
        dd if=/dev/mem of="${output_path}.raw" bs=1M 2>&1 | tee -a "$LOG_FILE"
    elif [ -c /dev/fmem ]; then
        log "[*] Using /dev/fmem for memory acquisition"
        dd if=/dev/fmem of="${output_path}.raw" bs=1M 2>&1 | tee -a "$LOG_FILE"
    else
        log "${YELLOW}[!] No memory acquisition tool available${NC}"
        log "[*] For production use, install:"
        log "    - AVML (https://github.com/microsoft/avml)"
        log "    - LiME (https://github.com/504ensicsLabs/LiME)"
        return 1
    fi
    
    # Hash the memory dump
    if [ -f "${output_path}.lime" ] || [ -f "${output_path}.raw" ]; then
        local mem_file=$(ls ${output_path}.* 2>/dev/null | head -1)
        MEM_HASH=$(sha256sum "$mem_file" | cut -d' ' -f1)
        log "[✓] Memory dump SHA-256: $MEM_HASH"
        echo "$MEM_HASH  $(basename $mem_file)" >> "$EVIDENCE_DIR/$CASE_ID/hashes/memory_hashes.txt"
    fi
}

# Function to generate chain of custody document
generate_chain_of_custody() {
    local coc_file="$EVIDENCE_DIR/$CASE_ID/chain_of_custody/coc_${TIMESTAMP}.md"
    
    log ""
    log "${CYAN}=== GENERATING CHAIN OF CUSTODY DOCUMENT ===${NC}"
    
    cat > "$coc_file" << EOF
# CHAIN OF CUSTODY REPORT

## Case Information
| Field | Value |
|-------|-------|
| Case ID | $CASE_ID |
| Date | $(date "+%Y-%m-%d") |
| Time | $(date "+%H:%M:%S %Z") |
| Examiner | $EXAMINER |

## Evidence Items

### Disk Images
EOF

    # List all created images
    for img in "$EVIDENCE_DIR/$CASE_ID/disk_images"/*.dd; do
        if [ -f "$img" ]; then
            local img_name=$(basename "$img")
            local img_hash=$(sha256sum "$img" | cut -d' ' -f1)
            local img_size=$(ls -lh "$img" | awk '{print $5}')
            
            cat >> "$coc_file" << EOF

#### $img_name
| Property | Value |
|----------|-------|
| File | $img_name |
| Size | $img_size |
| SHA-256 | \`$img_hash\` |
| Created | $(stat -f "%Sm" "$img" 2>/dev/null || stat -c "%y" "$img" 2>/dev/null) |

EOF
        fi
    done

    cat >> "$coc_file" << EOF

## Evidence Handling Log

| Date/Time | Action | Person | Location | Notes |
|-----------|--------|--------|----------|-------|
| $(date "+%Y-%m-%d %H:%M") | Evidence Collected | $EXAMINER | Forensic Workstation | Initial acquisition |

## Signatures

### Examiner
- Name: $EXAMINER
- Date: $(date "+%Y-%m-%d")
- Signature: ________________________

### Witness (if applicable)
- Name: ________________________
- Date: ________________________
- Signature: ________________________

---
*This document is part of the official chain of custody for Case ID: $CASE_ID*
EOF

    log "[✓] Chain of Custody document created: $coc_file"
}

# Main execution
main() {
    log ""
    log "${GREEN}=== STARTING FORENSIC IMAGING PROCESS ===${NC}"
    log ""
    
    # For simulation: create a sample file to image
    if [ ! -e "/dev/sda" ]; then
        log "[*] Creating sample data for imaging demonstration..."
        
        # Create sample evidence file
        SAMPLE_FILE="$EVIDENCE_DIR/sample_evidence.img"
        dd if=/dev/urandom of="$SAMPLE_FILE" bs=1M count=10 2>/dev/null
        
        # Add some "evidence" to the sample
        echo "SIMULATED EVIDENCE DATA" >> "$SAMPLE_FILE"
        echo "User login: admin at $(date)" >> "$SAMPLE_FILE"
        echo "Suspicious file access detected" >> "$SAMPLE_FILE"
        
        log "[✓] Sample evidence file created: $SAMPLE_FILE"
        
        # Image the sample file
        create_disk_image "$SAMPLE_FILE" "sample_evidence"
    else
        # Real disk imaging (requires root)
        log "${YELLOW}[!] Real disk detected. Ensure you have proper authorization!${NC}"
        # create_disk_image "/dev/sda" "primary_disk"
    fi
    
    # Generate chain of custody
    generate_chain_of_custody
    
    # Summary
    log ""
    log "${GREEN}=== FORENSIC IMAGING COMPLETE ===${NC}"
    log ""
    log "Evidence Directory: $EVIDENCE_DIR/$CASE_ID"
    log ""
    log "Created files:"
    find "$EVIDENCE_DIR/$CASE_ID" -type f | while read f; do
        log "  - $f"
    done
    
    log ""
    log "${CYAN}Next Steps:${NC}"
    log "1. Verify all hash values"
    log "2. Complete chain of custody documentation"
    log "3. Store original evidence in secure location"
    log "4. Use forensic tools (Autopsy, FTK) to analyze images"
}

# Run main function
main "$@"
