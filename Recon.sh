#!/bin/bash

#═══════════════════════════════════════════════════════════════════════════════
#  ██████╗  ██████╗ ██████╗     ██╗     ███████╗██╗   ██╗███████╗██╗     
# ██╔════╝ ██╔═══██╗██╔══██╗    ██║     ██╔════╝██║   ██║██╔════╝██║     
# ██║  ███╗██║   ██║██║  ██║    ██║     █████╗  ██║   ██║█████╗  ██║     
# ██║   ██║██║   ██║██║  ██║    ██║     ██╔══╝  ╚██╗ ██╔╝██╔══╝  ██║     
# ╚██████╔╝╚██████╔╝██████╔╝    ███████╗███████╗ ╚████╔╝ ███████╗███████╗
#  ╚═════╝  ╚═════╝ ╚═════╝     ╚══════╝╚══════╝  ╚═══╝  ╚══════╝╚══════╝
#                                                                          
#  RECONNAISSANCE FRAMEWORK v6.1
# 
#═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail
IFS=$'\n\t'

# ============================================================================
# COLOR DEFINITIONS
# ============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ============================================================================
# CONFIGURATION
# ============================================================================
DOMAIN=""
WORKDIR=""
THREADS=50
TIMEOUT=120

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================
print_banner() {
    clear
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════════════════╗
║  ██████╗  ██████╗ ██████╗     ██╗     ███████╗██╗   ██╗███████╗██╗        ║
║ ██╔════╝ ██╔═══██╗██╔══██╗    ██║     ██╔════╝██║   ██║██╔════╝██║        ║
║ ██║  ███╗██║   ██║██║  ██║    ██║     █████╗  ██║   ██║█████╗  ██║        ║
║ ██║   ██║██║   ██║██║  ██║    ██║     ██╔══╝  ╚██╗ ██╔╝██╔══╝  ██║        ║
║ ╚██████╔╝╚██████╔╝██████╔╝    ███████╗███████╗ ╚████╔╝ ███████╗███████╗   ║
║  ╚═════╝  ╚═════╝ ╚═════╝     ╚══════╝╚══════╝  ╚═══╝  ╚══════╝╚══════╝   ║
║                                                                           ║
║             RECON v6.1 - CLEAN OUTPUT                                     ║
╚═══════════════════════════════════════════════════════════════════════════╝
EOF
    echo ""
}

log() { echo -e "${CYAN}[$(date +'%H:%M:%S')]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; }
warning() { echo -e "${YELLOW}[!]${NC} $1"; }
info() { echo -e "${BLUE}[*]${NC} $1"; }

section() {
    echo ""
    echo -e "${PURPLE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${PURPLE}${BOLD}  $1${NC}"
    echo -e "${PURPLE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

check_tool() {
    if ! command -v "$1" &> /dev/null; then
        return 1
    fi
    return 0
}

# ============================================================================
# MODULE 1: SUBDOMAIN ENUMERATION
# ============================================================================
module_subdomains() {
    section "MODULE 1: SUBDOMAIN ENUMERATION"
    
    > "$WORKDIR/.temp_subs.txt"
    
    # Parallel execution for speed
    info "Running passive enumeration (parallel)..."
    
    (check_tool subfinder && subfinder -d "$DOMAIN" -silent 2>/dev/null || true) >> "$WORKDIR/.temp_subs.txt" &
    (check_tool assetfinder && assetfinder --subs-only "$DOMAIN" 2>/dev/null || true) >> "$WORKDIR/.temp_subs.txt" &
    (check_tool amass && timeout "$TIMEOUT" amass enum -passive -d "$DOMAIN" 2>/dev/null || true) >> "$WORKDIR/.temp_subs.txt" &
    
    wait
    
    # Single unique file
    sort -u "$WORKDIR/.temp_subs.txt" > "$WORKDIR/subdomains.txt"
    rm -f "$WORKDIR/.temp_subs.txt"
    
    local total=$(wc -l < "$WORKDIR/subdomains.txt")
    success "Unique subdomains: ${BOLD}$total${NC}"
    
    # DNS Resolution
    info "Resolving subdomains..."
    
    if [ ! -f "$WORKDIR/resolvers.txt" ]; then
        echo -e "8.8.8.8\n1.1.1.1\n8.8.4.4\n1.0.0.1" > "$WORKDIR/resolvers.txt"
    fi
    
    if check_tool puredns; then
        puredns resolve "$WORKDIR/subdomains.txt" -r "$WORKDIR/resolvers.txt" -q > "$WORKDIR/resolved.txt" 2>/dev/null || true
    elif check_tool dnsx; then
        dnsx -l "$WORKDIR/subdomains.txt" -silent -a -resp-only -t $THREADS > "$WORKDIR/resolved.txt" 2>/dev/null || true
    else
        cp "$WORKDIR/subdomains.txt" "$WORKDIR/resolved.txt"
    fi
    
    # Extract IPs
    if check_tool dnsx; then
        dnsx -l "$WORKDIR/resolved.txt" -silent -a -resp-only 2>/dev/null | grep -oE '^[0-9.]+$' | sort -u > "$WORKDIR/ips.txt"
        success "Resolved: ${BOLD}$(wc -l < "$WORKDIR/resolved.txt")${NC} | IPs: ${BOLD}$(wc -l < "$WORKDIR/ips.txt")${NC}"
    else
        success "Resolved: ${BOLD}$(wc -l < "$WORKDIR/resolved.txt")${NC}"
    fi
}

# ============================================================================
# MODULE 2: ALIVE HOST DETECTION
# ============================================================================
module_alive() {
    section "MODULE 2: ALIVE WEB SERVICES"
    
    if [ ! -s "$WORKDIR/resolved.txt" ]; then
        error "No resolved subdomains found"
        return
    fi
    
    info "Probing for alive services..."
    
    if check_tool httpx; then
        httpx -l "$WORKDIR/resolved.txt" -silent -threads $THREADS \
            -status-code -title -tech-detect -follow-redirects \
            -o "$WORKDIR/alive.txt" 2>/dev/null
        
        local alive=$(wc -l < "$WORKDIR/alive.txt")
        success "Alive services: ${BOLD}$alive${NC}"
        
        # Extract clean URLs for next modules
        awk '{print $1}' "$WORKDIR/alive.txt" | sort -u > "$WORKDIR/live_urls.txt"
        
        # Quick stats
        echo "" > "$WORKDIR/stats.txt"
        echo "=== ALIVE SERVICES STATS ===" >> "$WORKDIR/stats.txt"
        grep -c "\[200\]" "$WORKDIR/alive.txt" 2>/dev/null >> "$WORKDIR/stats.txt" && echo " → HTTP 200 responses" >> "$WORKDIR/stats.txt" || true
        grep -c "\[403\]" "$WORKDIR/alive.txt" 2>/dev/null >> "$WORKDIR/stats.txt" && echo " → HTTP 403 (Forbidden)" >> "$WORKDIR/stats.txt" || true
        grep -c "\[401\]" "$WORKDIR/alive.txt" 2>/dev/null >> "$WORKDIR/stats.txt" && echo " → HTTP 401 (Auth Required)" >> "$WORKDIR/stats.txt" || true
        
        cat "$WORKDIR/stats.txt"
    else
        error "httpx not found - skipping"
        cp "$WORKDIR/resolved.txt" "$WORKDIR/live_urls.txt"
    fi
}

# ============================================================================
# MODULE 3: URL DISCOVERY
# ============================================================================
module_urls() {
    section "MODULE 3: URL DISCOVERY & CRAWLING"
    
    if [ ! -s "$WORKDIR/live_urls.txt" ]; then
        error "No alive URLs found"
        return
    fi
    
    info "Collecting URLs from archives & crawlers..."
    
    > "$WORKDIR/.temp_urls.txt"
    
    # Process each URL
    while IFS= read -r url; do
        echo -ne "\r${CYAN}[*]${NC} Processing: $url                    "
        
        # Parallel collection
        (check_tool waybackurls && echo "$url" | waybackurls 2>/dev/null || true) >> "$WORKDIR/.temp_urls.txt" &
        (check_tool gau && echo "$url" | gau --threads 3 --blacklist ttf,woff,svg,png,jpg 2>/dev/null || true) >> "$WORKDIR/.temp_urls.txt" &
        (check_tool hakrawler && echo "$url" | hakrawler -d 2 -subs -u -insecure 2>/dev/null || true) >> "$WORKDIR/.temp_urls.txt" &
        
        wait
        
    done < "$WORKDIR/live_urls.txt"
    
    echo ""
    
    # Clean and deduplicate
    grep -oE "https?://[^\"'<> ]+" "$WORKDIR/.temp_urls.txt" 2>/dev/null | sort -u > "$WORKDIR/urls.txt"
    rm -f "$WORKDIR/.temp_urls.txt"
    
    local total=$(wc -l < "$WORKDIR/urls.txt")
    success "Total unique URLs: ${BOLD}$total${NC}"
    
    # Smart categorization - single files only
    info "Categorizing URLs..."
    
    # Parameters (for testing)
    grep "?" "$WORKDIR/urls.txt" | sort -u > "$WORKDIR/params.txt"
    
    # APIs
    grep -Ei "(\/api\/|\/v[0-9]\/|\/rest\/|\/graphql)" "$WORKDIR/urls.txt" | sort -u > "$WORKDIR/apis.txt"
    
    # JavaScript
    grep -Ei "\.js(\?|$)" "$WORKDIR/urls.txt" | sort -u > "$WORKDIR/javascript.txt"
    
    # Interesting paths
    grep -Ei "(admin|login|auth|dashboard|panel|config|upload|backup)" "$WORKDIR/urls.txt" | sort -u > "$WORKDIR/interesting.txt"
    
    echo ""
    echo -e "${GREEN}├─${NC} Parameters: ${BOLD}$(wc -l < "$WORKDIR/params.txt")${NC}"
    echo -e "${GREEN}├─${NC} APIs: ${BOLD}$(wc -l < "$WORKDIR/apis.txt")${NC}"
    echo -e "${GREEN}├─${NC} JavaScript: ${BOLD}$(wc -l < "$WORKDIR/javascript.txt")${NC}"
    echo -e "${GREEN}└─${NC} Interesting: ${BOLD}$(wc -l < "$WORKDIR/interesting.txt")${NC}"
    
    # GF patterns (only if available and worth it)
    if check_tool gf && [ "$total" -gt 100 ]; then
        info "Running GF pattern matching..."
        
        > "$WORKDIR/patterns.txt"
        for pattern in xss sqli lfi ssrf redirect; do
            local matches=$(cat "$WORKDIR/urls.txt" | gf "$pattern" 2>/dev/null | wc -l)
            if [ "$matches" -gt 0 ]; then
                echo "$pattern: $matches matches" >> "$WORKDIR/patterns.txt"
                cat "$WORKDIR/urls.txt" | gf "$pattern" 2>/dev/null | head -20 >> "$WORKDIR/patterns.txt"
                echo "" >> "$WORKDIR/patterns.txt"
            fi
        done
        
        [ -s "$WORKDIR/patterns.txt" ] && success "GF patterns saved to patterns.txt"
    fi
}

# ============================================================================
# MODULE 4: VULNERABILITY SCANNING
# ============================================================================
module_vuln() {
    section "MODULE 4: VULNERABILITY DETECTION"
    
    if [ ! -s "$WORKDIR/live_urls.txt" ]; then
        error "No alive URLs found"
        return
    fi
    
    > "$WORKDIR/findings.txt"
    
    # Quick vulnerability checks from URLs
    if [ -s "$WORKDIR/urls.txt" ]; then
        info "Analyzing URL patterns..."
        
        # Sensitive files
        local sensitive=$(grep -Ei "\.(env|git|config|backup|bak|old|sql|zip|tar|gz)(\?|$)" "$WORKDIR/urls.txt" | wc -l)
        if [ "$sensitive" -gt 0 ]; then
            warning "Sensitive files: $sensitive"
            echo "=== SENSITIVE FILES ===" >> "$WORKDIR/findings.txt"
            grep -Ei "\.(env|git|config|backup|bak|old|sql|zip|tar|gz)(\?|$)" "$WORKDIR/urls.txt" | head -50 >> "$WORKDIR/findings.txt"
            echo "" >> "$WORKDIR/findings.txt"
        fi
        
        # Potential SQLi
        local sqli=$(grep -Ei "(union|select|from|where|\.\.\/)" "$WORKDIR/urls.txt" | wc -l)
        if [ "$sqli" -gt 0 ]; then
            warning "Potential SQLi patterns: $sqli"
            echo "=== POTENTIAL SQLi ===" >> "$WORKDIR/findings.txt"
            grep -Ei "(union|select|from|where|\.\.\/)" "$WORKDIR/urls.txt" | head -30 >> "$WORKDIR/findings.txt"
            echo "" >> "$WORKDIR/findings.txt"
        fi
        
        # Potential XSS
        local xss=$(grep -Ei "(<script|onerror=|onload=|javascript:)" "$WORKDIR/urls.txt" | wc -l)
        if [ "$xss" -gt 0 ]; then
            warning "Potential XSS patterns: $xss"
            echo "=== POTENTIAL XSS ===" >> "$WORKDIR/findings.txt"
            grep -Ei "(<script|onerror=|onload=|javascript:)" "$WORKDIR/urls.txt" | head -30 >> "$WORKDIR/findings.txt"
            echo "" >> "$WORKDIR/findings.txt"
        fi
    fi
    
    # Nuclei scan
    if check_tool nuclei; then
        info "Running Nuclei scanner..."
        nuclei -l "$WORKDIR/live_urls.txt" -severity critical,high,medium \
            -silent -no-color -o "$WORKDIR/nuclei.txt" 2>/dev/null || true
        
        if [ -s "$WORKDIR/nuclei.txt" ]; then
            local vulns=$(wc -l < "$WORKDIR/nuclei.txt")
            warning "Nuclei found $vulns potential issues"
            echo "=== NUCLEI SCAN ===" >> "$WORKDIR/findings.txt"
            cat "$WORKDIR/nuclei.txt" >> "$WORKDIR/findings.txt"
        else
            success "No critical vulnerabilities detected by Nuclei"
        fi
    fi
    
    [ -s "$WORKDIR/findings.txt" ] && success "Findings saved to findings.txt" || success "No major issues found"
}

# ============================================================================
# MODULE 5: ASN & NETWORK INTELLIGENCE
# ============================================================================
module_asn() {
    section "MODULE 5: ASN & NETWORK INTELLIGENCE"
    
    info "Gathering ASN information..."
    
    # Get primary IP
    local ip=$(dig +short "$DOMAIN" 2>/dev/null | grep -oE '^[0-9.]+$' | head -1)
    
    if [ -z "$ip" ]; then
        error "Could not resolve domain IP"
        return
    fi
    
    > "$WORKDIR/asn.txt"
    
    echo "DOMAIN: $DOMAIN" >> "$WORKDIR/asn.txt"
    echo "PRIMARY IP: $ip" >> "$WORKDIR/asn.txt"
    echo "" >> "$WORKDIR/asn.txt"
    
    # Get ASN info
    local asn_data=$(curl -s "http://ip-api.com/json/$ip" 2>/dev/null)
    
    if [ -n "$asn_data" ]; then
        local asn=$(echo "$asn_data" | grep -oP '"as":"\K[^"]+' | cut -d' ' -f1 | sed 's/AS//')
        local org=$(echo "$asn_data" | grep -oP '"org":"\K[^"]+')
        local country=$(echo "$asn_data" | grep -oP '"country":"\K[^"]+')
        
        echo "ASN: AS$asn" >> "$WORKDIR/asn.txt"
        echo "Organization: $org" >> "$WORKDIR/asn.txt"
        echo "Country: $country" >> "$WORKDIR/asn.txt"
        echo "" >> "$WORKDIR/asn.txt"
        
        if [ -n "$asn" ]; then
            info "Getting IP ranges for AS$asn..."
            whois -h whois.radb.net -- "-i origin AS$asn" 2>/dev/null | \
                grep -Eo "([0-9.]+){4}/[0-9]+" | sort -u > "$WORKDIR/ip_ranges.txt" || true
            
            local ranges=$(wc -l < "$WORKDIR/ip_ranges.txt" 2>/dev/null || echo 0)
            echo "IP RANGES: $ranges" >> "$WORKDIR/asn.txt"
            
            success "ASN: AS$asn | Org: $org | Ranges: $ranges"
        fi
    fi
    
    cat "$WORKDIR/asn.txt"
}

# ============================================================================
# FINAL REPORT
# ============================================================================
generate_report() {
    section "GENERATING SUMMARY"
    
    cat > "$WORKDIR/SUMMARY.txt" << EOF
╔═══════════════════════════════════════════════════════════════════════════╗
║                     GOD LEVEL RECON - SUMMARY REPORT                      ║
╚═══════════════════════════════════════════════════════════════════════════╝

Target: $DOMAIN
Date: $(date)
Location: $WORKDIR

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📊 STATISTICS:

$([ -f "$WORKDIR/subdomains.txt" ] && echo "  → Total Subdomains: $(wc -l < "$WORKDIR/subdomains.txt")" || echo "  → Total Subdomains: 0")
$([ -f "$WORKDIR/resolved.txt" ] && echo "  → Resolved: $(wc -l < "$WORKDIR/resolved.txt")" || echo "  → Resolved: 0")
$([ -f "$WORKDIR/ips.txt" ] && echo "  → Unique IPs: $(wc -l < "$WORKDIR/ips.txt")" || echo "  → Unique IPs: 0")
$([ -f "$WORKDIR/alive.txt" ] && echo "  → Alive Services: $(wc -l < "$WORKDIR/alive.txt")" || echo "  → Alive Services: 0")
$([ -f "$WORKDIR/urls.txt" ] && echo "  → Total URLs: $(wc -l < "$WORKDIR/urls.txt")" || echo "  → Total URLs: 0")
$([ -f "$WORKDIR/params.txt" ] && echo "  → Parameterized URLs: $(wc -l < "$WORKDIR/params.txt")" || echo "  → Parameterized URLs: 0")
$([ -f "$WORKDIR/apis.txt" ] && echo "  → API Endpoints: $(wc -l < "$WORKDIR/apis.txt")" || echo "  → API Endpoints: 0")


Security:
  findings.txt        # Vulnerability findings
  $([ -f "$WORKDIR/nuclei.txt" ] && echo "nuclei.txt          # Nuclei scan results")
  $([ -f "$WORKDIR/patterns.txt" ] && echo "patterns.txt        # GF pattern matches")

Intelligence:
  asn.txt             # ASN & network info
  $([ -f "$WORKDIR/ip_ranges.txt" ] && echo "ip_ranges.txt       # IP ranges for ASN")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🎯 NEXT STEPS:

1. Review findings.txt for potential vulnerabilities
2. Test parameters in params.txt for injection flaws
3. Analyze APIs in apis.txt for exposed endpoints
4. Check javascript.txt for sensitive data in JS files
5. Investigate interesting.txt for unauthorized access

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚡ Pro Tips:
  • Use 'cat params.txt | qsreplace FUZZ | ffuf' for parameter fuzzing
  • Feed javascript.txt to 'LinkFinder' for hidden endpoints
  • Check alive.txt for outdated tech stacks
  • Use ip_ranges.txt for broader network scanning

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF
    
    cat "$WORKDIR/SUMMARY.txt"
    echo ""
    success "Complete summary saved to: ${BOLD}SUMMARY.txt${NC}"
}

# ============================================================================
# CLEANUP
# ============================================================================
cleanup() {
    # Remove empty files
    find "$WORKDIR" -type f -empty -delete 2>/dev/null || true
    # Remove temp files
    rm -f "$WORKDIR/.temp_"* "$WORKDIR/resolvers.txt" "$WORKDIR/stats.txt" 2>/dev/null || true
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================
main() {
    print_banner
    
    if [ $# -eq 0 ]; then
        error "Domain required!"
        echo ""
        echo "Usage: $0 <domain> [threads]"
        echo ""
        echo "Example:"
        echo "  $0 example.com"
        echo "  $0 example.com 100"
        exit 1
    fi
    
    DOMAIN="$1"
    [ $# -gt 1 ] && THREADS="$2"
    
    WORKDIR="${DOMAIN}-recon"
    
    # Create work directory ONCE
    if [ -d "$WORKDIR" ]; then
        warning "Directory $WORKDIR already exists!"
        read -p "Delete and continue? (y/N): " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            rm -rf "$WORKDIR"
        else
            error "Aborted"
            exit 1
        fi
    fi
    
    mkdir -p "$WORKDIR"
    
    info "Target: ${BOLD}$DOMAIN${NC}"
    info "Threads: ${BOLD}$THREADS${NC}"
    info "Output: ${BOLD}$WORKDIR${NC}"
    echo ""
    
    local start=$(date +%s)
    
    # Execute all modules
    module_subdomains
    module_alive
    module_urls
    module_vuln
    module_asn
    
    # Final steps
    cleanup
    generate_report
    
    local end=$(date +%s)
    local duration=$((end - start))
    
    section "RECON COMPLETE"
    success "Time taken: ${BOLD}${duration}s${NC} ($(($duration / 60))m)"
    success "All results in: ${BOLD}$WORKDIR${NC}"
    echo ""
}

main "$@"
