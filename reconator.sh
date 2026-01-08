#!/bin/bash
# Reconator - Improved Version
# More efficient, cleaner output, better error handling

# Exit on error
set -e

# Source profiles if they exist
[[ -f ~/.profile ]] && source ~/.profile
[[ -f ~/.bash_profile ]] && source ~/.bash_profile

# Validate input
if [ $# -eq 0 ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

url=$1

# Create directory structure
mkdir -p "$url"/{subdomains,potential_takeovers,wayback,httpx,scans,nuclei}

# Banner
cat << "EOF"

 ██▀███  ▓█████  ▄████▄   ▒█████   ███▄    █  ▄▄▄     ▄▄▄█████▓ ▒█████   ██▀███
▓██ ▒ ██▒▓█   ▀ ▒██▀ ▀█  ▒██▒  ██▒ ██ ▀█   █ ▒████▄   ▓  ██▒ ▓▒▒██▒  ██▒▓██ ▒ ██▒
▓██ ░▄█ ▒▒███   ▒▓█    ▄ ▒██░  ██▒▓██  ▀█ ██▒▒██  ▀█▄ ▒ ▓██░ ▒░▒██░  ██▒▓██ ░▄█ ▒
▒██▀▀█▄  ▒▓█  ▄ ▒▓▓▄ ▄██▒▒██   ██░▓██▒  ▐▌██▒░██▄▄▄▄██░ ▓██▓ ░ ▒██   ██░▒██▀▀█▄
░██▓ ▒██▒░▒████▒▒ ▓███▀ ░░ ████▓▒░▒██░   ▓██░ ▓█   ▓██▒ ▒██▒ ░ ░ ████▓▒░░██▓ ▒██▒
░ ▒▓ ░▒▓░░░ ▒░ ░░ ░▒ ▒  ░░ ▒░▒░▒░ ░ ▒░   ▒ ▒  ▒▒   ▓▒█░ ▒ ░░   ░ ▒░▒░▒░ ░ ▒▓ ░▒▓░
  ░▒ ░ ▒░ ░ ░  ░  ░  ▒     ░ ▒ ▒░ ░ ░░   ░ ▒░  ▒   ▒▒ ░   ░      ░ ▒ ▒░   ░▒ ░ ▒░
  ░░   ░    ░   ░        ░ ░ ░ ▒     ░   ░ ░   ░   ▒    ░      ░ ░ ░ ▒    ░░   ░
   ░        ░  ░░ ░          ░ ░           ░       ░  ░            ░ ░     ░
                ░                                       - By @RootSploit

EOF

# Consolidated subdomain enumeration with 3rd party APIs
subdomain_misc() {
    echo "[+] Harvesting subdomains with 3rd Party APIs..."

    local tmpfile=$(mktemp)

    # Run all API queries and redirect everything to tmpfile (no stdout)
    (
        # ThreatCrowd
        curl -sk "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$url" 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.$url" 2>/dev/null

        # HackerTarget
        curl -sk "https://api.hackertarget.com/hostsearch/?q=$url" 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.$url" 2>/dev/null

        # crt.sh - 4 depth levels
        curl -sk "https://crt.sh/?q=%.$url" 2>/dev/null | grep "$url" 2>/dev/null | cut -d '>' -f2 | cut -d '<' -f1 | grep -v " " 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.$url" 2>/dev/null
        curl -sk "https://crt.sh/?q=%.%.$url" 2>/dev/null | grep "$url" 2>/dev/null | cut -d '>' -f2 | cut -d '<' -f1 | grep -v " " 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.$url" 2>/dev/null
        curl -sk "https://crt.sh/?q=%.%.%.$url" 2>/dev/null | grep "$url" 2>/dev/null | cut -d '>' -f2 | cut -d '<' -f1 | grep -v " " 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.$url" 2>/dev/null
        curl -sk "https://crt.sh/?q=%.%.%.%.$url" 2>/dev/null | grep "$url" 2>/dev/null | cut -d '>' -f2 | cut -d '<' -f1 | grep -v " " 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.$url" 2>/dev/null

        # URLScan
        curl -sk "https://urlscan.io/api/v1/search/?q=$url" 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.$url" 2>/dev/null

        # Sonar Omnisint
        curl -sk "https://sonar.omnisint.io/subdomains/$url" 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.$url" 2>/dev/null

        # AlienVault OTX
        curl -sk "https://otx.alienvault.com/api/v1/indicators/domain/$url/passive_dns" 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.$url" 2>/dev/null

        # BufferOver
        curl -sk "https://dns.bufferover.run/dns?q=.$url" 2>/dev/null | jq -r ".FDNS_A[]?" 2>/dev/null | cut -d ',' -f2 2>/dev/null

        # AnubisDB
        curl -sk "https://jldc.me/anubis/subdomains/$url" 2>/dev/null | jq -r '.[]?' 2>/dev/null | tr -d '"' 2>/dev/null

        # Riddler.io
        curl -sk "https://riddler.io/search/exportcsv?q=pld:$url" 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.$url" 2>/dev/null

        # VirusTotal (public search)
        curl -sk "https://www.virustotal.com/ui/domains/$url/subdomains?limit=40" 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.$url" 2>/dev/null

        # RapidDNS
        curl -sk "https://rapiddns.io/subdomain/$url" 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.$url" 2>/dev/null

        # DNSDumpster alternative via search
        curl -sk "https://api.recon.dev/search?domain=$url" 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.$url" 2>/dev/null

        # SecurityTrails (public)
        curl -sk "https://securitytrails.com/domain/$url/dns" 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.$url" 2>/dev/null

        # Leakix
        curl -sk "https://leakix.net/domain/$url" 2>/dev/null | grep -oE "[a-zA-Z0-9._-]+\.$url" 2>/dev/null

        # CertSpotter
        curl -sk "https://api.certspotter.com/v1/issuances?domain=$url&include_subdomains=true&expand=dns_names" 2>/dev/null | jq -r '.[].dns_names[]?' 2>/dev/null | grep "$url" 2>/dev/null

        # Facebook CT
        curl -sk "https://graph.facebook.com/certificates?query=$url&access_token=|&fields=domains" 2>/dev/null | jq -r '.data[].domains[]?' 2>/dev/null | grep "$url" 2>/dev/null

        # Sublist3r API (if available)
        curl -sk "https://api.sublist3r.com/search.php?domain=$url" 2>/dev/null | jq -r '.[]?' 2>/dev/null | grep "$url" 2>/dev/null

        # WebArchive CDX
        curl -sk "https://web.archive.org/cdx/search/cdx?url=*.$url&output=json&fl=original&collapse=urlkey" 2>/dev/null | jq -r '.[]?' 2>/dev/null | grep "$url" 2>/dev/null | cut -d'/' -f3 | sort -u

    ) > "$tmpfile" 2>&1

    sort -u "$tmpfile" | grep -v '^$' | grep -v '^\*\.' > "$url/subdomains/misc-subs.txt" 2>/dev/null
    rm -f "$tmpfile"

    local subcount=$(wc -l < "$url/subdomains/misc-subs.txt" 2>/dev/null | tr -d ' ')
    echo "    [-] Subdomains Found with 3rd Party APIs: $subcount"
}

# Assetfinder enumeration
subdomain_assetfinder() {
    if ! command -v assetfinder &>/dev/null; then
        return 0
    fi

    echo "[+] Harvesting subdomains with Assetfinder..."
    assetfinder --subs-only "$url" 2>&1 | grep -v ":" | grep "$url" | sort -u > "$url/subdomains/assetfinder.txt"
    local subcount=$(wc -l < "$url/subdomains/assetfinder.txt" | tr -d ' ')
    echo "    [-] Subdomains Found with Assetfinder: $subcount"
}

# Findomain enumeration
subdomain_findomain() {
    if ! command -v findomain &>/dev/null; then
        return 0
    fi

    echo "[+] Harvesting subdomains with Findomain..."
    findomain -t "$url" --threads 25 -q 2>&1 | grep -v "Searching" | grep "$url" | sort -u > "$url/subdomains/findomain.txt"
    local subcount=$(wc -l < "$url/subdomains/findomain.txt" 2>/dev/null | tr -d ' ')
    echo "    [-] Subdomains Found with Findomain: $subcount"
}

# Subfinder enumeration
subdomain_subfinder() {
    if ! command -v subfinder &>/dev/null; then
        return 0
    fi

    echo "[+] Harvesting subdomains with Subfinder..."
    subfinder -d "$url" -all -t 25 2>&1 >/dev/null | grep -v "\[" | grep "$url" | sort -u > "$url/subdomains/subfinder.txt" &

    # Silent version to file
    subfinder -d "$url" -silent -all -t 25 2>/dev/null | grep "$url" >> "$url/subdomains/subfinder.txt"
    wait

    sort -u "$url/subdomains/subfinder.txt" -o "$url/subdomains/subfinder.txt"
    local subcount=$(wc -l < "$url/subdomains/subfinder.txt" | tr -d ' ')
    echo "    [-] Subdomains Found with Subfinder: $subcount"
}

# Vita enumeration
subdomain_vita() {
    if ! command -v vita &>/dev/null; then
        return 0
    fi

    echo "[+] Harvesting subdomains with Vita..."
    vita -d "$url" -a --subs-only 2>/dev/null | grep "$url" | sort -u > "$url/subdomains/vita.txt"
    local subcount=$(wc -l < "$url/subdomains/vita.txt" | tr -d ' ')
    echo "    [-] Subdomains Found with Vita: $subcount"
}

# Chaos enumeration
subdomain_chaos() {
    if ! command -v chaos &>/dev/null; then
        return 0
    fi

    echo "[+] Harvesting subdomains with Chaos..."
    chaos -d "$url" --silent 2>/dev/null | grep "$url" | sort -u > "$url/subdomains/chaos.txt"
    local subcount=$(wc -l < "$url/subdomains/chaos.txt" | tr -d ' ')
    echo "    [-] Subdomains Found with Chaos: $subcount"
}

# Amass enumeration (passive mode)
subdomain_amass() {
    if ! command -v amass &>/dev/null; then
        return 0
    fi

    echo "[+] Harvesting subdomains with Amass..."
    amass enum -passive -d "$url" -o "$url/subdomains/amass.txt" 2>/dev/null
    sort -u "$url/subdomains/amass.txt" -o "$url/subdomains/amass.txt" 2>/dev/null
    local subcount=$(wc -l < "$url/subdomains/amass.txt" 2>/dev/null | tr -d ' ')
    echo "    [-] Subdomains Found with Amass: $subcount"
}

# Puredns DNS Bruteforce (Now enabled with extended wordlist)
subdomain_puredns() {
    if ! command -v puredns &>/dev/null; then
        return 0
    fi

    # Try wordlists in order: medium (20k) > extended (630) > small (25)
    local wordlist_path="$(dirname "$0")/wordlists/subdomain-bruteforce-medium.txt"
    if [ ! -f "$wordlist_path" ]; then
        wordlist_path="$(dirname "$0")/wordlists/subdomain-bruteforce-extended.txt"
    fi
    if [ ! -f "$wordlist_path" ]; then
        wordlist_path="$(dirname "$0")/wordlists/subdomain-bruteforce.txt"
    fi

    if [ ! -f "$wordlist_path" ]; then
        return 0
    fi

    # Use resolvers if available
    local resolvers_path="$(dirname "$0")/wordlists/resolvers.txt"
    if [ ! -f "$resolvers_path" ]; then
        # Fallback resolvers
        echo "8.8.8.8" > /tmp/resolvers-tmp.txt
        echo "1.1.1.1" >> /tmp/resolvers-tmp.txt
        resolvers_path="/tmp/resolvers-tmp.txt"
    fi

    local wordcount=$(wc -l < "$wordlist_path" | tr -d ' ')
    echo "[+] DNS Bruteforce with PureDNS ($wordcount words)..."

    puredns bruteforce "$wordlist_path" "$url" -r "$resolvers_path" --write "$url/subdomains/puredns-bruteforce.txt" 2>/dev/null

    [ -f "/tmp/resolvers-tmp.txt" ] && rm -f /tmp/resolvers-tmp.txt

    local subcount=$(wc -l < "$url/subdomains/puredns-bruteforce.txt" 2>/dev/null | tr -d ' ')
    echo "    [-] Subdomains Found with PureDNS Bruteforce: $subcount"
}

# GitHub subdomain scraping
subdomain_github() {
    if ! command -v github-subdomains &>/dev/null; then
        return 0
    fi

    echo "[+] Harvesting subdomains from GitHub..."
    github-subdomains -d "$url" -t $GITHUB_TOKEN 2>/dev/null | sort -u > "$url/subdomains/github.txt"
    local subcount=$(wc -l < "$url/subdomains/github.txt" 2>/dev/null | tr -d ' ')
    echo "    [-] Subdomains Found from GitHub: $subcount"
}

# Cero enumeration
subdomain_cero() {
    if ! command -v cero &>/dev/null; then
        return 0
    fi

    echo "[+] Harvesting subdomains with Cero..."
    cero -d "$url" 2>&1 | grep -v "Cero" | grep "$url" | sort -u > "$url/subdomains/cero.txt"
    local subcount=$(wc -l < "$url/subdomains/cero.txt" | tr -d ' ')
    echo "    [-] Subdomains Found with Cero: $subcount"
}

# DNS Bruteforce with DNSx
subdomain_dnsx_bruteforce() {
    if ! command -v dnsx &>/dev/null; then
        return 0
    fi

    # Try wordlists in order: medium (20k) > extended (630) > small (25)
    local wordlist_path="$(dirname "$0")/wordlists/subdomain-bruteforce-medium.txt"
    if [ ! -f "$wordlist_path" ]; then
        wordlist_path="$(dirname "$0")/wordlists/subdomain-bruteforce-extended.txt"
    fi
    if [ ! -f "$wordlist_path" ]; then
        wordlist_path="$(dirname "$0")/wordlists/subdomain-bruteforce.txt"
    fi

    if [ ! -f "$wordlist_path" ]; then
        return 0
    fi

    # Use resolvers if available
    local resolvers_path="$(dirname "$0")/wordlists/resolvers.txt"
    local resolver_flag=""
    if [ -f "$resolvers_path" ]; then
        resolver_flag="-r $resolvers_path"
    fi

    local wordcount=$(wc -l < "$wordlist_path" | tr -d ' ')
    echo "[+] DNS Bruteforce with DNSx ($wordcount words)..."

    dnsx -d "$url" -w "$wordlist_path" $resolver_flag -silent -a -resp 2>/dev/null | \
        awk '{print $1}' | \
        sort -u > "$url/subdomains/dnsx-bruteforce.txt"

    local subcount=$(wc -l < "$url/subdomains/dnsx-bruteforce.txt" 2>/dev/null | tr -d ' ')
    echo "    [-] Subdomains Found with DNSx Bruteforce: $subcount"
}

# Subdomain Permutations with mksub + dsieve enrichment
subdomain_permutations() {
    if ! command -v mksub &>/dev/null; then
        return 0
    fi

    # Try wordlists in order: medium (20k) > extended (630) > small (25)
    local wordlist_path="$(dirname "$0")/wordlists/subdomain-bruteforce-medium.txt"
    if [ ! -f "$wordlist_path" ]; then
        wordlist_path="$(dirname "$0")/wordlists/subdomain-bruteforce-extended.txt"
    fi
    if [ ! -f "$wordlist_path" ]; then
        wordlist_path="$(dirname "$0")/wordlists/subdomain-bruteforce.txt"
    fi

    if [ ! -f "$wordlist_path" ]; then
        return 0
    fi

    local wordcount=$(wc -l < "$wordlist_path" | tr -d ' ')
    echo "[+] Generating subdomain permutations ($wordcount word patterns)..."

    # Merge discovered subdomains for permutation input
    cat "$url/subdomains"/*.txt 2>/dev/null | sort -u > "$url/subdomains/discovered-base.txt"

    # Step 1: Generate permutations with mksub (all levels - no depth limit)
    cat "$url/subdomains/discovered-base.txt" | \
        mksub -d "$url" -w "$wordlist_path" 2>/dev/null | \
        grep "$url" | \
        sort -u > "$url/subdomains/mksub-permutations.txt"

    local mksub_count=$(wc -l < "$url/subdomains/mksub-permutations.txt" 2>/dev/null | tr -d ' ')
    echo "    [*] mksub generated: $mksub_count permutations"

    # Step 2: dsieve enrichment (extract all subdomain levels from nested domains)
    if command -v dsieve &>/dev/null; then
        cat "$url/subdomains/discovered-base.txt" | \
            dsieve -f 3: 2>/dev/null | \
            grep "$url" | \
            sort -u > "$url/subdomains/dsieve-enriched.txt"

        local dsieve_count=$(wc -l < "$url/subdomains/dsieve-enriched.txt" 2>/dev/null | tr -d ' ')
        echo "    [*] dsieve enriched: $dsieve_count subdomains"
    fi

    # Merge all permutations
    cat "$url/subdomains"/mksub-permutations.txt "$url/subdomains"/dsieve-enriched.txt 2>/dev/null | \
        sort -u > "$url/subdomains/all-permutations.txt"

    local total_count=$(wc -l < "$url/subdomains/all-permutations.txt" 2>/dev/null | tr -d ' ')
    echo "    [-] Total Permutations Generated: $total_count"
}

# Validate with PureDNS (faster) or DNSx (fallback) - DNS Resolution Check
subdomain_validation() {
    echo "[+] Validating subdomains (DNS Resolution)..."

    # Combine all discovered + bruteforced + permuted subdomains
    cat "$url/subdomains"/*.txt 2>/dev/null | sort -u > "$url/subdomains/all-unvalidated.txt"

    local total=$(wc -l < "$url/subdomains/all-unvalidated.txt" 2>/dev/null | tr -d ' ')
    echo "    [*] Validating $total subdomains..."

    # Use resolvers if available
    local resolvers_path="$(dirname "$0")/wordlists/resolvers.txt"

    # Try PureDNS first (faster for large lists)
    if command -v puredns &>/dev/null && [ -f "$resolvers_path" ]; then
        echo "    [*] Using PureDNS with custom resolvers..."
        puredns resolve "$url/subdomains/all-unvalidated.txt" -r "$resolvers_path" \
            --write "$url/subdomains/validated.txt" 2>/dev/null

        local subcount=$(wc -l < "$url/subdomains/validated.txt" 2>/dev/null | tr -d ' ')

        # If PureDNS succeeded, we're done
        if [ "$subcount" -gt 0 ]; then
            local filtered=$((total - subcount))
            echo "    [-] Validated Subdomains: $subcount (filtered out: $filtered)"
            return 0
        fi
    fi

    # Fallback to DNSx if PureDNS failed or not available
    if command -v dnsx &>/dev/null; then
        echo "    [*] Using DNSx for validation..."
        local resolver_flag=""
        if [ -f "$resolvers_path" ]; then
            resolver_flag="-r $resolvers_path"
        fi

        cat "$url/subdomains/all-unvalidated.txt" | \
            dnsx $resolver_flag -silent -a -resp 2>/dev/null | \
            awk '{print $1}' | \
            grep -v '^\*\.' | \
            sort -u > "$url/subdomains/validated.txt"

        local subcount=$(wc -l < "$url/subdomains/validated.txt" 2>/dev/null | tr -d ' ')
        local filtered=$((total - subcount))
        echo "    [-] Validated Subdomains: $subcount (filtered out: $filtered)"
    else
        echo "[!] No validation tools available (puredns/dnsx not found)"
        cp "$url/subdomains/all-unvalidated.txt" "$url/subdomains/validated.txt"
        echo "    [-] Skipped validation: $total subdomains"
    fi
}

# Merge all subdomains
subdomain_merge() {
    echo "[+] Merging all the subdomains..."

    # Use validated list if it exists, otherwise merge all
    if [ -f "$url/subdomains/validated.txt" ] && [ -s "$url/subdomains/validated.txt" ]; then
        cp "$url/subdomains/validated.txt" "$url/subdomains/subdomains.txt"
    else
        cat "$url/subdomains"/*.txt 2>/dev/null | sort -u > "$url/subdomains/subdomains.txt"
    fi

    local subcount=$(wc -l < "$url/subdomains/subdomains.txt" | tr -d ' ')
    echo "    [*] Total No of Subdomains Identified: $subcount"
}

# Subdomain takeover check
subdomain_takeover() {
    if ! command -v nuclei &>/dev/null; then
        echo "[+] Skipping subdomain takeover (nuclei not found)"
        return 0
    fi

    echo "[+] Performing Subdomain Takeover..."
    nuclei -update-templates -silent &>/dev/null

    local pids=()

    # Nuclei takeover scan
    if [ -f "$url/httpx/alive.txt" ]; then
        cat "$url/httpx/alive.txt" | nuclei -c 200 -t subdomain-takeover/ -o "$url/potential_takeovers/nuclei.txt" -silent &>/dev/null &
        pids+=($!)
    fi

    # Subzy scan
    if command -v subzy &>/dev/null; then
        subzy --targets="$url/subdomains/subdomains.txt" --concurrency 25 --hide_fails --https > "$url/potential_takeovers/subzy.txt" 2>/dev/null &
        pids+=($!)
    fi

    # Subjack scan
    if command -v subjack &>/dev/null && [ -f ~/go/src/github.com/haccer/subjack/fingerprints.json ]; then
        subjack -w "$url/subdomains/subdomains.txt" -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3 -o "$url/potential_takeovers/takeover.txt" > "$url/potential_takeovers/subjack.txt" 2>/dev/null &
        pids+=($!)
    fi

    # Wait for all takeover scans
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done

    echo "    [-] Subdomain Takeover Scan Completed"
}

# Port scanning with naabu
port_scan_naabu() {
    if ! command -v naabu &>/dev/null; then
        echo "[+] Skipping port scan (naabu not found)"
        return 0
    fi

    echo "[+] Performing Portscan on Subdomains..."
    naabu -c 250 -l "$url/subdomains/subdomains.txt" \
        -port 80,443,4443,3000,5000,8000-8100,9000-9003,10000,10001,7000-7003,7070 \
        -o "$url/scans/naabu_scans.txt" -silent 2>/dev/null >/dev/null

    local portcount=$(wc -l < "$url/scans/naabu_scans.txt" 2>/dev/null | tr -d ' ')
    echo "    [-] Port Scan Completed: $portcount open ports found"
}

# Probe for alive domains
probe_subdomains() {
    if ! command -v httpx &>/dev/null; then
        echo "[+] Skipping probing (httpx not found)"
        return 0
    fi

    echo "[+] Probing for alive domains..."
    cat "$url/scans/naabu_scans.txt" 2>/dev/null | httpx -threads 200 -silent > "$url/httpx/alive.txt" 2>/dev/null
    local alivec=$(wc -l < "$url/httpx/alive.txt" | tr -d ' ')
    echo "    [*] Total No of Alive Subdomains Identified: $alivec"
}

# Nuclei vulnerability scan
nuclei_scan() {
    if ! command -v nuclei &>/dev/null; then
        echo "[+] Skipping nuclei scan (nuclei not found)"
        return 0
    fi

    if [ ! -f "$url/httpx/alive.txt" ] || [ ! -s "$url/httpx/alive.txt" ]; then
        echo "[+] Skipping nuclei scan (no alive hosts)"
        return 0
    fi

    echo "[+] Scanning for known CVE with Nuclei..."
    nuclei -update-templates -silent &>/dev/null

    # Run scans in parallel
    cat "$url/httpx/alive.txt" | nuclei -c 200 -t security-misconfiguration/ -o "$url/nuclei/security-misconfiguration.txt" -silent &>/dev/null &
    cat "$url/httpx/alive.txt" | nuclei -c 200 -t panels/ -o "$url/nuclei/panels.txt" -silent &>/dev/null &
    cat "$url/httpx/alive.txt" | nuclei -c 200 -t files/ -o "$url/nuclei/files.txt" -silent &>/dev/null &

    wait
    echo "    [-] Scanning with Nuclei Completed"
}

# VHost Bruteforce with ffuf (with CDN/WAF protection)
vhost_bruteforce() {
    if ! command -v ffuf &>/dev/null; then
        echo "[+] Skipping VHost discovery (ffuf not found)"
        return 0
    fi

    if [ ! -f "$url/httpx/alive.txt" ] || [ ! -s "$url/httpx/alive.txt" ]; then
        echo "[+] Skipping VHost discovery (no alive hosts)"
        return 0
    fi

    # Try wordlists in order: medium (20k) > extended (630) > small (25)
    local wordlist_path="$(dirname "$0")/wordlists/subdomain-bruteforce-medium.txt"
    if [ ! -f "$wordlist_path" ]; then
        wordlist_path="$(dirname "$0")/wordlists/subdomain-bruteforce-extended.txt"
    fi
    if [ ! -f "$wordlist_path" ]; then
        wordlist_path="$(dirname "$0")/wordlists/subdomain-bruteforce.txt"
    fi

    if [ ! -f "$wordlist_path" ]; then
        return 0
    fi

    echo "[+] VHost Discovery with ffuf..."
    mkdir -p "$url/vhost"

    # CDN Detection helper function
    check_cdn() {
        local target=$1
        local headers=$(curl -sI "$target" 2>/dev/null | grep -iE 'cloudflare|akamai|fastly|cloudfront|imperva|sucuri')

        if [ -n "$headers" ]; then
            echo "1"  # CDN detected
        else
            echo "0"  # No CDN
        fi
    }

    local vhost_count=0
    local host_count=0

    # Process each alive host
    while IFS= read -r host; do
        ((host_count++))

        # Skip if more than 5 hosts (prevent excessive scanning)
        if [ $host_count -gt 5 ]; then
            echo "    [!] Limiting VHost scan to first 5 hosts to prevent blocks"
            break
        fi

        # CDN detection
        local has_cdn=$(check_cdn "$host")
        local rate=5  # Conservative default

        if [ "$has_cdn" = "0" ]; then
            rate=15  # Slightly higher rate if no CDN
        fi

        echo "    [*] VHost scanning: $host (rate: $rate req/sec)"

        # Run ffuf with safety features
        ffuf -c -r \
            -u "$host" \
            -H "Host: FUZZ.$url" \
            -w "$wordlist_path" \
            -mc 200,403,401,500 \
            -fs 0 \
            -rate $rate \
            -t 10 \
            -ac \
            -o "$url/vhost/vhost_$(echo "$host" | sed 's/[^a-zA-Z0-9]/_/g').json" \
            -of json \
            -s 2>/dev/null

        # Extract discovered vhosts from JSON
        if [ -f "$url/vhost/vhost_$(echo "$host" | sed 's/[^a-zA-Z0-9]/_/g').json" ]; then
            jq -r '.results[]?.input.FUZZ' "$url/vhost/vhost_$(echo "$host" | sed 's/[^a-zA-Z0-9]/_/g').json" 2>/dev/null | \
                sed "s/$/./" | sed "s/\.$/$url/" >> "$url/vhost/vhost-discovered.txt"
        fi

    done < "$url/httpx/alive.txt"

    # Merge and deduplicate results
    if [ -f "$url/vhost/vhost-discovered.txt" ]; then
        sort -u "$url/vhost/vhost-discovered.txt" -o "$url/vhost/vhost-discovered.txt"
        vhost_count=$(wc -l < "$url/vhost/vhost-discovered.txt" 2>/dev/null | tr -d ' ')
    fi

    echo "    [-] VHost Discovery Completed: $vhost_count vhosts found"
}

# Archive scan with waybackurls
archieve_scan() {
    if ! command -v waybackurls &>/dev/null; then
        echo "[+] Skipping archive scan (waybackurls not found)"
        return 0
    fi

    echo "[+] Scrapping URLs from Wayback Machine..."
    cd "$url/wayback/" || return

    # Clean up old files
    rm -f allfiles.txt uniq_files.txt wayback_only_html.txt wayback_js_files.txt \
          wayback_json_files.txt important_http_urls.txt aws_s3_files.txt

    # Collect URLs
    waybackurls "$url" > allfiles.txt 2>/dev/null
    command -v gau &>/dev/null && gau "$url" >> allfiles.txt 2>/dev/null

    sort -u allfiles.txt > uniq_files.txt

    # Process URLs
    grep -ivE '\.(js|png|jpg|gif|ico|img|css)$' uniq_files.txt > wayback_only_html.txt 2>/dev/null
    grep '\.js' uniq_files.txt | sort -u > wayback_js_files.txt 2>/dev/null
    grep '\.json' uniq_files.txt | sort -u > wayback_json_files.txt 2>/dev/null
    grep -iE 'admin|auth|api|jenkins|corp|dev|stag|stg|prod|sandbox|swagger|aws|azure|uat|test|vpn|cms' wayback_only_html.txt > important_http_urls.txt 2>/dev/null
    grep -iE 'aws|s3' uniq_files.txt > aws_s3_files.txt 2>/dev/null

    cd - >/dev/null
    echo "    [-] Archive Scan Completed"
}

# Main execution
find_subdomains() {
    # Phase 1: Passive Discovery (run all tools in parallel)
    subdomain_assetfinder &
    subdomain_findomain &
    subdomain_subfinder &
    subdomain_vita &
    subdomain_chaos &
    subdomain_amass &
    subdomain_cero &
    subdomain_github &
    subdomain_misc &

    # Wait for all passive discovery to complete
    wait

    # Phase 2: DNS Bruteforce (run both DNSx and PureDNS in parallel)
    subdomain_dnsx_bruteforce &
    subdomain_puredns &
    wait

    # Phase 3: Subdomain Permutations (sequential - needs discovered subdomains)
    subdomain_permutations

    # Phase 4: Validation (sequential - validates all discovered + bruteforced + permuted)
    subdomain_validation

    # Phase 5: Final Merge (uses validated list if available)
    subdomain_merge

    # Phase 6: Subdomain Takeover Check
    subdomain_takeover
}

# Execute pipeline
echo ""
find_subdomains
port_scan_naabu
probe_subdomains
vhost_bruteforce
nuclei_scan

echo ""
echo "-------------------------------"
echo " [-]--- Recon Completed ---[-]"
echo "-------------------------------"
