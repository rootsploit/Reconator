#!/bin/bash
 
source ~/.profile
source ~/.bash_profile
 
url=$1
 
if [ ! -d "$url" ];then
        mkdir $url
fi
 
if [ ! -d "$url/subdomains" ];then
        mkdir $url/subdomains
fi
 
if [ ! -d "$url/potential_takeovers" ];then
        mkdir $url/potential_takeovers
fi
 
if [ ! -d "$url/wayback" ];then
        mkdir $url/wayback
fi
 
if [ ! -d "$url/httpx" ];then
        mkdir $url/httpx
fi
 
if [ ! -d "$url/scans" ];then
        mkdir $url/scans
fi
 
if [ ! -d "$url/nuclei/" ];then
        mkdir $url/nuclei/
fi
 
echo "                                                                                ";
echo "                                                                                ";
echo " ██▀███  ▓█████  ▄████▄   ▒█████   ███▄    █  ▄▄▄     ▄▄▄█████▓ ▒█████   ██▀███  ";
echo "▓██ ▒ ██▒▓█   ▀ ▒██▀ ▀█  ▒██▒  ██▒ ██ ▀█   █ ▒████▄   ▓  ██▒ ▓▒▒██▒  ██▒▓██ ▒ ██▒";
echo "▓██ ░▄█ ▒▒███   ▒▓█    ▄ ▒██░  ██▒▓██  ▀█ ██▒▒██  ▀█▄ ▒ ▓██░ ▒░▒██░  ██▒▓██ ░▄█ ▒";
echo "▒██▀▀█▄  ▒▓█  ▄ ▒▓▓▄ ▄██▒▒██   ██░▓██▒  ▐▌██▒░██▄▄▄▄██░ ▓██▓ ░ ▒██   ██░▒██▀▀█▄  ";
echo "░██▓ ▒██▒░▒████▒▒ ▓███▀ ░░ ████▓▒░▒██░   ▓██░ ▓█   ▓██▒ ▒██▒ ░ ░ ████▓▒░░██▓ ▒██▒";
echo "░ ▒▓ ░▒▓░░░ ▒░ ░░ ░▒ ▒  ░░ ▒░▒░▒░ ░ ▒░   ▒ ▒  ▒▒   ▓▒█░ ▒ ░░   ░ ▒░▒░▒░ ░ ▒▓ ░▒▓░";
echo "  ░▒ ░ ▒░ ░ ░  ░  ░  ▒     ░ ▒ ▒░ ░ ░░   ░ ▒░  ▒   ▒▒ ░   ░      ░ ▒ ▒░   ░▒ ░ ▒░";
echo "  ░░   ░    ░   ░        ░ ░ ░ ▒     ░   ░ ░   ░   ▒    ░      ░ ░ ░ ▒    ░░   ░ ";
echo "   ░        ░  ░░ ░          ░ ░           ░       ░  ░            ░ ░     ░     ";
echo "                ░                                                                ";
echo "                                                      - By @RootSploit           ";
echo "                                                                                 ";
 
#Run Chaos
subdomain_chaos(){
        echo "[+] Harvesting subdomains with Chaos..."
        chaos -d $url --silent | grep $url >> $url/subdomains/chaos.txt
        uniq $url/subdomains/chaos.txt > $url/subdomains/c-temp.txt
        sort $url/subdomains/c-temp.txt > $url/subdomains/chaos.txt
        rm $url/subdomains/c-temp.txt
        subcount=$(wc -l $url/subdomains/chaos.txt | awk '{print $1}')
        echo "    [-] Subdomains Found with Chaos: $subcount "
}
 
#Run Assetfinder
subdomain_assetfinder(){
        echo "[+] Harvesting subdomains with Assetfinder..."
        assetfinder $url | grep $url >> $url/subdomains/assetfinder.txt
        uniq $url/subdomains/assetfinder.txt > $url/subdomains/a-temp.txt
        sort $url/subdomains/a-temp.txt > $url/subdomains/assetfinder.txt
        rm $url/subdomains/a-temp.txt
        subcount=$(wc -l $url/subdomains/assetfinder.txt | awk '{print $1}')
        echo "    [-] Subdomains Found with Assetfinder: $subcount "
}
 
#Run Findomain
subdomain_findomain(){
        echo "[+] Harvesting subdomains with Findomain..."
        findomain -t $url --threads 25 -u $url/subdomains/findomain.txt --quiet
        uniq $url/subdomains/findomain.txt > $url/subdomains/f-temp.txt
        sort $url/subdomains/f-temp.txt > $url/subdomains/findomain.txt
        rm $url/subdomains/f-temp.txt
        subcount=$(wc -l $url/subdomains/findomain.txt | awk '{print $1}')
        echo "    [-] Subdomains Found with Findomain: $subcount "
        #echo "[+]Find Domain Done"
}
 
#Run Subfinder
subdomain_subfinder(){
        echo "[+] Harvesting subdomains with Subfinder..."
        subfinder -d $url -silent -all -t 25 | grep $url >> $url/subdomains/subfinder.txt
        uniq $url/subdomains/subfinder.txt > $url/subdomains/s-temp.txt
        sort $url/subdomains/s-temp.txt > $url/subdomains/subfinder.txt
        rm $url/subdomains/s-temp.txt
        subcount=$(wc -l $url/subdomains/subfinder.txt | awk '{print $1}')
        echo "    [-] Subdomains Found with Subfinder: $subcount "
}

subdomain_vita(){
        echo "[+] Harvesting subdomains with Vita..."
        vita -d $url -a --subs-only | grep $url >> $url/subdomains/vita.txt
        uniq $url/subdomains/vita.txt > $url/subdomains/v-temp.txt
        sort $url/subdomains/v-temp.txt > $url/subdomains/vita.txt
        rm $url/subdomains/v-temp.txt
        subcount=$(wc -l $url/subdomains/vita.txt | awk '{print $1}')
        echo "    [-] Subdomains Found with Vita: $subcount "
}

subdomain_bbot(){
        echo "[+] Harvesting subdomains with BBOT..."
        bbot -t $url -f subdomain-enum -c excavate=true &>/dev/null
        cat ~/.bbot/scans/*/subdomains | grep $url > $url/subdomains/bbot-temp.txt
        sort $url/subdomains/bbot-temp.txt > $url/subdomains/vita.txt
        subcount=$(wc -l $url/subdomains/bbot.txt | awk '{print $1}')
        echo "    [-] Subdomains Found with BBOT: $subcount "
}


subdomain_misc(){
 
        echo "[+] Harvesting subdomains with 3rd Party APIs..."
#SubMisc-Code
#ThreatCrowd
        curl --silent "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$1" | grep -o -E "[a-zA-Z0-9._-]+\.$1" > tmp.txt
 
#HackerTarget
        curl --silent "https://api.hackertarget.com/hostsearch/?q=$1" | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> tmp.txt
 
#Cert.sh Enumeration
#1-level SubDomain
        curl --silent "https://crt.sh/?q=%.$1" | grep "$1" | cut -d '>' -f2 | cut -d '<' -f1 | grep -v " " | grep -o -E "[a-zA-Z0-9._-]+\.$1" | sort -u >> tmp.txt
#2-level SubDomain
        curl --silent "https://crt.sh/?q=%.%.$1" | grep "$1" | cut -d '>' -f2 | cut -d '<' -f1 | grep -v " " | grep -o -E "[a-zA-Z0-9._-]+\.$1" | sort -u >> tmp.txt
#3-level subdomain
        curl --silent "https://crt.sh/?q=%.%.%.$1" | grep "$1" | cut -d '>' -f2 | cut -d '<' -f1 | grep -v " " | grep -o -E "[a-zA-Z0-9._-]+\.$1" | sort -u >> tmp.txt
#4-level subdomain
        curl --silent "https://crt.sh/?q=%.%.%.%.$1" | grep "$1" | cut -d '>' -f2 | cut -d '<' -f1 | grep -v " " | grep -o -E "[a-zA-Z0-9._-]+\.$1" |  sort -u >> tmp.txt
        curl --silent "https://urlscan.io/api/v1/search/?q=$1" | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> tmp.txt
        curl --silent "https://sonar.omnisint.io/subdomains/$1" | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> tmp.txt
        curl --silent "https://otx.alienvault.com/api/v1/indicators/domain/$1/passive_dns" | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> tmp.txt
        curl --silent "https://riddler.io/search/exportcsv?q=pld:$1" | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> tmp.txt
 
#Bufferover
        curl --silent "https://dns.bufferover.run/dns?q=.$url" | jq -r ".FDNS_A[]" |cut -d ',' -f2 | sort -u >> tmp.txt

# JLDC
        curl -s https://jldc.me/anubis/subdomains/$url | jq '.[]' | sort -u  | tr --delete '"' | uniq >> tmp.txt
 
        uniq tmp.txt > tmp2.txt
        sort -u tmp2.txt > $url/subdomains/misc-subs.txt


 
        subcount=$(wc -l $url/subdomains/misc-subs.txt | awk '{print $1}')
        echo "    [-] Subdomains Found with 3rd Party APIs: $subcount"
 
}
 
#Run Amass
subdomain_amass(){
        echo "[+] Harvesting subdomains with Amass..."
        amass enum -silent -d $url -o $url/subdomains/amass-temp.txt
        sort -u $url/subdomains/amass-temp.txt >> $url/subdomains/amass.txt
        rm $url/subdomains/amass-temp.txt
        subcount=$(wc -l $url/subdomains/amass.txt | awk '{print $1}')
        echo "    [-] Subdomains Found with Amass: $subcount"
}
 
#Bruteforce Subdomains
subdomain_ffufbrute(){
        echo "[+] Bruteforcing Subdomains with FFuF..."
        ffuf -w wordlists/subdomains.txt -u "https://FUZZ.$url/" -v | grep $url | awk '{print $4}'
}
 
#Combine Subdomains
subdomain_merge(){
        echo "[+] Merging all the subdomains..."
        cat $url/subdomains/*.txt > $url/subdomains/temp-1.txt
        cat $url/subdomains/temp-1.txt | sort -ru > $url/subdomains/temp-2.txt
        cp $url/subdomains/temp-2.txt $url/subdomains/subdomains.txt
        rm $url/subdomains/temp-1.txt $url/subdomains/temp-2.txt
        subcount=$(wc -l $url/subdomains/subdomains.txt | awk '{print $1}')
        echo "    [*] Total No of Subdomains Identified: $subcount "
}

#DNS Permutations

#Run Naab on all Alive Subdomains
port_scan_naabu(){
        echo "[+] Performing Portscan on Subdomains..."
        naabu -c 250 -l subdomains/subdomains.txt -port 3000,5000,8080,8000,8081,8888,8069,8009,8001,8070,8088,8002,8060,8091,8086,8010,8050,8085,8089,8040,8020,8051,8087,8071,8011,8030,8061,8072,8100,8083,8073,8099,8092,8074,8043,8035,8055,8021,8093,8022,8075,8044,8062,8023,8094,8012,8033,8063,8045,7000,9000,7070,9001,7001,10000,9002,7002,9003,7003,10001,80,443,4443 -o $url/scans/naabu_scans.txt

}
 
#Probing Live Domains
probe_subdomains(){
        echo "[+] Probing for alive domains..."
        cat $url/scans/naabu_scans.txt | httpx -threads 200 -silent > $url/httpx/alive.txt
        alivec=$(wc -l $url/httpx/alive.txt | awk '{print $1}')
        echo "    [*] Total No of Alive Subdomains Identified: $alivec "
}
 
subdomain_takeover(){
#Perform Subdomain Takeover with Nuclei
        nuclei -update-templates -silent
        echo "[+] Performing Subdomain Takeover "
        cat $url/httpx/alive.txt | nuclei -c 200 -t subdomain-takeover/ -o $url/potential_takeovers/nuclei.txt -silent  &
 
#Perform Subdomain Takeover with Subzy
        subzy --targets=$url/subdomains/subdomains.txt --concurrency 25 --hide_fails --https > $url/potential_takeovers/subzy.txt  &
 
#Perform Subdomain Takeover with Subjack
#To Do: Print Only the vulnerable ones
        subjack -w $url/subdomains/subdomains.txt  -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3 -o $url/potential_takeovers/takeover.txt > $url/potential_takeovers/subjack.txt  &
        wait
        echo "[+] Subdomain Takeover Scan Completed "
}
 
#Performing Nuclei Scan
nuclei_scan(){
        nuclei -update-templates -silent
        echo "[+] Scanning for known CVE with Nuclei "
        # cat $url/httpx/alive.txt | nuclei -c 200 -t cves/ -o $url/nuclei/cves.txt -silent
        # cat $url/httpx/alive.txt | nuclei -c 200 -t vulnerabilities/ -o $url/nuclei/vulnerabilities.txt -silent
        cat $url/httpx/alive.txt | nuclei -c 200 -t security-misconfiguration/ -o $url/nuclei/security-misconfiguration.txt -silent
        # cat $url/httpx/alive.txt | nuclei -c 200 -t default-credentials/ -o $url/nuclei/default-creds.txt -silent
        # cat $url/httpx/alive.txt | nuclei -c 200 -t tokens/ -o $url/nuclei/tokens.txt -silent
        cat $url/httpx/alive.txt | nuclei -c 200 -t panels/ -o $url/nuclei/panels.txt -silent
        cat $url/httpx/alive.txt | nuclei -c 200 -t files/ -o $url/nuclei/files.txt -silent
        # nuclei -rl 0 -bs 10000 -l 16_milion_list -id xxx -stats -elog errors.txt -stream -o output.txt -nh
        wait
        echo "[+] Scanning with Nuclei Completed "
}


 
#Run RustScan on all Alive Subdomains
port_scan_rust(){
        echo "[+] Performing Portscan on $alivec Alive Subdomains..."
        cat $url/httpx/alive.txt | sed 's/https\?:\/\///'  > $url/scans/nmap-temp.txt
        input="$url/scans/nmap-temp.txt"
        while IFS= read -r alivesubs
        do
        rustscan --range 1-10000 $alivesubs --ulimit 5000 -- -n -sV -Pn -oN $url/scans/$alivesubs
        done < "$input"
}
 
# Performing Scans with Waybackurls:
archieve_scan(){
        cd $url/wayback/
        rm -f allfiles.txt uniq_files.txt wayback_only_html.txt wayback_js_files.txt wayback_httprobe_file.txt wayback_json_files.txt important_http_urls.txt aws_s3_files.txt
        echo "[+] Scrapping URLs from Wayback Machine"
        waybackurls $url >> allfiles.txt
        gau $url >> allfiles.txt
        #gospider -a -w -s "$url" >> gospider.txt
        #cat gospider.txt | awk
        sort -ru allfiles.txt >> uniq_files.txt
        # Processing Waybackurls for sensitive keys/tokens
        grep -iv -E — '.js|.png|.jpg|.gif|.ico|.img|.css' uniq_files.txt >> wayback_only_html.txt
        cat uniq_files.txt | grep "\.js" | uniq | sort >> wayback_js_files.txt
        cat uniq_files.txt | grep "\.json" | uniq | sort >> wayback_json_files.txt
        grep --color=always -i -E  'admin|auth|api|jenkins|corp|dev|stag|stg|prod|sandbox|swagger|aws|azure|uat|test|vpn|cms' wayback_only_html.txt >> important_http_urls.txt
        grep --color=always -i -E  'aws|s3' uniq_files.txt >> aws_s3_files.txt
        #echo "cat wayback_only_html.txt | aquatone -threads 20"
        cd ../../
}
 
find_subdomains(){
        subdomain_assetfinder &
        subdomain_findomain &
        subdomain_subfinder &
        subdomain_vita &
        subdomain_misc &
        #subdomain_bbot &
        #subdomain_amass
        #subdomain_ffufbrute
        wait
        subdomain_merge
        subdomain_takeover
}
 
find_subdomains
archieve_scan
portscan_scan_naabu
probe_subdomains
nuclei_scan

 
echo "-------------------------------"
echo " [-]--- Recon Completed ---[-]"
echo "-------------------------------"
