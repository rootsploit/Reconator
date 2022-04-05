#!/bin/bash

source ~/.profile
source ~/.bash_profile
source ~/.bashrc

<<'Comment'

Methodology:
1.Enumerate Sub-Domains: chaos,subfinder,assetfinder
2.Bruteforce Subdomains with FFuF and amass
3.Run multiple subdomains takeover tools: Proper Output for it
4.Find live domains with HTTPx
5.Vulnerability Scanner > S3 Bucket, CORS, Smuggling
6.Fingerprinting Version/CVE based on Nuclei
7.Aquatone results and download to local system

To-Do:
1.Shodan Censys API implementation
2.Rustscan or PD Scan on ports
3.Project Sonar IP List
4.CloudFlare Detection

12 secs with Nmap and service version:
rustscan scanme.nmap.org --ulimit 5000 -- -n -sV -Pn 
20 secs without Nmap
naabu -host scanme.nmap.org -p - -verify -nmap 

echo hackerone.com | naabu -silent | httpx -silent
List Scan
rustscan list --ulimit 5000 -- -sV -n -Pn -oN new

Automate:
rustscan $subdomain --ulimit 5000 -- -n -sV -Pn -oN $subdomain

input="$url/subdomains/subdomains.txt"
while IFS= read -r subdomain
do
  rustscan $subdomain --ulimit 5000 -- -n -sV -Pn -oN $subdomain
done < "$input"

Wordlists:
Seclist
Random Robbie bruteforce
All.txxt jason
ffuf -w wordlists/subdomains.txt -u "https://FUZZ.$url/" -v | grep "$url" | awk '{print $4}'
Chaospy

Comment

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



#Performing Nuclei Scan
nuclei_scan(){
        nuclei -update-templates -silent
        echo "[+] Scanning for known CVE with Nuclei "
        cat $url/httpx/alive.txt | nuclei -c 200 -t cves/ -o $url/nuclei/cves.txt -silent 
        cat $url/httpx/alive.txt | nuclei -c 200 -t vulnerabilities/ -o $url/nuclei/vulnerabilities.txt -silent 
        cat $url/httpx/alive.txt | nuclei -c 200 -t security-misconfiguration/ -o $url/nuclei/security-misconfiguration.txt -silent 
        cat $url/httpx/alive.txt | nuclei -c 200 -t default-credentials/ -o $url/nuclei/default-creds.txt -silent 
        cat $url/httpx/alive.txt | nuclei -c 200 -t tokens/ -o $url/nuclei/tokens.txt -silent 
        cat $url/httpx/alive.txt | nuclei -c 200 -t panels/ -o $url/nuclei/panels.txt -silent 
        cat $url/httpx/alive.txt | nuclei -c 200 -t files/ -o $url/nuclei/files.txt -silent 
        wait
        echo "[+] Scanning with Nuclei Completed "
}

#Run RustScan on all Alive Subdomains
port_scan(){
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

nuclei_scan
#portscan_scan
#archieve_scan

echo "-------------------------------"
echo " [-]--- Recon Completed ---[-]"
echo "-------------------------------"
