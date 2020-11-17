#!/bin/bash

source ~/.profile

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
ffuf -w wordlists/subdomains.txt -u "https://FUZZ.$url/" -v | grep "| $url |" | awk '{print $4}'
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

#Run Chaos
echo "[+] Harvesting subdomains with Chaos..."

chaos -d $url --silent | grep $url >> $url/subdomains/chaos.txt
uniq $url/subdomains/chaos.txt > $url/subdomains/c-temp.txt
sort $url/subdomains/c-temp.txt > $url/subdomains/chaos.txt
rm $url/subdomains/c-temp.txt
subcount=$(wc -l $url/subdomains/chaos.txt | awk '{print $1}')
echo "    [-] Subdomains Found with Chaos: $subcount "

#Run Assetfinder
echo "[+] Harvesting subdomains with Assetfinder..."

assetfinder $url | grep $url >> $url/subdomains/assetfinder.txt
uniq $url/subdomains/assetfinder.txt > $url/subdomains/a-temp.txt
sort $url/subdomains/a-temp.txt > $url/subdomains/assetfinder.txt
rm $url/subdomains/a-temp.txt
subcount=$(wc -l $url/subdomains/assetfinder.txt | awk '{print $1}')
echo "    [-] Subdomains Found with Assetfinder: $subcount "

#Run Subfinder
echo "[+] Harvesting subdomains with Findomain..."

~/./tools/findomain -t $url --threads 25 -u $url/subdomains/findomain.txt > /dev/null
uniq $url/subdomains/findomain.txt > $url/subdomains/f-temp.txt
sort $url/subdomains/f-temp.txt > $url/subdomains/findomain.txt
rm $url/subdomains/f-temp.txt
subcount=$(wc -l $url/subdomains/findomain.txt | awk '{print $1}')
echo "    [-] Subdomains Found with Findomain: $subcount "


#Run Subfinder
echo "[+] Harvesting subdomains with Subfinder..."

subfinder -d $url -silent | grep $url >> $url/subdomains/subfinder.txt
uniq $url/subdomains/subfinder.txt > $url/subdomains/s-temp.txt
sort $url/subdomains/s-temp.txt > $url/subdomains/subfinder.txt
rm $url/subdomains/s-temp.txt
subcount=$(wc -l $url/subdomains/subfinder.txt | awk '{print $1}')
echo "    [-] Subdomains Found with Subfinder: $subcount "

#Run Amass
#echo "[+] Harvesting subdomains with Amass..."
#amass enum -d $url >> $url/subdomains/amass.txt
#sort -u $url/subdomains/f.txt >> $url/subdomains/final.txt
#rm $url/subdomains/f.txt

#Bruteforce Subdomains
echo "[+] Bruteforcing Subdomains with FFuF..."
#ffuf -w wordlists/subdomains.txt -u "https://FUZZ.$url/" -v | grep "| $url |" | awk '{print $4}'

#Combine Subdomains
echo "[+] Merging all the subdomains..."

cat $url/subdomains/*.txt > $url/subdomains/subdomains.txt
cat $url/subdomains/subdomains.txt | sort | uniq > $url/subdomains/temp-s.txt
mv $url/subdomains/temp-s.txt $url/subdomains/subdomains.txt
subcount=$(wc -l $url/subdomains/subdomains.txt | awk '{print $1}')
echo "    [*] Total No of Subdomains Identified: $subcount "

#Perform Subdomain Takeover with Nuclei
echo "[+] Performing Subdomain Takeover with Nuclei "
cat $url/subdomains/subdomains.txt | nuclei -t subdomain-takeover/ -o $url/potential_takeovers/nuclei.txt -silent

#Perform Subdomain Takeover
echo "[+] Performing Subdomain Takeover with Subzy "
subzy --targets=$url/subdomains/subdomains.txt --concurrency 25 --hide_fails --https > $url/potential_takeovers/subzy.txt

#To Do: Print Only the vulnerable ones

echo "[+] Performing Subdomain Takeover with Subjack "
subjack -w $url/subdomains/subdomains.txt  -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3 -o $url/potential_takeovers/takeover.txt > $url/potential_takeovers/subjack.txt

#Perform Subdomain Takeover
echo "[+] Probing for alive domains..."
cat $url/subdomains/subdomains.txt | httpx -silent > $url/httpx/alive.txt
alivec=$(wc -l $url/httpx/alive.txt | awk '{print $1}')
echo "    [*] Total No of Alive Subdomains Identified: $alivec "

#Print Only the vulnerable ones
echo "[+] Scanning for known CVE with Nuclei "
cat $url/httpx/alive.txt | nuclei -t cves/ -o $url/nuclei/cve.txt -silent

#Run RustScan on all Alive Subdomains
echo "[+] Performing Portscan on $alivec Alive Subdomains..."
cat $url/httpx/alive.txt | sed 's/https\?:\/\///'  > $url/scans/nmap-temp.txt
input="$url/scans/nmap-temp.txt"
while IFS= read -r alivesubs
do
  rustscan --range 1-10000 $alivesubs --ulimit 5000 -- -n -sV -Pn -oN $url/scans/$alivesubs
done < "$input"

#==============================
#Wayback Scan:
#==============================

cd $url/wayback/

rm -f allfiles.txt uniq_files.txt wayback_only_html.txt wayback_js_files.txt wayback_httprobe_file.txt wayback_json_files.txt important_http_urls.txt aws_s3_files.txt

echo "[+] Scrapping URLs from Wayback Machine"

waybackurls $url >> allfiles.txt
gau $url >> allfiles.txt

#echo "Waybackurls extraction is complete!!"
sort -ru allfiles.txt >> uniq_files.txt
grep -iv -E — '.js|.png|.jpg|.gif|.ico|.img|.css' uniq_files.txt >> wayback_only_html.txt
cat uniq_files.txt | grep "\.js" | uniq | sort >> wayback_js_files.txt
cat uniq_files.txt | grep "\.json" | uniq | sort >> wayback_json_files.txt
grep --color=always -i -E  'admin|auth|api|jenkins|corp|dev|stag|stg|prod|sandbox|swagger|aws|azure|uat|test|vpn|cms' wayback_only_html.txt >> important_http_urls.txt
grep --color=always -i -E  'aws|s3' uniq_files.txt >> aws_s3_files.txt
#echo "cat wayback_only_html.txt | aquatone -threads 20"
cd ../../
echo "==============================="
echo " [-]--- Recon Completed ---[-]"
echo "==============================="
