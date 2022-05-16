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
        findomain -t $url --threads 25 -u $url/subdomains/findomain.txt >> /dev/null 2>&1
        uniq $url/subdomains/findomain.txt > $url/subdomains/f-temp.txt
        sort $url/subdomains/f-temp.txt > $url/subdomains/findomain.txt
        rm $url/subdomains/f-temp.txt
        subcount=$(wc -l $url/subdomains/findomain.txt | awk '{print $1}')
        echo "    [-] Subdomains Found with Findomain: $subcount "
}

#Run Subfinder
subdomain_subfinder(){
        echo "[+] Harvesting subdomains with Subfinder..."
        subfinder -d $url -silent | grep $url >> $url/subdomains/subfinder.txt
        uniq $url/subdomains/subfinder.txt > $url/subdomains/s-temp.txt
        sort $url/subdomains/s-temp.txt > $url/subdomains/subfinder.txt
        rm $url/subdomains/s-temp.txt
        subcount=$(wc -l $url/subdomains/subfinder.txt | awk '{print $1}')
        echo "    [-] Subdomains Found with Subfinder: $subcount "
}

subdomain_misc(){

#SubMisc-Code
curl --silent https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$url | grep -o -E "[a-zA-Z0-9._-]+\.$1" > $url/subdomains/misc-tmp.txt
curl --silent https://api.hackertarget.com/hostsearch/?q=$1 | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> $url/subdomains/misc-tmp.txt
curl --silent https://crt.sh/?q=%.$1  | grep -oP "\<TD\>\K.*\.$1" | sed -e 's/\<BR\>/\n/g' | grep -oP "\K.*\.$1" | sed -e 's/[\<|\>]//g' | grep -o -E "[a-zA-Z0-9._-]+\.$1"  >> $url/subdomains/misc-tmp.txt
curl --silent https://crt.sh/?q=%.%.$1 | grep -oP "\<TD\>\K.*\.$1" | sed -e 's/\<BR\>/\n/g' | sed -e 's/[\<|\>]//g' | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> $url/subdomains/misc-tmp.txt
curl --silent https://crt.sh/?q=%.%.%.$1 | grep "$1" | cut -d '>' -f2 | cut -d '<' -f1 | grep -v " " | grep -o -E "[a-zA-Z0-9._-]+\.$1" | sort -u >> $url/subdomains/misc-tmp.txt
curl --silent https://crt.sh/?q=%.%.%.%.$1 | grep "$1" | cut -d '>' -f2 | cut -d '<' -f1 | grep -v " " | grep -o -E "[a-zA-Z0-9._-]+\.$1" |  sort -u >> $url/subdomains/misc-tmp.txt
curl --silent https://certspotter.com/api/v0/certs?domain=$1 | grep  -o '\[\".*\"\]' | sed -e 's/\[//g' | sed -e 's/\"//g' | sed -e 's/\]//g' | sed -e 's/\,/\n/g' | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> $url/subdomains/misc-tmp.txt
curl --silent https://spyse.com/target/domain/$1 | grep -E -o "button.*>.*\.$1\/button>" |  grep -o -E "[a-zA-Z0-9._-]+\.$1" >> $url/subdomains/misc-tmp.txt
curl --silent https://tls.bufferover.run/dns?q=$1 | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> $url/subdomains/misc-tmp.txt
curl --silent https://dns.bufferover.run/dns?q=.$1 | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> $url/subdomains/misc-tmp.txt
curl --silent https://urlscan.io/api/v1/search/?q=$1 | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> $url/subdomains/misc-tmp.txt
curl --silent -X POST https://synapsint.com/report.php -d "name=http%3A%2F%2F$1" | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> $url/subdomains/misc-tmp.txt
curl --silent https://jldc.me/anubis/subdomains/$1 | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" >> $url/subdomains/misc-tmp.txt
curl --silent https://sonar.omnisint.io/subdomains/$1 | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> $url/subdomains/misc-tmp.txt
curl --silent https://otx.alienvault.com/api/v1/indicators/domain/$1/passive_dns | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> $url/subdomains/misc-tmp.txt
curl --silent https://riddler.io/search/exportcsv?q=pld:$1 | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> $url/subdomains/misc-tmp.txt

cat $url/subdomains/misc-tmp.txt | sort -u | grep $url > tmp.txt
cp $url/subdomains/misc-tmp.txt $url/subdomains/tmp.txt

if [[ $# -eq 2 ]]; then
    cat $url/subdomains/tmp.txt | sed -e "s/\*\.$1//g" | sed -e "s/^\..*//g" | grep -o -E "[a-zA-Z0-9._-]+\.$1" | sort -u > $2
else
    cat $url/subdomains/tmp.txt | sed -e "s/\*\.$1//g" | sed -e "s/^\..*//g" | grep -o -E "[a-zA-Z0-9._-]+\.$1" | sort -u
fi
rm -f $url/subdomains/tmp.txt
#End of SubMis Code

#Bufferover
curl -s https://dns.bufferover.run/dns?q=.$url |jq -r .FDNS_A[]|cut -d',' -f2|sort -u >> $url/subdomains/misc-subs.txt

#Riddler.io
curl -s "https://riddler.io/search/exportcsv?q=pld:$url" | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u >> $url/subdomains/misc-subs.txt

curl -s "https://www.virustotal.com/ui/domains/$url/subdomains?limit=40" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u >> $url/subdomains/misc-subs.txt

curl -s "http://web.archive.org/cdx/search/cdx?url=*.$url/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" | sort -u >> $url/subdomains/misc-subs.txt

curl -s "https://rapiddns.io/subdomain/$url?full=1#result" | grep "<td><a" | cut -d '"' -f 2 | grep http | cut -d '/' -f3 | sed 's/#results//g' | sort -u >> $url/subdomains/misc-subs.txt

cat $url/subdomains/misc-subs.txt | sort -u | grep $url > $url/subdomains/misc-temp.txt
mv $url/subdomains/misc-temp.txt $url/subdomains/misc-subs.txt

}

#Run Amass
subdomain_amass(){
        echo "[+] Harvesting subdomains with Amass..."
        amass enum -d $url >> $url/subdomains/amass.txt
        sort -u $url/subdomains/f.txt >> $url/subdomains/final.txt
        rm $url/subdomains/f.txt
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

#Probing Live Domains
probe_subdomains(){
        echo "[+] Probing for alive domains..."
        cat $url/subdomains/subdomains.txt | httpx -threads 200 -silent > $url/httpx/alive.txt
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

find_subdomains(){
        subdomain_chaos &
        subdomain_assetfinder &
        subdomain_findomain &
        subdomain_subfinder &
        subdomain_misc &
        #subdomain_amass
        #subdomain_ffufbrute
        wait
        subdomain_merge
        probe_subdomains
        subdomain_takeover
}

find_subdomains
nuclei_scan
portscan_scan
#archieve_scan

echo "-------------------------------"
echo " [-]--- Recon Completed ---[-]"
echo "-------------------------------"
