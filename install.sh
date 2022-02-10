#!/bin/bash


# Pending tool list
#Chaos Findomain Nuclei-templates Subzy
#Install GoLang

wget -q -O - https://git.io/vQhTU | bash
sudo apt-get install jq python python3 python3-pip grepcidr brutespray amass git nmap tmux screen -y 

pip install shodan

#subfinder
GO111MODULE=on go get -u -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder

#assetfinder
go get -u github.com/tomnomnom/assetfinder

#chaos
GO111MODULE=on go get -u github.com/projectdiscovery/chaos-client/cmd/chaos

#findomain
wget https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux
mv findomain-linux findomain
chmod +x findomain
sudo mv findomain /usr/bin/

#zcat
#goaltdns
go install -v github.com/subfinder/goaltdns@latest

#shuffledns
GO111MODULE=on go get -u -v github.com/projectdiscovery/shuffledns/cmd/shuffledns

#dnsprobe
GO111MODULE=on go get -u -v github.com/projectdiscovery/dnsprobe

#Nuclei
GO111MODULE=auto go get -u -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei

#ffuf
go get -u github.com/ffuf/ffuf

#cf-check
go get -u github.com/dwisiswant0/cf-check

#httpx
GO111MODULE=on go get -u -v github.com/projectdiscovery/httpx/cmd/httpx

#tko-subs
go get github.com/anshumanbh/tko-subs

#subjack
go get github.com/haccer/subjack

#aquatone

#webanalyze
go install -v github.com/rverton/webanalyze/cmd/webanalyze@latest

#gau
GO111MODULE=on go get -u -v github.com/lc/gau

#getching
go install -v github.com/phspade/getching@latest

#kxss
go install -v github.com/Emoe/kxss@latest

#Waybackurls
go install -v github.com/tomnomnom/waybackurls@latest

# Install QSReplace
go install -v github.com/tomnomnom/qsreplace@latest

#dalfox
go install -v github.com/hahwul/dalfox@latest

#Nuclei-Templates
git clone https://github.com/projectdiscovery/nuclei-templates.git -o ~/


# Install GF Pattern
go get -u github.com/tomnomnom/gf
echo 'source $GOPATH/src/github.com/tomnomnom/gf/gf-completion.bash' >> ~/.bashrc
cp -r $GOPATH/src/github.com/tomnomnom/gf/examples ~/.gf
git clone https://github.com/1ndianl33t/Gf-Patterns
mv ~/Gf-Patterns/*.json ~/.gf
rm -r Gf-Patterns/
