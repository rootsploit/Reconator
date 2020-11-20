#!/bin/bash

#Install GoLang
wget -q -O - https://git.io/vQhTU | bash
sudo apt-get install jq grepcidr brutespray amass git nmap tmux screen -y 

pip install shodan

#subfinder
GO111MODULE=on go get -u -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder

#assetfinder
go get -u github.com/tomnomnom/assetfinder

#zcat
#goaltdns
go get github.com/subfinder/goaltdns

#shuffledns
GO111MODULE=on go get -u -v github.com/projectdiscovery/shuffledns/cmd/shuffledns

#dnsprobe
GO111MODULE=on go get -u -v github.com/projectdiscovery/dnsprobe

#Nuclei
GO111MODULE=auto go get -u -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei

#ffuf
go get -u github.com/ffuf/ffuf

#httpx
GO111MODULE=on go get -u -v github.com/projectdiscovery/httpx/cmd/httpx

#tko-subs
go get github.com/anshumanbh/tko-subs

#subjack
go get github.com/haccer/subjack

#aquatone

#webanalyze
go get -v -u github.com/rverton/webanalyze/cmd/webanalyze

#gau
GO111MODULE=on go get -u -v github.com/lc/gau

#getching
go get -u github.com/phspade/getching

#kxss
go get github.com/Emoe/kxss

#Waybackurls
go get github.com/tomnomnom/waybackurls

# Install QSReplace
go get -u github.com/tomnomnom/qsreplace

#dalfox
go get -u github.com/hahwul/dalfox

#Nuclei-Templates
git clone https://github.com/projectdiscovery/nuclei-templates.git -o ~/

#zdns
git clone https://github.com/zmap/zdns.git
cd zdns
go build
cd ..


# Install GF Pattern
go get -u github.com/tomnomnom/gf
echo 'source $GOPATH/src/github.com/tomnomnom/gf/gf-completion.bash' >> ~/.bashrc
cp -r $GOPATH/src/github.com/tomnomnom/gf/examples ~/.gf
git clone https://github.com/1ndianl33t/Gf-Patterns
mv ~/Gf-Patterns/*.json ~/.gf
rm -r Gf-Patterns/
