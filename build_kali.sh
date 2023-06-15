apt update
apt upgrade -y
apt dist-upgrade -y
apt install kali-linux-everything docker.io python3-poetry -y
curl -L https://github.com/Porchetta-Industries/CrackMapExec/releases/download/v5.4.0/cme-ubuntu-latest-3.11.zip > /opt/cme.zip
unzip /opt/cme.zip
rm /opt/cme.zip
dpkg --add-architecture i386
apt-get update
apt-get install wine32:i386
git clone https://github.com/NSAKEY/nsa-rules.git /opt/nsa-rules
git clone https://github.com/S3cur3Th1sSh1t/PowerSharpPack.git /opt/PowerSharpPack
git clone https://github.com/Flangvik/SharpCollection.git /opt/SharpCollection
git clone https://github.com/andrew-d/static-binaries.git /opt/static-binaries
git clone https://github.com/nettitude/PoshC2.git /opt/PoshC2
git clone --recurse-submodules https://github.com/cobbr/Covenant /opt/Covenant
mkdir /opt/static-impacket
cd /opt/static-impacket
curl -LJO "https://api.github.com/repos/ropnop/impacket_static_binaries/releases/latest"
ASSET_URLS=$(jq -r '.assets[].browser_download_url' latest)
for url in $ASSET_URLS; do
  curl -LOJ $url
done
rm latest
cd ~
curl -L https://github.com/carlospolop/PEASS-ng/releases/download/20230611-b11e87f7/winPEAS.bat > /opt/winPEAS.bat
curl -L https://github.com/carlospolop/PEASS-ng/releases/download/20230611-b11e87f7/linpeas.sh > /opt/linpeas.sh
curl -L https://github.com/jpillora/chisel/releases/download/v1.8.1/chisel_1.8.1_linux_amd64.gz > /opt/chisel.gz
gzip /opt/chisel.gz
curl -L https://github.com/jpillora/chisel/releases/download/v1.8.1/chisel_1.8.1_windows_amd64.gz > /opt/chiselwin.gz
gzip /opt/chiselwin.gz
gzip -d /usr/share/wordlists/rockyou.txt.gz
git clone /opt/https://github.com/tmux-plugins/tmux-logging.git /opt/tmux-logging
