# curl -fsSL https://download.docker.com/linux/debian/gpg | sudo apt-key add -
# echo 'deb [arch=amd64] https://download.docker.com/linux/debian buster stable' | sudo tee /etc/apt/sources.list.d/docker.list

banner "Updating: APT"
sudo apt -y update

banner "Running APT upgrade"
confirm "Upgrade all packages (Default: N) [y/n]? " \
    && sudo apt -y upgrade

banner "Disabling APT auto-updates"
confirm "Disable auto updates (Default: N) [y/n]? " \
    && (gsettings set org.gnome.software download-updates false; sed -i "s/1/0/g" /etc/apt/apt.conf.d/20auto-upgrades)

banner "Updating: mlocate database" 
updatedb

banner "Installing: pip2 and pip3" 
sudo wget https://bootstrap.pypa.io/get-pip.py
sudo python2 get-pip.py
sudo python3 get-pip.py
sudo rm get-pip.py

banner "Installing: git" 
sudo apt install --no-upgrade git

banner "Installing: unzip" 
sudo apt install --no-upgrade unzip

banner "Installing: winrar" 
sudo apt install --no-upgrade unrar

banner "Installing: ftp" 
sudo apt install --no-upgrade ftp

banner "Installing: mdbtools" 
sudo apt install --no-upgrade mdbtools

banner "Installing: nfs-common" 
sudo apt install --no-upgrade nfs-common

banner "Installing: rinetd - port forwarding tool" 
sudo apt install --no-upgrade rinetd

banner "Installing: httptunnel" 
sudo apt install --no-upgrade httptunnel
# victim: hts --forward-port localhost:8888 1234
# attacker: htc --forward-port 8080 10.11.0.128:1234

banner "Installing: mingw-w64" 
sudo apt install --no-upgrade mingw-w64

banner "Installing: libc6-dev-i386" 
sudo apt install --no-upgrade libc6-dev
sudo apt install --no-upgrade libc6-dev-i386 

# pyinstaller is not supported in kali-64 bit. Commenting this until there is another option.
#banner "Installing: winetricks" 
#sudo apt install --no-upgrade wine winetricks
#sudo dpkg --add-architecture i386
#sudo apt update
#apt-get install --no-upgrade wine32
#banner "Installing: winetricks python27" 
#winetricks python27
#banner "Installing: wine pip2 install pyinstaller7" 
#wine pip2 install pyinstaller

banner "Installing python"
sudo apt install --no-upgrade python

banner "Installing: virtualenv over pip" 
sudo pip2 install virtualenv

banner "Installing: redis-tools" 
sudo apt install --no-upgrade redis-tools

if ! $useRecommended; then
    banner "Installing: exiftool" 
    sudo apt install --no-upgrade exiftool
fi

banner "Installing: snmp-mibs-downloader" 
sudo apt install --no-upgrade snmp-mibs-downloader
sed -i "s/mibs/#mibs/g" /etc/snmp/snmp.conf 

banner "Updating: seclist" 
sudo apt install seclists

#sudo apt install --no-upgrade pygmentize PIP?

banner "Updating: exploitdb" 
sudo apt install exploitdb

banner "Updating: metasploit-framework (Recommanded: N)" 
#msfupdate
if $useRecommended; then
    sudo apt install --no-upgrade metasploit-framework
else 
    confirm "Update metasploit (Default: N) [y/n]? " \
        && sudo apt install metasploit-framework
fi

banner "Updating: searchsploit" 
sudo searchsploit -u

banner "Updating: nmap-scripts"
sudo nmap --script-updated

banner "Adding PubkeyAcceptedKeyTypes ssh-dss to ssh_config (used in Debian OpenSSL Predictable PRNG (CVE-2008-0166))"
echo "More@: https://github.com/weaknetlabs/Penetration-Testing-Grimoire/blob/master/Vulnerabilities/SSH/key-exploit.md"
echo "More@: https://github.com/g0tmi1k/debian-ssh"
if ! grep -q "PubkeyAcceptedKeyTypes +ssh-dss" "/etc/ssh/ssh_config"; then
    sudo echo "PubkeyAcceptedKeyTypes +ssh-dss" >> /etc/ssh/ssh_config
fi 
 
banner "Fixing SMB/RPC - NT_STATUS_INVALID_PARAMETER"
echo "More@: https://forums.offensive-security.com/showthread.php?12943-Found-solution-to-enum4linux-rpcclient-problem-NT_STATUS_INVALID_PARAMETER/page2&highlight=NT_STATUS_INVALID_PARAMETER"
if ! grep -q "client min protocol = NT1" "/etc/samba/smb.conf"; then
    sed -i "s/workgroup = WORKGROUP/workgroup = WORKGROUP\n   client min protocol = NT1\n   client max protocol = SMB3\n   client use spnego = No/g" /etc/samba/smb.conf
fi

sudo apt install gobuster

#sudo apt-get install docker-ce

# TODO: 
#  sdkman
#  java 11
#  ghidra
#  pure-ftpd

if ! grep -q "cdsetup" ~/.bashrc; then
cat <<EOT >> ~/.bashrc
alias cdsetup="cd ~/Desktop/setup"
alias cdpublic="cd ~/Desktop/setup/public"
alias cddesktop="cd ~/Desktop/"
alias cdauto="cd ~/Desktop/setup/tools/general/AutoRecon"

alias webup='python -m SimpleHTTPServer 80'
alias smbup='smbserver.py share .'
alias shieldsup='tcpdump -i tap0 -nnvv src net 10.11.0.0/24 and dst 10.11.0.54 -w - | tee capture.pcap | tcpdump -n -r -'

alias ss='searchsploit $1'
alias ssx='searchsploit -x $1'

alias ll='ls -la'
mcd () { mkdir -p $1; cd $1; }
EOT
fi
