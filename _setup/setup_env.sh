banner "Updating: APT"
sudo apt -y update

banner "Running APT upgrade"
confirm "Upgrade all packages (Default: N) [y/n]? " \
    && sudo apt -y upgrade

banner "Disabling APT auto-updates"
confirm "Keep auto update enabled (Default: N) [y/n]? " \
    && (gsettings set org.gnome.software download-updates false; sed -i "s/1/0/g" /etc/apt/apt.conf.d/20auto-upgrades)

banner "Updating: mlocate database" 
updatedb

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

banner "Installing: mingw-w64" 
sudo apt install --no-upgrade mingw-w64

banner "Installing: libc6-dev-i386" 
sudo apt install --no-upgrade libc6-dev-i386 

banner "Installing: winetricks" 
sudo apt install --no-upgrade wine winetricks

banner "Installing: winetricks python27" 
winetricks python27

banner "Installing: wine pip install pyinstaller7" 
wine pip install pyinstaller

banner "Installing: virtualenv over pip" 
pip install virtualenv

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
banner "Adding aliases"
if ! grep -q "SimpleHTTPServer" "/etc/profile.d/00-aliases.sh"; then
cat <<EOT >> /etc/profile.d/00-aliases.sh
#!/bin/bash

## will prevent the need of exiting/reopening terminal after adding an alias
refreshaliases='/etc/profile.d/00-aliases.sh'

    alias vpn='openvpn ~/OS-XXXXX-PWK.ovpn'
    alias htb='openvpn ~/HTB-Username.ovpn'
    alias rdp='rdesktop -g 85% -u offsec -p PASSWORD_HERE 10.11.14.134 &'
    alias mapshare='ln -s /mnt/hgfs/Pwn_Share/ /root/pwnshare'
    alias l='ls -la'
    alias webup='python -m SimpleHTTPServer 80'
    alias shieldsup='tcpdump -i tap0 -nnvv src net 10.11.0.0/24 and dst 10.11.0.54 -w - | tee capture.pcap | tcpdump -n -r -'
    alias ss='searchsploit $1'
    alias ssx='searchsploit -x $1'
    
## navigation
alias goshare='cd /mnt/hgfs/VMShare/'
alias gosoftware='cd /mnt/hgfs/VMShare/software/'
alias gocode='cd /mnt/hgfs/VMShare/code/'
alias godesktop='cd /root/Desktop/'
alias gopwk="cd /mnt/hgfs/VMShare/pwk/"
alias goexam="cd /mnt/hgfs/VMShare/pwk/exam/"
alias gopub="cd /mnt/hgfs/VMShare/pwk/lab/PUBLIC/"

## rdp to the offsec windows vm
alias offsecvm='rdesktop -u admin -p lab 192.168.23.111 -g 1366x768'
alias pwkconnect='openvpn /mnt/hgfs/VMShare/pwk/lab-connection/OS-39215-PWK.ovpn'

## a ssh tunnel i found myself having to use
alias proxy="echo password=Summer2018! && sshuttle -vr root@10.11.11.11 10.1.1.0/24"

## open a drag-to-select screenshot capture (mapped to hotkey)
alias sc='gnome-screenshot -ac'

## software:
alias nosqlmap='python /mnt/hgfs/VMShare/software/NoSQLMap/nosqlmap.py'
alias rsactftool='/mnt/hgfs/VMShare/software/RsaCtfTool/RsaCtfTool.py'
alias nfsshell="/mnt/hgfs/VMShare/software/nfsshell/nfsshell"
alias knock="/usr/bin/python3 /mnt/hgfs/VMShare/software/knock/knock"
# etc...

## mcd foldername - creates the folder and moves you into it. ty @brax <3
mcd () { mkdir -p $1; cd $1; }
EOT
fi



#!/bin/bash
apt update && apt install pure-ftpd
groupadd ftpgroup
useradd -g ftpgroup -d /dev/null -s /etc ftpuser
pure-pw useradd offsec -u ftpuser -d /ftphome # use user offsec when logging into ftp
pure-pw mkdb
cd /etc/pure-ftpd/auth/
ln -s ../conf/PureDB 60pdb
mkdir -p /ftphome # DIRECTORY HOSTING FILES
chown -R ftpuser:ftpgroup /ftphome/
service pure-ftpd restart