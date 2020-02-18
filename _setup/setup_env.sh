banner "Updating: APT"
sudo apt -y update

banner "Running APT upgrade"
confirm "SKIP upgrading all packages (Recommanded: Y) [y/n]?" \
    || sudo apt -y upgrade

banner "Disabling APT auto-updates"
confirm "Disable auto update (Recommanded: Y) [y/n]?" \
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

banner "Installing: snmp-mibs-downloader" 
sudo apt install --no-upgrade snmp-mibs-downloader
sed -i "s/mibs/#mibs/g" /etc/snmp/snmp.conf 

#banner "Updating: seclist" 
#sudo apt install seclists

#sudo apt install --no-upgrade pygmentize PIP?

banner "Updating: exploitdb (Recommanded: Y)" 
sudo apt install exploitdb

banner "Updating: metasploit-framework (Recommanded: N)" 
#msfupdate
sudo apt install metasploit-framework

banner "Updating: searchsploit" 
sudo searchsploit -u

banner "Updating: nmap-scripts"
sudo nmap --script-updated

banner "Adding PubkeyAcceptedKeyTypes ssh-dss to ssh_config (used in Debian OpenSSL Predictable PRNG (CVE-2008-0166))"
echo "More@: https://github.com/weaknetlabs/Penetration-Testing-Grimoire/blob/master/Vulnerabilities/SSH/key-exploit.md"
echo "More@: https://github.com/g0tmi1k/debian-ssh"
if ! grep -q "PubkeyAcceptedKeyTypes +ssh-dss" "/etc/ssh/ssh_config"; then
    confirm "Add PubkeyAcceptedKeyTypes ssh-dss to ssh_config (Recommanded: Y) [y/n]? " && sudo echo "PubkeyAcceptedKeyTypes +ssh-dss" >> /etc/ssh/ssh_config
fi 
 
banner "Fixing SMB/RPC - NT_STATUS_INVALID_PARAMETER"
echo "More@: https://forums.offensive-security.com/showthread.php?12943-Found-solution-to-enum4linux-rpcclient-problem-NT_STATUS_INVALID_PARAMETER/page2&highlight=NT_STATUS_INVALID_PARAMETER"
if ! grep -q "client min protocol = NT1" "/etc/samba/smb.conf"; then
    confirm "Fix SMB/RPC - NT_STATUS_INVALID_PARAMETER (Recommanded: Y) [y/n]? " && sed -i "s/workgroup = WORKGROUP/workgroup = WORKGROUP\n   client min protocol = NT1\n   client max protocol = SMB3\n   client use spnego = No/g" /etc/samba/smb.conf
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
