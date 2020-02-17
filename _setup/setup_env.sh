sudo apt -y update
##sudo apt -y upgrade

updatedb

sudo apt install --no-upgrade git
sudo apt install --no-upgrade unzip
sudo apt install --no-upgrade unrar
sudo apt install --no-upgrade ftp
sudo apt install --no-upgrade mdbtools
sudo apt install --no-upgrade nfs-common

sudo apt install --no-upgrade snmp-mibs-downloader
sed -i "s/mibs/#mibs/g" /etc/snmp/snmp.conf 

sudo apt install seclists

#sudo apt install --no-upgrade pygmentize PIP?

#sudo apt -y install exploitdb
##sudo apt -y install metasploit-framework

sudo searchsploit -u
sudo nmap --script-updated
##msfupdate

# https://github.com/weaknetlabs/Penetration-Testing-Grimoire/blob/master/Vulnerabilities/SSH/key-exploit.md
if ! grep -q "PubkeyAcceptedKeyTypes +ssh-dss" "/etc/ssh/ssh_config"; then
    sudo echo "PubkeyAcceptedKeyTypes +ssh-dss" >> /etc/ssh/ssh_config
fi 

# mkdir -p share
# chmod 777 share
# adduser share


# apt-get update
# apt dist-upgrade #Reboot 
# apt install kali-linux-all #Reboot
# apt autoclean
# apt autoremove
# apt --fix-broken install

# Keyboard shortcuts