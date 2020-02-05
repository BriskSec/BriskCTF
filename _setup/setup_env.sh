#sudo apt -y update
##sudo apt -y upgrade
#sudo apt -y install git
#sudo apt -y install unzip
#sudo apt -y install unrar

#sudo apt -y install exploitdb
##sudo apt -y install metasploit-framework

searchsploit -u
##msfupdate

# https://github.com/weaknetlabs/Penetration-Testing-Grimoire/blob/master/Vulnerabilities/SSH/key-exploit.md
sudo echo "PubkeyAcceptedKeyTypes +ssh-dss" >> /etc/ssh/ssh_config

mkdir -p share
chmod 777 share

adduser share
