banner "Updating: APT"
sudo apt -y update

banner "Updating: VM Tools"
sudo apt install -y --reinstall open-vm-tools-desktop fuse

cat <<EOF | sudo tee /usr/local/sbin/mount-shared-folders
#!/bin/sh
vmware-hgfsclient | while read folder; do
  vmwpath="/mnt/hgfs/\${folder}"
  echo "[i] Mounting \${folder}   (\${vmwpath})"
  sudo mkdir -p "\${vmwpath}"
  sudo umount -f "\${vmwpath}" 2>/dev/null
  sudo vmhgfs-fuse -o allow_other -o auto_unmount ".host:/\${folder}" "\${vmwpath}"
done
sleep 2s
EOF
sudo chmod +x /usr/local/sbin/mount-shared-folders

cat <<EOF | sudo tee /usr/local/sbin/restart-vm-tools
#!/bin/sh

systemctl stop run-vmblock\\\\x2dfuse.mount
killall -q -w vmtoolsd
systemctl start run-vmblock\\\\x2dfuse.mount
systemctl enable run-vmblock\\\\x2dfuse.mount
vmware-user-suid-wrapper vmtoolsd -n vmusr 2>/dev/null
vmtoolsd -b /var/run/vmroot 2>/dev/null
EOF
sudo chmod +x /usr/local/sbin/restart-vm-tools

echo "export PATH=\$PATH:/usr/local/sbin" > ~/.bashrc

banner "Running APT upgrade"
confirm "Upgrade all packages (Default: N) [y/n]? " \
    && sudo apt -y full-upgrade

banner "Installing offsec-awae"
sudo apt-get install -y offsec-awae

banner "Updating: mlocate database" 
sudo updatedb

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

banner "Installing: virtualenv over pip" 
sudo pip2 install setuptools
sudo pip2 install virtualenv

banner "Installing: redis-tools" 
sudo apt install --no-upgrade redis-tools

banner "Installing: exiftool" 
sudo apt install --no-upgrade exiftool

banner "Installing: snmp-mibs-downloader" 
sudo apt install --no-upgrade snmp-mibs-downloader
sudo sed -i "s/mibs/#mibs/g" /etc/snmp/snmp.conf 

banner "Updating: seclist" 
sudo apt install seclists

banner "Updating: exploitdb" 
sudo apt install exploitdb

banner "Updating: metasploit-framework" 
sudo apt install metasploit-framework

banner "Updating: searchsploit" 
sudo searchsploit -u

banner "Updating: nmap-scripts"
sudo nmap --script-updated

banner "Updating: gobuster"
sudo apt install gobuster

banner "Adding PubkeyAcceptedKeyTypes ssh-dss to ssh_config (used in Debian OpenSSL Predictable PRNG (CVE-2008-0166))"
echo "More@: https://github.com/weaknetlabs/Penetration-Testing-Grimoire/blob/master/Vulnerabilities/SSH/key-exploit.md"
echo "More@: https://github.com/g0tmi1k/debian-ssh"
if ! grep -q "PubkeyAcceptedKeyTypes +ssh-dss" "/etc/ssh/ssh_config"; then
    sudo su
    echo "PubkeyAcceptedKeyTypes +ssh-dss" >> /etc/ssh/ssh_config
    exit
fi 
 
banner "Fixing SMB/RPC - NT_STATUS_INVALID_PARAMETER"
echo "More@: https://forums.offensive-security.com/showthread.php?12943-Found-solution-to-enum4linux-rpcclient-problem-NT_STATUS_INVALID_PARAMETER/page2&highlight=NT_STATUS_INVALID_PARAMETER"
if ! grep -q "client min protocol = NT1" "/etc/samba/smb.conf"; then
    sudo su
    sed -i "s/workgroup = WORKGROUP/workgroup = WORKGROUP\n   client min protocol = NT1\n   client max protocol = SMB3\n   client use spnego = No/g" /etc/samba/smb.conf
    exit
fi

# sudo apt-get install docker-ce
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
