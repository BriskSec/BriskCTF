git clone --depth=1 --recursive https://github.com/GDSSecurity/Windows-Exploit-Suggester.git
git clone --depth=1 --recursive https://github.com/InteliSecureLabs/Linux_Exploit_Suggester.git
git clone --depth=1 --recursive https://github.com/jondonas/linux-exploit-suggester-2.git
git clone --depth=1 --recursive https://github.com/Arr0way/linux-local-enumeration-script.git
git clone --depth=1 --recursive https://github.com/sleventyeleven/linuxprivchecker.git
git clone --depth=1 --recursive https://github.com/mzet-/linux-exploit-suggester.git
git clone --depth=1 --recursive https://github.com/pentestmonkey/unix-privesc-check
git clone --depth=1 --recursive https://github.com/GDSSecurity/Windows-Exploit-Suggester.git
git clone --depth=1 --recursive https://github.com/rasta-mouse/Watson.git
git clone --depth=1 --recursive https://github.com/pentestmonkey/windows-privesc-check.git

git clone --depth=1 --recursive https://github.com/b374k/b374k.git

###########################
##       SCRIPTS         ##
###########################

# Common
wget https://www.exploit-db.com/download/34900
mv 34900 shellshock.py
chmod +x *

###########################
##       EXPLOITS        ##
###########################

mkdir -p exploits/ms08-067
cd exploits/ms08-067
wget https://raw.githubusercontent.com/jivoi/pentest/master/exploit_win/ms08-067.py
cd -

mkdir -p exploit/drupal
cd exploit/drupal
searchsploit -m 34992
mv 34992.py sqli-CVE2014-3704.py
cd -

mkdir exploits/MS16-135
cd exploits/MS16-135
wget https://raw.githubusercontent.com/SecWiki/windows-kernel-exploits/master/MS16-135/MS16-135.ps1
wget https://github.com/SecWiki/windows-kernel-exploits/raw/master/MS16-135/41015.exe
wget https://github.com/SecWiki/windows-kernel-exploits/raw/master/MS16-135/40823/SetWindowLongPtr_Exploit.exe
cd -

cd exploits

git clone --depth=1 --recursive https://github.com/Re4son/Chimichurri.git

wget https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/11199.zip
unzip 11199.zip
rm 11199.zip
cd -

# Setup ODATA

# https://github.com/codingo/OSCP-2
wget https://raw.githubusercontent.com/codingo/OSCP-2/master/Windows/wget.vbs
wget https://raw.githubusercontent.com/codingo/OSCP-2/master/Windows/WinPrivCheck.bat
wget https://raw.githubusercontent.com/codingo/OSCP-2/master/Windows/useradd.c
wget https://raw.githubusercontent.com/codingo/OSCP-2/master/BASH/LinuxPrivCheck.sh
wget https://raw.githubusercontent.com/codingo/OSCP-2/master/BASH/PortKnocker.sh
wget https://raw.githubusercontent.com/codingo/OSCP-2/master/BASH/SUIDChecker.sh
wget https://raw.githubusercontent.com/codingo/OSCP-2/master/BASH/CronJobChecker.sh

wget https://raw.githubusercontent.com/ankh2054/windows-pentest/master/icacls.bat
wget https://raw.githubusercontent.com/ankh2054/windows-pentest/master/schcheck.bat
wget https://raw.githubusercontent.com/ankh2054/windows-pentest/master/wmic-info

wget https://raw.githubusercontent.com/FuzzySecurity/PSKernel-Primitives/master/Sample-Exploits/MS16-135/MS16-135.ps1

wget https://raw.githubusercontent.com/411Hall/JAWS/master/jaws-enum.ps11

wget https://raw.githubusercontent.com/s0wr0b1ndef/OSCP-note/master/bruteforce%20%26%20password_attacks/zip-cracker.sh

cd -

# grep -le "key"

# search for files named  authorized_keys
# Windows Server 2003 Resource Kit Tools  https://www.microsoft.com/en-us/download/details.aspx?id=17657

mkdir /opt/oracle
# https://www.oracle.com/database/technologies/instant-client/downloads.html
cd /opt/oracle/instantclient_12_2
ln libclntsh.so.12.1 libclntsh.so
ls -lh libclntsh.so
ldconfig

~/.bashrc
export PATH=$PATH:/opt/oracle/instantclient_12_2
export SQLPATH=/opt/oracle/instantclient_12_2
export TNS_ADMIN=/opt/oracle/instantclient_12_2
export LD_LIBRARY_PATH=/opt/oracle/instantclient_12_2
export ORACLE_HOME=/opt/oracle/
