mkdir -p scripts_windows
cd scripts_windows

  wget -Nq https://raw.githubusercontent.com/GDSSecurity/Windows-Exploit-Suggester/master/windows-exploit-suggester.py

  # TODO BUILD Watson
  #wget https://github.com/rasta-mouse/Watson/releases/download/2.0/Watson_Net35.exe
  #wget https://github.com/rasta-mouse/Watson/releases/download/2.0/Watson_Net45.exe

  wget -Nq https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe
  wget -Nq https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2008-vista.exe

  if [ ! -f accesschk.exe ]; then
    wget https://download.sysinternals.com/files/AccessChk.zip
    unzip AccessChk.zip
    rm Eula.txt
    rm AccessChk.zip
  fi

  if [ ! -d pstools ]; then
    wget https://download.sysinternals.com/files/PSTools.zip
    unzip PSTools.zip -d pstools
    rm PSTools.zip
  fi

  if [ ! -f wce.exe ]; then
    wget https://www.ampliasecurity.com/research/wce_v1_41beta_universal.zip
    unzip wce_v1_41beta_universal.zip -d wce
    cp wce/wce.exe .
    rm -rf wce
    rm wce_v1_41beta_universal.zip
  fi

  if [ ! -f tcpdump.exe ]; then
    wget http://www.microolap.com/downloads/tcpdump/tcpdump_trial_license.zip
    unzip tcpdump_trial_license.zip -d tcpdumpwim
    cp tcpdumpwim/tcpdump.exe .
    rm -rf tcpdumpwim
    rm tcpdump_trial_license.zip
  fi

  if [ ! -f gp3finder.exe ]; then
    wget http://www.sec-1.com/blog/wp-content/uploads/2015/05/gp3finder_v4.0.zip
    unzip gp3finder_v4.0.zip
    rm gp3finder_v4.0.zip
  fi

  #TODO Installation
  wget -Nq https://2.na.dl.wireshark.org/win32/WiresharkPortable_3.2.0.paf.exe

  if [ ! -d 3proxy ]; then
    wget https://github.com/z3APA3A/3proxy/releases/download/0.8.13/3proxy-0.8.13.zip
    unzip 3proxy-0.8.13.zip -d 3proxy
    mv 3proxy-0.8.13.zip 3proxy.zip
  fi

  if [ ! -d pwdump7 ]; then
    wget http://www.tarasco.org/security/pwdump_7/pwdump7.zip
    unzip pwdump7.zip -d pwdump7
    rm pwdump7.zip
  fi

  wget -Nq https://github.com/pentestmonkey/windows-privesc-check/raw/master/windows-privesc-check2.exe

cd -

mkdir -p scripts_windows/ps
cd scripts_windows/ps

  wget -Nq https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1
  wget -Nq https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1

  wget -Nq https://github.com/Kevin-Robertson/Invoke-TheHash/raw/master/Invoke-SMBClient.ps1
  wget -Nq https://github.com/Kevin-Robertson/Invoke-TheHash/raw/master/Invoke-SMBEnum.ps1
  wget -Nq https://github.com/Kevin-Robertson/Invoke-TheHash/raw/master/Invoke-SMBExec.ps1
  wget -Nq https://github.com/Kevin-Robertson/Invoke-TheHash/raw/master/Invoke-TheHash.ps1
  wget -Nq https://github.com/Kevin-Robertson/Invoke-TheHash/raw/master/Invoke-TheHash.psd1
  wget -Nq https://github.com/Kevin-Robertson/Invoke-TheHash/raw/master/Invoke-TheHash.psm1
  wget -Nq https://github.com/Kevin-Robertson/Invoke-TheHash/raw/master/Invoke-WMIExec.ps1

  wget -Nq https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/CodeExecution/Invoke-Shellcode.ps1

cd -

rm -rf scripts_windows/bin
mkdir -p scripts_windows/bin
cd scripts_windows/bin

  cp -rf /usr/share/windows-binaries/* .

  # http://www.saule-spb.ru/touch/windows_files.html
  wget http://www.saule-spb.ru/windows/reg.zip
  wget http://www.saule-spb.ru/windows/regedit.zip
  wget http://www.saule-spb.ru/windows/regini.zip
  wget http://www.saule-spb.ru/windows/sclist.zip
  unzip sclist.zip
  mv sclist/sclist.exe sclist.exe
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
