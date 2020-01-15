mkdir -p scripts_windows
cd scripts_windows

  wget https://raw.githubusercontent.com/GDSSecurity/Windows-Exploit-Suggester/master/windows-exploit-suggester.py

  wget https://github.com/DominicBreuker/pspy/releases/download/v1.0.0/pspy32
  wget https://github.com/DominicBreuker/pspy/releases/download/v1.0.0/pspy64
  wget https://github.com/DominicBreuker/pspy/releases/download/v1.0.0/pspy32s
  wget https://github.com/DominicBreuker/pspy/releases/download/v1.0.0/pspy64s

  wget https://github.com/rasta-mouse/Watson/releases/download/2.0/Watson_Net35.exe
  wget https://github.com/rasta-mouse/Watson/releases/download/2.0/Watson_Net45.exe

  wget https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe
  wget https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2008-vista.exe
  wget https://download.sysinternals.com/files/AccessChk.zip
  unzip AccessChk.zip
  rm Eula.txt

  wget https://download.sysinternals.com/files/PSTools.zip
  unzip PSTools.zip -d pstools
  rm PSTools.zip

  wget https://www.ampliasecurity.com/research/wce_v1_41beta_universal.zip
  unzip wce_v1_41beta_universal.zip -d wce
  cp wce/wce.exe .
  rm -rf wce
  rm wce_v1_41beta_universal.zip

  wget http://www.microolap.com/downloads/tcpdump/tcpdump_trial_license.zip
  unzip tcpdump_trial_license.zip -d tcpdumpwim
  cp tcpdumpwim/tcpdump.exe .
  rm -rf tcpdumpwim
  rm tcpdump_trial_license.zip

  wget http://www.sec-1.com/blog/wp-content/uploads/2015/05/gp3finder_v4.0.zip
  unzip gp3finder_v4.0.zip
  rm gp3finder_v4.0.zip

  #TODO Installation
  wget https://2.na.dl.wireshark.org/win32/WiresharkPortable_3.2.0.paf.exe

  wget https://github.com/z3APA3A/3proxy/releases/download/0.8.13/3proxy-0.8.13.zip
  unzip 3proxy-0.8.13.zip -d 3proxy
  mv 3proxy-0.8.13.zip 3proxy.zip

  wget http://www.tarasco.org/security/pwdump_7/pwdump7.zip
  unzip pwdump7.zip -d pwdump7
  rm pwdump7.zip
cd -

mkdir -p scripts_windows/ps
cd scripts_windows/ps

  wget https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1
  wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1

  wget https://github.com/Kevin-Robertson/Invoke-TheHash/raw/master/Invoke-SMBClient.ps1
  wget https://github.com/Kevin-Robertson/Invoke-TheHash/raw/master/Invoke-SMBEnum.ps1
  wget https://github.com/Kevin-Robertson/Invoke-TheHash/raw/master/Invoke-SMBExec.ps1
  wget https://github.com/Kevin-Robertson/Invoke-TheHash/raw/master/Invoke-TheHash.ps1
  wget https://github.com/Kevin-Robertson/Invoke-TheHash/raw/master/Invoke-TheHash.psd1
  wget https://github.com/Kevin-Robertson/Invoke-TheHash/raw/master/Invoke-TheHash.psm1
  wget https://github.com/Kevin-Robertson/Invoke-TheHash/raw/master/Invoke-WMIExec.ps1

  wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/CodeExecution/Invoke-Shellcode.ps1

cd -

mkdir -p scripts_windows/bin
cd scripts_windows/bin
  cp /usr/share/windows-binaries/* .

  # http://www.saule-spb.ru/touch/windows_files.html
  wget http://www.saule-spb.ru/windows/reg.zip
  wget http://www.saule-spb.ru/windows/regedit.zip
  wget http://www.saule-spb.ru/windows/regini.zip
  wget http://www.saule-spb.ru/windows/sclist.zip
  wget http://www.saule-spb.ru/windows/tasklist.zip
  wget http://www.saule-spb.ru/windows/taskkill.rar
  wget http://www.saule-spb.ru/windows/netstat.zip
  wget http://www.saule-spb.ru/windows/ip6fw.zip
  wget http://www.saule-spb.ru/windows/tcpip-2892.zip
  wget http://www.saule-spb.ru/windows/tcpip-2180.zip
  wget http://www.saule-spb.ru/windows/sfc_os_dll_5.1.2600.1106.rar
  wget http://www.saule-spb.ru/windows/sfc_os_dll_5.1.2600.2180.rar
  wget http://www.saule-spb.ru/windows/sfc_os_dll_5.2.3790.3959.rar
  # Run a DLL as an App
  wget http://www.saule-spb.ru/windows/rundll32_xp2.zip
  wget http://www.saule-spb.ru/windows/rundll32_2003.zip
  # Windows Control Panel
  wget http://www.saule-spb.ru/windows/control_2003.zip
  # System Configuration Utility
  wget http://www.saule-spb.ru/windows/msconfig_xp2.zip
  wget http://www.saule-spb.ru/windows/msconfig_2003.zip
  unzip *.zip
  unrar x *.rar
  rm *.zip *.rar

cd -
