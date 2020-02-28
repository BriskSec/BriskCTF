# Enumeration

- Nmap Basic
- Nmap Extended TCP
- Nmap Extended UDP
- Nikto
- Dirbuster
- Webdev
- CMS
- SMB
- SNMP
- Databases
- FTP

```
Network Scanning

   ☐  nmap -sn 10.11.1.*
   ☐  nmap -sL 10.11.1.*
   ☐  nbtscan -r 10.11.1.0/24
   ☐  smbtree

Individual Host Scanning

   ☐  nmap  --top-ports 20 --open -iL iplist.txt
   ☐  nmap -sS -A -sV -O -p- ipaddress
   ☐  nmap -sU ipaddress

Service Scanning

    WebApp
      ☐   Nikto
      ☐   dirb
      ☐   dirbuster
      ☐   wpscan (use searchsploit also)
      ☐   dotdotpwn
      ☐   view source
      ☐   davtest\cadevar
      ☐   droopscan
      ☐   joomscan
      ☐   LFI\RFI Test
      ☐   Certificate - All domains in SAN and CN
      ☐   fimap - All clickable links (fimap -H -d 3 -u http://10.10.10.8 -w /tmp/fimap_output)

    Linux\Windows
      ☐   snmpwalk -c public -v1 ipaddress 1
      ☐   smbclient -L //ipaddress
      ☐   showmount -e ipaddress port
      ☐   rpcinfo
      ☐   Enum4Linux

    Anything Else
      ☐   nmap scripts (locate *nse* | grep servicename)
      ☐   hydra
      ☐   MSF Aux Modules
      ☐   Download the softward

Exploitation
   ☐   Gather Version Numbes
   ☐   Searchsploit
   ☐   Default Creds
   ☐   Creds Previously Gathered
   ☐   Download the software

Post Exploitation

    Linux
      ☐   Check emails
      ☐   Word-writable files (LinEnum -t)  
      ☐   linux-local-enum.sh
      ☐   linuxprivchecker.py
      ☐   linux-exploit-suggestor.sh
      ☐   unix-privesc-check.py
      ☐   Processes (ps -aux)
          ☐   Tmux sessions / Knockd / VNC / TTY (ps -ef | grep -E "tmux|knock|vnc|tty")
          ☐   System timers (watch -n 1 'systemctl list-timers')
      ☐   Interesting groups
          ☐   Video - screenshot (​/sys/class/graphics/fb0/virtual_size ​/dev/fb0)
          ​☐   Disk - Access to partitions (debugfs /dev/sda1​)
      ☐   Local ports (netstat -an)
      ☐   Schedules processes (PsPy)
      ☐   .Net version - reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP"
      ☐   .Net version - dir C:\Windows\Microsoft.NET\Framework
      ☐   Watson

    Windows
      ☐   wpc.exe
      ☐   windows-exploit-suggestor.py
      ☐   windows_privesc_check.py
      ☐   windows-privesc-check2.exe

Priv Escalation
   ☐  acesss internal services (portfwd)
   ☐  add account

Windows
   ☐  List of exploits

Linux
   ☐  sudo su
   ☐  KernelDB
   ☐  Searchsploit

Final
   ☐  Screenshot of IPConfig\WhoamI
   ☐  Copy proof.txt
   ☐  Dump hashes
   ☐  Dump SSH Keys
   ☐  Delete files
```
