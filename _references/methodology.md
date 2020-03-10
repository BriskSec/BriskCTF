- Network Scanning
    - nmap -sn 10.11.1.*
    - nmap -sL 10.11.1.*
    - netdiscover -r 10.11.1.0/24
    - nbtscan -r 10.11.1.0/24
    - smbtree
    - DNS: nmap -p 53 10.11.1.* -vv

- Individual Host Scanning
    - nmap  --top-ports 20 --open -iL iplist.txt
    - nmap -sC -sV -Pn -oA  -vv standard_tcp $ip
    - nmap -sC -sV -sU -Pn -oA  -vv standard_udp $ip
    - nmap -p -sU -sT -Pn 0-65535 -vv -oN all_ports $ip 
    - nmap -sU ipaddress
    - unicornscan -mU -I 192.168.24.53:a -v -l unicorn_full_udp.txt
    - unicornscan -mT -I 192.168.24.53:a -v -l unicorn_full_tcp.txt
    - nmap -Pn -sT -sU  -p $ports --script=*vuln*  -vv -oN nmap_vuln  $ip 

- Service Scanning
    - WebApp
        -  Nikto
        -  dirb
        -  dirbuster
        -  wpscan (use searchsploit also)
        -  dotdotpwn (lfi/rfi)
        -  view source
        -  davtest\cadevar
        -  droopscan
        -  joomscan
        -  LFI\RFI Test
        -  Certificate - All domains in SAN and CN
        -  fimap - All clickable links (fimap -H -d 3 -u http://10.10.10.8 -w /tmp/fimap_output)
        -  cgi-bin shellshock
    - Linux\Windows
        -  snmpwalk -c public -v1 ipaddress 1
        -  smbclient -L //ipaddress
        -  SMB Null Session
        -  showmount -e ipaddress port
        -  rpcinfo
        -  Enum4Linux
        -  DNS enumeration + AXRF
    - Anything Else
        -  nmap scripts (locate *nse* | grep servicename)
        -  hydra
        -  MSF Aux Modules
        -  Download the software


- Exploitation
    -  Gather Version Numbers
    -  Searchsploit
    -  Default Creds
    -  Creds Previously Gathered
    -  Download the software

- Client Side Attacks 
  - MS12-037 - Internet Explorer 8 Fixed Col Span ID
  - Java Signed Applet Attack

- Post Exploitation
    - Linux
        -  Check emails
        -  Word-writable files (LinEnum -t)  
        -  linux-local-enum.sh
        -  linuxprivchecker.py
        -  linux-exploit-suggestor.sh
        -  unix-privesc-check.py
        -  Processes (ps -aux)
            -  Tmux sessions / Knockd / VNC / TTY (ps -ef | grep -E "tmux|knock|vnc|tty")
            -  System timers (watch -n 1 'systemctl list-timers')
        -  Interesting groups
            -  Video - screenshot (​/sys/class/graphics/fb0/virtual_size ​/dev/fb0)
            ​☐   Disk - Access to partitions (debugfs /dev/sda1​)
        -  Local ports (netstat -an)
        -  Schedules processes (PsPy)
        -  .Net version - reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP"
        -  .Net version - dir C:\Windows\Microsoft.NET\Framework
        -  Watson
    - Windows
        -  wpc.exe
        -  windows-exploit-suggestor.py
        -  windows_privesc_check.py
        -  windows-privesc-check2.exe

- Priv Escalation
    - Windows
        - List of exploits
        - Weak Service Permissions
          - Insecure Service Permissions with accesschk.exe and sc
          - Unquoted Services
          - AlwaysInstallElevated
          - DLL Hijacking
          - Task Scheduler Weak File/Folder Permissions
          - Stored Credentials
    - Linux
        - sudo su
        - KernelDB
        - Searchsploit
        - SUID Privilege Escalation

- Final
    - Screenshot of IPConfig\WhoamI
    - Copy proof.txt
    - Dump hashes
    - Dump SSH Keys
    - Delete files