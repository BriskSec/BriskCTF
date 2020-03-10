
# Common 

- [CyberChef](https://gchq.github.io/CyberChef) - The Cyber Swiss Army Knife - a web app for encryption, encoding, compression and data analysis

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

## Metasploit 

### Auto Migrate 
```
set AutoRunScript multi_console_command -r $pwd/payloads_linux/automigrate.rc
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