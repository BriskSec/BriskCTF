#!/bin/bash

if [ $# -lt 3 ]
  then
    echo "Usage ./commands.sh [source_ip] [source_port] [target_ip]"
    echo "  source_ip   - IP address or the interface-name (ex: tun0) of the attacker machine"
    echo "                This is mostly used as the target IP of reverse-tcp connections"
    echo "  source_port - Port to listen on the attacker machine"
    echo "                This is mostly used as the target port of reverse-tcp connections"
    echo "  target_ip   - IP addesss of the target host"
    echo "                This is mostly used in attack scripts or scans"
    exit
fi

cd _commands
bash commands.sh $@ > ../$3.out
cat ../$3.out
cd ..
