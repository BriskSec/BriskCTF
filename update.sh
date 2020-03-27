
#!/bin/bash

if [ ! $# -eq 1 ]
  then
    echo "Usage ./update.sh remote_port"
    echo ""
    echo "  source_ip   - IP address or the interface-name (ex: tun0) of the attacker machine"
    echo "                This is mostly used as the target IP of reverse-tcp connections"
    echo ""
    echo "  source_port - Port to listen on the attacker machine"
    echo "                This is mostly used as the destination port of reverse-tcp connections"
    echo ""
    echo "  remote_port - Port to open on the target machine"
    echo "                This is mostly used as the source port of bind-tcp connections"
    echo ""
    exit
fi

source_ip=$1
source_port=$2
remote_port=$3

bash setup.sh $source_ip $source_port $remote_port false true
