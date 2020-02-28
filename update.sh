
#!/bin/bash

if [ ! $# -eq 1 ]
  then
    echo "Usage ./update.sh remote_port"
    echo ""
    echo "  remote_port - Port to open on the target machine"
    echo "                This is mostly used as the source port of bind-tcp connections"
    echo ""
    exit
fi

source_ip="`cat _setup/config.properties | grep "source_ip" | cut -d '=' -f2`"
source_port="`cat _setup/config.properties | grep "source_port" | cut -d '=' -f2`"
remote_port="`cat _setup/config.properties | grep "remote_port" | cut -d '=' -f2`"

remote_port=$1

bash setup.sh $source_ip $source_port $remote_port false true
