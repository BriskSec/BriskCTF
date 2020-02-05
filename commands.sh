#!/bin/bash

if [ $# -lt 3 ]
  then
    echo "Usage ./commands.sh [source_ip] [source_port] [target_ip]"
    exit
fi

cd _commands
bash commands.sh $@ > ../$3.out
cat ../$3.out
cd ..