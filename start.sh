#!/bin/bash

cd public
echo ""
echo "Starting SimpleHTTPServer on port 80"
nohup python -m SimpleHTTPServer 80 &
echo ""
echo "Starting smbserver share name \"share\""
nohup python tools/general/smbserver.py share . &
# smbserver.py -smb2support -username noob -password noob share .
# nohup sudo impacket-smbserver share . &
echo ""
cd - 