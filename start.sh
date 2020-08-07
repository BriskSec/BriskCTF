#!/bin/bash

cd public
echo ""
echo "Starting SimpleHTTPServer on port 80"
nohup python -m SimpleHTTPServer 80 &
echo ""
echo "Starting smbserver share name \"share\""
nohup python tools/general/smbserver.py share . &
echo ""
cd - 