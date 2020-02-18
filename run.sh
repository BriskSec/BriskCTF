#!/bin/bash
#sudo su share
cd 
python tools/smbserver.py share . &
python -m SimpleHTTPServer 80 &
