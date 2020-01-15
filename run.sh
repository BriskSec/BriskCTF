#!/bin/bash
sudo su share

python tools/smbserver.py share . &
python -m SimpleHTTPServer 80 &
