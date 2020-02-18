#!/bin/bash
cd public
python -m SimpleHTTPServer 80 &
python tools/smbserver.py share .
cd -