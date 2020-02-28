#!/bin/bash

# HTTP port and SMB share to use for commands
export http_port=80
export smb_share='share'

# Get parent directory
export pwd="`pwd`"

cd _commands
bash commands.sh $@
cd ..

URL="commands.html"
[[ -x $BROWSER ]] && exec "$BROWSER" "$URL"
path=$(which xdg-open || which gnome-open || which open) && exec "$path" "$URL"
echo "Can't find browser. Open 'file://`pwd`/commands.html'"
