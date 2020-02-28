#!/bin/bash
cd public
python -m SimpleHTTPServer 80 &
python tools/smbserver.py share .
#python3 -m http.server
#ruby -rwebrick -e "WEBrick::HTTPServer.new(:Port => 80, :DocumentRoot => Dir.pwd).start"
#php -S $ip:80

#mkdir /tftp
#atftpd --daemon --port 69 /tftp

#apt-get update && apt-get install pure-ftpd
#groupadd ftpgroup
#useradd -g ftpgroup -d /dev/null -s /etc ftpuser
#pure-pw useradd offsec -u ftpuser -d /ftphome
#pure-pw mkdb
#cd /etc/pure-ftpd/auth/
#ln -s ../conf/PureDB 60pdb
#mkdir -p /ftphome
#chown -R ftpuser:ftpgroup /ftphome/
#/etc/init.d/pure-ftpd restart

cd -