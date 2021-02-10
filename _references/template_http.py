# virtualenv -p python3 myvenv
# source myvenv/bin/activate

import requests
import socket
import json
from requests.auth import HTTPBasicAuth

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# auth = HTTPBasicAuth('user', 'pass')
# auth = HTTPDigestAuth('user', 'pass')
# auth = OAuth1('YOUR_APP_KEY', 'YOUR_APP_SECRET', 'USER_OAUTH_TOKEN', 'USER_OAUTH_TOKEN_SECRET')
# https://requests-oauthlib.readthedocs.io/en/latest/oauth1_workflow.html
# https://requests-oauthlib.readthedocs.io/en/latest/oauth2_workflow.html#introduction
#
# proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
#
# payload = {'key1': 'value1', 'key2': 'value2'}
# data = {'key1': 'value1', 'key2': 'value2'}
# headers = {'user-agent': 'my-app/0.0.1'}
# files = {'file': open('report.xls', 'rb')}
# files = {'file': ('report.xls', open('report.xls', 'rb'), 'application/vnd.ms-excel', {'Expires': '0'})}
# files = {'file': ('report.csv', 'some,data,to,send\nanother,row,to,send\n')}
#
# cookies = dict(cookies_are='working')
# OR 
# cookies = requests.cookies.RequestsCookieJar()
# cookies.set('tasty_cookie', 'yum', domain='httpbin.org', path='/cookies')
# cookies.set('gross_cookie', 'blech', domain='httpbin.org', path='/elsewhere')
#
def doHttp(verb, url, proxies = None, auth = None, params = None, data = None, json = None, headers = None, filename = None, files = None, cookies = None, allow_redirects = False, timeout = None):
    resp = requests.request(verb, url, verify=False, proxies=proxies, auth=auth, params=params, data=data, json=json, headers=headers, files=files, cookies=cookies, allow_redirects=False, timeout=timeout)

    print("[HTTP] > " + resp.url)
    print("[HTTP] > " + str(resp.request.body))
    print("[HTTP] > " + str(resp.request.headers))
    print("")
    print("[HTTP] < " + str(resp.status_code)) # r.status_code == requests.codes.ok
    print("[HTTP] < " + str(resp.headers))
    try:
        print("[HTTP] < " + resp.cookies['example_cookie_name'])
    except KeyError as e:
        print("[HTTP] < No Such Cookie")

    # print("[HTTP] < " + resp.text)

    # try:
    #     response = resp.json()
    # except (json.decoder.JSONDecodeError, requests.exceptions.ConnectionError) as e:
    #     print("[HTTP] < Not JSON")

    if filename != None:
        with open(filename, 'wb') as fd:
            for chunk in resp.iter_content(chunk_size=128):
                fd.write(chunk)
   
    return resp.text

doHttp('POST', 'http://example.com', json = {"a": "b"})