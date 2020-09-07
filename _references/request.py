import restests

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
# r = requests.get('https://example.com/',verify=False, proxies=proxies)

r = requests.get('https://example.com/',verify=False)

# r.cookies r.status_code r.headers r.text 