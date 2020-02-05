#!/usr/bin/python3
# From https://github.com/tagnullde/CTF/blob/master/Recon/recon.py

import subprocess
import sys

if len(sys.argv) <= 1:
    print("[-] Target IP is required")
    quit()

ip = sys.argv[1]

ippsec = "ippsec_scan.txt"
service = "all_tcp_service_scan.txt"
script = "script_scan.txt"
all_udp = "all_tcp_scan.txt"


def ippsec_scan(ip):
    print("[!] Starting ippsec_scan ")
    subprocess.run(["nmap", "-sC", "-sV", "-oN", ippsec, ip])
    print("[+] Done ")

def all_tcp_service_scan(ip):
    print("[!] Starting service_scan ")
    subprocess.run(["nmap", "-A", "-p-", "-oN", service, ip])
    print("[+] Done ")

def script_scan(ip):
    print("[!] Starting script_scan ")
    # TODO:  GET port list from the full TCP scan 
    subprocess.run(["nmap", "--script", "discovery, safe, vuln", "-oN", script, ip])
    print("[+] Done ")

def alludp_scan(ip):
    print("[!] Starting all_udp_scan ")
    subprocess.run(["nmap", "-p-", "-sU", "-oN", all_udp, ip])
    print("[+] Done ")

if __name__ == '__main__':
    ippsec_scan(ip)
    all_tcp_service_scan(ip)
    script_scan(ip)
    alludp_scan(ip)