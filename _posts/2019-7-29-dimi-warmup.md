---
title: "2017 Dimi CTF Final warmup"
date: 2019-7-29
tags: [dimi,z3]
categories: [CTF]
---

64bit 바이너리 warmup과 flag.enc가 주어졌다.

```
$ file warmup
warmup: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 2.6.32, BuildID[sha1]=387ae1f78e1eda40583739245d91ad9ce53a9442, stripped
```

flag.enc 파일은 뭔가 인코딩 되어 있는듯 알 수 없이 되어있었다.![](https://user-images.githubusercontent.com/32904385/62010411-5da00880-b1a5-11e9-8124-fe19c88541e9.png)

우선 메인을 보게 되면 입력받은 값을 각종 연산을 하고 flag.enc에 한 글자씩 써 넣는다.

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  unsigned int v3; // eax
  int v4; // eax
  unsigned int v5; // eax
  size_t v6; // rbx
  unsigned int ptr; // [rsp+Ch] [rbp-54h]
  int i; // [rsp+10h] [rbp-50h]
  unsigned int v10; // [rsp+14h] [rbp-4Ch]
  FILE *s; // [rsp+18h] [rbp-48h]
  char v12[8]; // [rsp+20h] [rbp-40h]
  __int64 v13; // [rsp+28h] [rbp-38h]
  __int64 v14; // [rsp+30h] [rbp-30h]
  __int64 v15; // [rsp+38h] [rbp-28h]
  __int64 v16; // [rsp+40h] [rbp-20h]
  unsigned __int64 v17; // [rsp+48h] [rbp-18h]

  v17 = __readfsqword(0x28u);
  *(_QWORD *)v12 = 0LL;
  v13 = 0LL;
  v14 = 0LL;
  v15 = 0LL;
  v16 = 0LL;
  printf("INPUT: ", a2, a3);
  __isoc99_scanf("%20s", v12);
  v3 = time(0LL);
  srand(v3);
  s = fopen("flag.enc", "wb");
  for ( i = 0; ; ++i )
  {
    v6 = i;
    if ( v6 >= strlen(v12) )
      break;
    v4 = rand();
    v10 = (unsigned __int8)(((unsigned int)(v4 >> 31) >> 24) + v4) - ((unsigned int)(v4 >> 31) >> 24);
    v5 = (unsigned int)((signed int)(255 - (v10 & v12[i])) >> 31) >> 24;
    ptr = (v10 | v12[i]) & ((unsigned __int8)(v5 + -1 - (v10 & v12[i])) - v5);
    fwrite(&ptr, 1uLL, 1uLL, s);
  }
  fclose(s);
  return 0LL;
}
```

근데 여기서 문제는 여기서부터였다. 조금 게싱이 필요한 문제이다. 이 flag.enc 파일이 생성된 날짜가 필요했다.

위에 보면 v3 = time(0) 그리고 이 v3를 srand() 값으로 넣어주고 밑에 이 시드를 이용해 rand() 함수를 사용한다. 

일단 time(0)를 하게되면 어떤 일이 일어나냐면 `1970년 1월 1일 00:00:00 UTC` 부터 현재까지의 경과 시간을 초로 리턴해준다. 

-> 참고 : [유닉스 시간](https://futurecreator.github.io/2018/06/07/computer-system-time/)

![](https://user-images.githubusercontent.com/32904385/62010409-5d077200-b1a5-11e9-8274-39a14312e12a.png)

그래서 1970년 1월 1일 00:00:00 UTC 부터 이 flag.enc 인코딩된 시간인 2017 7월 19일 9시 57분 27초까지 경과된 초를 가져와서 srand() 넣어주면 된다. 나는 유닉스 계산기를 이용해서 시간을 구했다.

![](https://user-images.githubusercontent.com/32904385/62010544-2b8fa600-b1a7-11e9-9617-3aece2a51039.png)

자 이제 flag.enc가 생성된 날짜의 time(0)를 구했고 이제 `1500425847` 을 시드 값으로 넣어주고 rand()를 이용해서 막 엄청난 연산을 한다 :) 이제 인코딩된 문자들의 값을 구해주고 쉽게 풀 수 있다.

```python
#!/usr/bin/python
# -*- coding: iso-8859-15 -*-

from ctypes import *
from z3 import *
import string

libc = CDLL('/lib/x86_64-linux-gnu/libc.so.6')
libc.srand(1500425847)
table=[0xAD,0xE4,0xAE,0x8D,0xA9,0x63,0xE0,0x48,0x79,0x34,0x10,0x1A,0xF4,0x51,0x2B,0xD3,0xCE,0x3C,0x98]

s = Solver()
a1 = [BitVec('a%i'%i,8)for i in range(len(table))]
for i in range(len(table)):
	random = libc.rand()
	shift_rand = (((random >> 31) >> 24) + random) - ((random >> 31) >> 24)
	s.add((shift_rand | a1[i]) & (((((255 - (shift_rand & a1[i])) >> 31) >> 24) + -1 - (shift_rand & a1[i])) - (((255 - (shift_rand & a1[i])) >> 31) >> 24)) == table[i])

print s.check()
print s.model()
m = s.model()
print ''.join(chr(int(str((m.evaluate(a1[i]))))) for i in range(len(table)))
```

**FLAG : `dimigo{Warming_up!}`**