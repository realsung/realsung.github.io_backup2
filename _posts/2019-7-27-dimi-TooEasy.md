---
title: "2017 Dimi CTF Final TooEasy"
date: 2019-7-27
tags: [dimi,z3]
categories: [CTF]
---

시드값 정해주고 랜덤 값 가져와서 어떠한 연산을 한 뒤에 마지막에는 저장되어 있는 값과 비교 연산을 한다.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v3; // ST10_1
  unsigned int v4; // esi
  int v5; // ecx
  char v6; // ST20_1
  char Str2[16]; // [esp+8h] [ebp-204h]
  __int128 v9; // [esp+18h] [ebp-1F4h]
  char v10; // [esp+28h] [ebp-1E4h]
  char v11; // [esp+29h] [ebp-1E3h]
  char Dst[256]; // [esp+108h] [ebp-104h]
  char v13[256]; // [esp+109h] [ebp-103h]

  memset(Dst, 0, 0xFFu);
  *(_OWORD *)Str2 = xmmword_402160;
  v9 = xmmword_402150;
  v10 = -114;
  memset(&v11, 0, 0xDEu);
  ((void (__cdecl *)(const char *, char))sub_401020)("Password: ", v3);
  sub_401050("%36s", (unsigned int)Dst);
  srand(0x3FD1CC7u);
  v4 = 0;
  if ( &Dst[strlen(Dst) + 1] != v13 )
  {
    do
    {
      v5 = rand() % 256;
      v6 = (v5 | Dst[v4]) & ~(v5 & Dst[v4]);
      Dst[v4] = v6;
      sub_401020("%d, ", v6);
      ++v4;
    }
    while ( v4 < strlen(Dst) );
  }
  if ( !strncmp(Dst, Str2, 0x21u) )
    sub_401020("\nCorrect\n");
  else
    sub_401020("\nWrong\n");
  return 0;
}
```

ctypes로 윈도우 라이브러리 불러와서 시드값 66919623 넣어주고 rand() 돌려서 브루트 포스 해줬다. 

```python
from ctypes import *

CDLL = CDLL('msvcrt')
CDLL.srand(66919623)
table=[0x4d,0xcb,0xc3,0xbb,0x19,0x0a,0x1a,0x7f,0x50,0xf8,0x18,0x08,0x89,0xc1,0xa8,0xcf,0xba,0xbe,0xec,0x75,0x90,0xe2,0x23,0x6d,0xa4,0xb7,0x35,0xf5,0xd1,0x9a,0x32,0x1a,0x8e]

flag =""
for i in range(len(table)):
	tmp = CDLL.rand() % 256
	for j in range(256):
		if ((tmp | j) & ~(tmp &j)) == table[i]:
			flag += chr(j)
print flag
```

이번에도 msvcrt 라이브러리에서 rand값만 가져와서 Solver를 이용해서 풀었다.

```python
from ctypes import *
from z3 import *

CDLL = CDLL('msvcrt')
CDLL.srand(66919623)
s = Solver()
table=[0x4d,0xcb,0xc3,0xbb,0x19,0x0a,0x1a,0x7f,0x50,0xf8,0x18,0x08,0x89,0xc1,0xa8,0xcf,0xba,0xbe,0xec,0x75,0x90,0xe2,0x23,0x6d,0xa4,0xb7,0x35,0xf5,0xd1,0x9a,0x32,0x1a,0x8e]
rand_table=[]
for i in range(len(table)):
	rand_table.append(CDLL.rand() % 256)
a1 = [BitVec('a%i'%i,8)for i in range(len(table))]
for i in range(len(table)):
	s.add((rand_table[i] | a1[i]) & ~(rand_table[i] & a1[i]) == table[i])
print s.check()
m = s.model()
print ''.join(chr(int(str(m.evaluate(a1[i])))) for i in range(len(table)))
```

**FLAG : `dimigo{warmup?_nooo_coldup_isit?}`**