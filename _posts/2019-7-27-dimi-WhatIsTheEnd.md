---
title: "2017 Dimi CTF Prequal WhatIsTheEnd"
date: 2019-7-27
tags: [CTF]
categories: [CTF]
---

메인을 보면 33글자를 입력받을 받는다.  그리고 어떠한 연산을 하고 맞는지 비교해준다.

```c
int __cdecl main(int a1)
{
  int v2; // [esp-Ah] [ebp-70h]
  int v3; // [esp-6h] [ebp-6Ch]
  int v4; // [esp-2h] [ebp-68h]
  char v5; // [esp+1h] [ebp-65h]
  signed int i; // [esp+2h] [ebp-64h]
  signed int j; // [esp+2h] [ebp-64h]
  char v8; // [esp+6h] [ebp-60h]
  char v9; // [esp+7h] [ebp-5Fh]
  char v10; // [esp+8h] [ebp-5Eh]
  char v11; // [esp+9h] [ebp-5Dh]
  char v12; // [esp+Ah] [ebp-5Ch]
  char v13; // [esp+Bh] [ebp-5Bh]
  char v14; // [esp+Ch] [ebp-5Ah]
  char v15; // [esp+Dh] [ebp-59h]
  char v16; // [esp+Eh] [ebp-58h]
  char v17; // [esp+Fh] [ebp-57h]
  char v18; // [esp+10h] [ebp-56h]
  char v19; // [esp+11h] [ebp-55h]
  char v20; // [esp+12h] [ebp-54h]
  char v21; // [esp+13h] [ebp-53h]
  char v22; // [esp+14h] [ebp-52h]
  char v23; // [esp+15h] [ebp-51h]
  char v24; // [esp+16h] [ebp-50h]
  char v25; // [esp+17h] [ebp-4Fh]
  char v26; // [esp+18h] [ebp-4Eh]
  char v27; // [esp+19h] [ebp-4Dh]
  char v28; // [esp+1Ah] [ebp-4Ch]
  char v29; // [esp+1Bh] [ebp-4Bh]
  char v30; // [esp+1Ch] [ebp-4Ah]
  char v31; // [esp+1Dh] [ebp-49h]
  char v32; // [esp+1Eh] [ebp-48h]
  char v33; // [esp+1Fh] [ebp-47h]
  char v34; // [esp+20h] [ebp-46h]
  char v35; // [esp+21h] [ebp-45h]
  char v36; // [esp+22h] [ebp-44h]
  char v37; // [esp+23h] [ebp-43h]
  char v38; // [esp+24h] [ebp-42h]
  char v39; // [esp+25h] [ebp-41h]
  __int16 v40; // [esp+26h] [ebp-40h]
  int v41; // [esp+28h] [ebp-3Eh]
  __int16 v42; // [esp+2Ch] [ebp-3Ah]
  int v43; // [esp+2Eh] [ebp-38h]
  int v44; // [esp+32h] [ebp-34h]
  int v45; // [esp+36h] [ebp-30h]
  int v46; // [esp+3Ah] [ebp-2Ch]
  int v47; // [esp+3Eh] [ebp-28h]
  int v48; // [esp+42h] [ebp-24h]
  int v49; // [esp+46h] [ebp-20h]
  unsigned int v50; // [esp+4Ah] [ebp-1Ch]
  int v51; // [esp+4Eh] [ebp-18h]
  int v52; // [esp+52h] [ebp-14h]
  int v53; // [esp+56h] [ebp-10h]
  int *v54; // [esp+5Ah] [ebp-Ch]

  v54 = &a1;
  v50 = __readgsdword(0x14u);
  v40 = 0;
  v8 = 172;
  v9 = 171;
  v10 = 30;
  v11 = 44;
  v12 = 166;
  v13 = 161;
  v14 = 156;
  v15 = 232;
  v16 = 255;
  v17 = 97;
  v18 = 9;
  v19 = 83;
  v20 = 37;
  v21 = 20;
  v22 = 130;
  v23 = 60;
  v24 = 165;
  v25 = 145;
  v26 = 165;
  v27 = 219;
  v28 = 233;
  v29 = 4;
  v30 = 96;
  v31 = 224;
  v32 = 26;
  v33 = 110;
  v34 = 97;
  v35 = 65;
  v36 = 183;
  v37 = 79;
  v38 = 83;
  v39 = 205;
  LOBYTE(v40) = 27;
  v41 = 0;
  v49 = 0;
  memset((&v42 & 0xFFFFFFFC), 0, 4 * (((&v41 - (&v42 & 0xFFFFFFFC) + 34) & 0xFFFFFFFC) >> 2));
  printf("INPUT: ");
  __isoc99_scanf(
    "%33s",
    &v41,
    v2,
    v3,
    v4,
    0,
    *&v8,
    *&v12,
    *&v16,
    *&v20,
    *&v24,
    *&v28,
    *&v32,
    *&v36,
    *&v40,
    *(&v41 + 2),
    v43,
    v44,
    v45,
    v46,
    v47,
    v48,
    v49);
  v53 = 0;
  v52 = 1;
  v51 = 0;
  v5 = ptrace(0, 0, 1, 0);
  for ( i = 0; i <= 32; ++i )
    *(&v41 + i) ^= v5 ^ rand();
  for ( j = 0; j <= 32; ++j )
  {
    if ( (*(&v8 + j) ^ *(&v41 + j)) != *(&v41 + j + 1) )
    {
      puts("Nope!");
      return -1;
    }
  }
  puts("Correct!");
  return 0;
}
```

여기서는 `v8[i] ^ input[i] ^ rand[i] == input[i+1] ^ rand[i+1]` 이러한 연산을 하고 있는데 우선 v8은 고정 값이고 rand()는 시드 값이 없으니까 그냥 긁어오면 된다. 

ptrace는 디버깅중이 아니니까 0을 리턴하니까 xor연산해도 같은 값이 나오니까 무시해도 된다. 디버깅 중이면 -1을 리턴한다.

나는 라이브러리를 불러와서 rand값을 다 구하고 z3 이용해서 풀었다.

```python
from ctypes import CDLL
from z3 import *

libc = CDLL('/lib/x86_64-linux-gnu/libc.so.6')
rand_table = []
table = [172,171,30,44,166,161,156,232,255,97,9,83,37,20,130,60,165,145,165,219,233,4,96,224,26,110,97,65,183,79,83,205,27]
for i in range(33):
        rand_table.append(libc.rand()%256)
s = Solver()
a1 = [BitVec('a%i'%i,8)for i in range(33)]
s.add(a1[0] == ord('d'))
s.add(a1[1] == ord('i'))
s.add(a1[2] == ord('m'))
s.add(a1[3] == ord('i'))
for i in range(32):
        s.add(table[i] ^  a1[i] ^ rand_table[i] == a1[i+1] ^ rand_table[i+1])

print s.check()
m = s.model()
print ''.join(chr(int(str((m.evaluate(a1[i]))))) for i in range(33))
```

**FLAG : `dimigo{Always_String_END_is_NULL}`**

