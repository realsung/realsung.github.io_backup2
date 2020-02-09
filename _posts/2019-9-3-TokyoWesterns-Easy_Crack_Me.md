---
title: "2019 TokyoWesterns CTF 5th Easy Crack Me"
date: 2019-9-3
tags: [TokyoWesterns]
categories: [TokyoWesterns]
---

Reverse Warmup 문제로 나온 문제다. 

main 코드를 보면 연산하고 memcmp로 비교한다. 분기들을 다 만족 시켜주면 된다.

```c
if ( a1 == 2 )
  {
    s = a2[1];
    if ( strlen(a2[1]) != 39 )
    {
      puts("incorrect");
      exit(0);
    }
    if ( memcmp(s, "TWCTF{", 6uLL) || s[38] != 125 )
    {
      puts("incorrect");
      exit(0);
    }
```

* 우선 argv로 입력받은 값은 39글자인지 비교한다.
* 입력 받은 값이 TWCTF{ 로 시작하고 뒤에 } 붙여야한다.

<br />

```c
		s1 = 0LL;
    v38 = 0LL;
    v39 = 0LL;
    v40 = 0LL;
    v41 = 0LL;
    v42 = 0LL;
    v43 = 0LL;
    v44 = 0LL;
    v46 = 3978425819141910832LL;
    v47 = 7378413942531504440LL;
    for ( i = 0; i <= 15; ++i )
    {
      for ( j = strchr(s, *(&v46 + i)); j; j = strchr(j + 1, *(&v46 + i)) )
        ++*(&s1 + i);
    }
    if ( memcmp(&s1, &unk_400F00, 0x40uLL) )
    {
      puts("incorrect");
      exit(0);
    }
```

* { }사이는 "0123456789abcdef" 만 들어간다. 16진수 값만 들어간다고 한다. 각각 개수는 `3, 2, 2, 0, 3, 2, 1, 3, 3, 1, 1, 3, 1, 2, 2, 3` 를 만족해야한다. 

<br />

```c
for ( k = 0; k <= 7; ++k )
    {
      v10 = 0;
      v11 = 0;
      for ( l = 0; l <= 3; ++l )
      {
        v5 = s[4 * k + 6 + l];
        v10 += v5;
        v11 ^= v5;
      }
      *(&v21 + k) = v10;
      *(&v25 + k) = v11;
    }

if ( memcmp(&v21, &unk_400F40, 0x20uLL) || memcmp(&v25, &unk_400F60, 0x20uLL) )
    {
      puts("incorrect");
      exit(0);
    }
```

* s[4 * k + 6 + l] 값들을 xor 연산과 덧셈연산 한 값들이 테이블 값들이 같도록 해야한다.

<br />

```c
for ( m = 0; m <= 7; ++m )
    {
      v14 = 0;
      v15 = 0;
      for ( n = 0; n <= 3; ++n )
      {
        v6 = s[8 * n + 6 + m];
        v14 += v6;
        v15 ^= v6;
      }
      *(&v29 + m) = v14;
      *(&v33 + m) = v15;
    }

if ( memcmp(&v29, &unk_400FA0, 0x20uLL) || memcmp(&v33, &unk_400F80, 0x20uLL) )
    {
      puts("incorrect");
      exit(0);
    }
```

* s[8 * n + 6 + m] 값들을 xor 연산과 덧셈연산 한 값들이 테이블 값들이 같도록 해야한다.

<br />

```c
for ( ii = 0; ii <= 31; ++ii )
    {
      v7 = s[ii + 6];
      if ( v7 <= 47 || v7 > 57 )
      {
        if ( v7 <= 96 || v7 > 102 )
          v45[ii] = 0;
        else
          v45[ii] = 128;
      }
      else
      {
        v45[ii] = 255;
      }
    }
    if ( memcmp(v45, &unk_400FC0, 0x80uLL) )
    {
      puts("incorrect");
      exit(0);
    }
```

* 이곳은 s의 문자열 범위 지정해준다. 

<br />

```c
v18 = 0;
    for ( jj = 0; jj <= 15; ++jj )
      v18 += s[2 * (jj + 3)];
    if ( v18 != 1160 )
    {
      puts("incorrect");
      exit(0);
    }
```

* s[2 * (jj + 3)]의 값들의 합이 1160이면 된다.

<br />

```c
if ( s[37] != 53 || s[7] != 102 || s[11] != 56 || s[12] != 55 || s[23] != 50 || s[31] != 52 )
    {
      puts("incorrect");
      exit(0);
    }
```

* 각각 인덱스의 값을 만족시키면 된다.

<br />

```python
from z3 import * 

s = Solver()

a1 = [BitVec('a%i'%i,8) for i in range(39)]

s.add(a1[0] == ord('T'))
s.add(a1[1] == ord('W'))
s.add(a1[2] == ord('C'))
s.add(a1[3] == ord('T'))
s.add(a1[4] == ord('F'))
s.add(a1[5] == ord('{'))
s.add(a1[38] == ord('}'))
s.add(a1[37] == 53 , a1[7] == 102 , a1[11] == 56 , a1[12] == 55 , a1[23] == 50 , a1[31] == 52)

v45 = [0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66]
# 0 1 2 3 4 5 6 7 8 9 a b c d e f 
tb1 = [3, 2, 2, 0, 3, 2, 1, 3, 3, 1, 1, 3, 1, 2, 2, 3]
tb2 = [0x015E, 0x00DA, 0x012F, 0x0131, 0x0100, 0x0131, 0x00FB, 0x0102]
tb3 = [82, 12, 1, 15, 92, 5, 83, 88]
tb4 = [1, 87, 7, 13, 13, 83, 81, 81]
tb5 = [0x0129, 0x0103, 0x012B, 0x0131, 0x0135, 0x010B, 0x00FF, 0x00FF]
tb6 = [128, 128, 255, 128, 255, 255, 255, 255, 128, 255, 255, 128, 128, 255, 255, 128, 255, 255, 128, 255, 128, 128, 255, 255, 255, 255, 128, 255, 255, 255, 128, 255]

for k in range(8):
	v10 = 0
	v11 = 0
	for l in range(4):
		v5 = a1[4 * k + 6 + l]
		v10 += v5
		v11 ^= v5
	s.add(tb2[k] == v10)
	s.add(tb3[k] == v11)

for m in range(8):
	v14 = 0
	v15 = 0
	for n in range(4):
		v6 = a1[8 * n + 6 + m]
		v14 += v6
		v15 ^= v6
	s.add(tb5[m] == v14)
	s.add(tb4[m] == v15)


v18 = 0
for jj in range(16):
	v18 += a1[2 * (jj + 3)]
s.add(v18 == 1160)

for i in range(32):
    if(tb6[i]==128):
        s.add(a1[i+6]>=97)
        s.add(a1[i+6]<=102)
    else:
        s.add(a1[i+6]>=48)
        s.add(a1[i+6]<=57)


for i,ch in enumerate("0123456789abcdef"):
	cnt = 0
	for x in a1:
		cnt += If(x == ord(ch),1,0)
	s.add(cnt == tb1[i])
if s.check() == sat:
	m = s.model()
	print ''.join(chr(int(str(m.evaluate(a1[i]))))for i in range(39))
```

**FLAG : `TWCTF{df2b4877e71bd91c02f8ef6004b584a5}`**