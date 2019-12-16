---
title: "2017 Dimi CTF Final angry"
date: 2019-7-29
tags: [CTF]
categories: [CTF]
---

파일 입출력을 사용해서 값을 읽어와서 루틴에 맞는지 아닌지 검증해 마지막에 GOOD을 출력해준다.

그냥 Codegate 2018에 나온 RedVelvet과 유사한 문제였다.

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  int fd; // ST1C_4
  int v4; // ST1C_4
  char buf; // [rsp+20h] [rbp-20h]
  char v7; // [rsp+21h] [rbp-1Fh]
  char v8; // [rsp+22h] [rbp-1Eh]
  char v9; // [rsp+23h] [rbp-1Dh]
  char v10; // [rsp+24h] [rbp-1Ch]
  char v11; // [rsp+25h] [rbp-1Bh]
  char v12; // [rsp+26h] [rbp-1Ah]
  char v13; // [rsp+27h] [rbp-19h]
  char v14; // [rsp+28h] [rbp-18h]
  char v15; // [rsp+29h] [rbp-17h]
  unsigned __int64 v16; // [rsp+38h] [rbp-8h]

  v16 = __readfsqword(0x28u);
  fd = open("f0", 0, a3, a2);
  read(fd, &buf, 10uLL);
  close(fd);
  sub_4006A6(buf);
  sub_4006C6(v7);
  sub_4006E6(v8);
  sub_400706(v9);
  sub_400726(v10);
  sub_400746(v11);
  sub_40076E(v12);
  sub_40079C(v13);
  sub_4007C7(v14);
  sub_4007E7(v15);
  read(0, &buf, 10uLL);
  sub_400807(buf);
  sub_400827(v7);
  sub_400847(v8);
  sub_400873(v9);
  sub_400893(v10);
  sub_4008B3(v11);
  sub_4008D3(v12);
  sub_4008FB(v13);
  sub_40091B(v14);
  sub_400943(v15);
  read(0, &buf, 10uLL);
  sub_400963(buf);
  sub_40098B(v7);
  sub_4009AB(v8);
  sub_4009D6(v9);
  sub_4009F6(v10);
  sub_400A16(v11);
  sub_400A36(v12);
  sub_400A56(v13);
  sub_400A76(v14);
  sub_400A96(v15);
  read(0, &buf, 10uLL);
  sub_400ABE(buf);
  sub_400ADE(v7);
  sub_400B0A(v8);
  sub_400B35(v9);
  sub_400B61(v10);
  sub_400B81(v11);
  sub_400BAC(v12);
  sub_400BCC(v13);
  sub_400BEC(v14);
  sub_400C14(v15);
  read(0, &buf, 0xAuLL);
  sub_400C34(buf);
  sub_400C54(v7);
  sub_400C74(v8);
  sub_400C9C(v9);
  sub_400CC4(v10);
  sub_400CF8(v11);
  sub_400D18(v12);
  sub_400D38(v13);
  sub_400D63(v14);
  sub_400D8B(v15);
  v4 = open("f50", 0);
  read(v4, &buf, 10uLL);
  close(v4);
  sub_400DAB(buf);
  puts("GOOD");
  return 0LL;
}
```

그냥 노가다 했던 문제,,,

```python
from z3 import *

s = Solver()

a1 = [Int('a%i'%i) for i in range(51)]
s.add(a1[0] == 100)
s.add(a1[1] == 105)
s.add(a1[2] == 109)
s.add(a1[3] == 105)
s.add(a1[4] == 103)
s.add(a1[5] == 11544/104)
s.add(a1[6] == 11808/96)
s.add(a1[7] == 17612/148)
s.add(a1[8] == 104)
s.add(a1[9] == 121)
s.add(a1[10] == 95)
s.add(a1[11] == 121)
s.add(a1[12] == 1665/15)
s.add(a1[13] == 117)
s.add(a1[14] == 95)
s.add(a1[15] == 108)
s.add(a1[16] == 10989/99)
s.add(a1[17] == 111)
s.add(a1[18] == 11766/106)
s.add(a1[19] == 111)
s.add(a1[20] == 12210/110)
s.add(a1[21] == 107)
s.add(a1[22] == 21185/223)
s.add(a1[23] == 115)
s.add(a1[24] == 111)
s.add(a1[25] == 111)
s.add(a1[26] == 111)
s.add(a1[27] == 111)
s.add(a1[28] == 111)
s.add(a1[29] == 760/8)
s.add(a1[30] == 65)
s.add(a1[31] == 1105/17)
s.add(a1[32] == 11310/174)
s.add(a1[33] == 1170/15)
s.add(a1[34] == 78)
s.add(a1[35] == 17862/229)
s.add(a1[36] == 71)
s.add(a1[37] == 71)
s.add(a1[38] == 6958/98)
s.add(a1[39] == 82)
s.add(a1[40] == 82)
s.add(a1[41] == 82)
s.add(a1[42] == 9020/110)
s.add(a1[43] == 6230/70)
s.add(a1[44] == 2403/27)
s.add(a1[45] == 89)
s.add(a1[46] == 89)
s.add(a1[47] == 11151/177)
s.add(a1[48] == 4347/69)
s.add(a1[49] == 63)
s.add(a1[50] == 125)
print s.check()
m = s.model()
print ''.join(chr(int(str(m.evaluate(a1[i])))) for i in range(len(m)))
```

**FLAG : `dimigo{why_you_loooook_sooooo_AAANNNGGGRRRRYYYY???}`**