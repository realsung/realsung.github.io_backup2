---
title: "Stack Canary"
date: 2020-1-7
tags: [Canary]
categories: [Tip]
---



64비트 기준으로 작성했습니다.

SSP 보호기법은 stack overflow를 방지하기 위한 보호기법이다.

SFP와 BUF사이에 canary를 삽입해서 frame pointer 와 return address가 변조되면 `__stack_chk_fail` 을 호출한다.

64비트 기준 : BUF, canary, SFP, RET, ARG

[Link](https://bpsecblog.wordpress.com/2016/05/16/memory_protect_linux_1/) <- 보호기법에 대한 설명은 이곳에 정리 잘 되어있다.

```c
#include <stdio.h>

int main(){
	char buf[256];
	gets(buf);
	puts(buf);
	return 0;
}
```

간단한 c 프로그램을 짜줍니다.

```
[*] '/vagrant/ctfs/canary'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

stack canary 걸어놨습니다.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s; // [rsp+0h] [rbp-110h]
  unsigned __int64 v5; // [rsp+108h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  gets(&s, argv, envp);
  puts(&s);
  return 0;
}
```

Canary 걸려있는 바이너리를 hexray로 보면 v5가 canary다.

Stack Canary가 있는 바이너리와 없는 바이너리를 비교하겠습니다.

```assembly
pwndbg> disassemble main
Dump of assembler code for function main:
   0x00000000004005d6 <+0>:	push   rbp
   0x00000000004005d7 <+1>:	mov    rbp,rsp
   0x00000000004005da <+4>:	sub    rsp,0x110
   0x00000000004005e1 <+11>:	mov    rax,QWORD PTR fs:0x28
   0x00000000004005ea <+20>:	mov    QWORD PTR [rbp-0x8],rax
   0x00000000004005ee <+24>:	xor    eax,eax
   0x00000000004005f0 <+26>:	lea    rax,[rbp-0x110]
   0x00000000004005f7 <+33>:	mov    rdi,rax
   0x00000000004005fa <+36>:	mov    eax,0x0
   0x00000000004005ff <+41>:	call   0x4004c0 <gets@plt>
   0x0000000000400604 <+46>:	lea    rax,[rbp-0x110]
   0x000000000040060b <+53>:	mov    rdi,rax
   0x000000000040060e <+56>:	call   0x400490 <puts@plt>
   0x0000000000400613 <+61>:	mov    eax,0x0
   0x0000000000400618 <+66>:	mov    rdx,QWORD PTR [rbp-0x8]
   0x000000000040061c <+70>:	xor    rdx,QWORD PTR fs:0x28
   0x0000000000400625 <+79>:	je     0x40062c <main+86>
   0x0000000000400627 <+81>:	call   0x4004a0 <__stack_chk_fail@plt>
   0x000000000040062c <+86>:	leave
   0x000000000040062d <+87>:	ret
End of assembler dump.
```

Stack Canary ON

<br />

```
pwndbg> disassemble main
Dump of assembler code for function main:
   0x0000000000400566 <+0>:	push   rbp
   0x0000000000400567 <+1>:	mov    rbp,rsp
   0x000000000040056a <+4>:	sub    rsp,0x100
   0x0000000000400571 <+11>:	lea    rax,[rbp-0x100]
   0x0000000000400578 <+18>:	mov    rdi,rax
   0x000000000040057b <+21>:	mov    eax,0x0
   0x0000000000400580 <+26>:	call   0x400450 <gets@plt>
   0x0000000000400585 <+31>:	lea    rax,[rbp-0x100]
   0x000000000040058c <+38>:	mov    rdi,rax
   0x000000000040058f <+41>:	call   0x400430 <puts@plt>
   0x0000000000400594 <+46>:	mov    eax,0x0
   0x0000000000400599 <+51>:	leave
   0x000000000040059a <+52>:	ret
End of assembler dump.
```

Stack Canary OFF

<br />

보호기법 해제한 것과 안한 것의 차이를 보면 아래 코드가 더 추가됐습니다.

```
   0x00000000004005e1 <+11>:	mov    rax,QWORD PTR fs:0x28
   0x00000000004005ea <+20>:	mov    QWORD PTR [rbp-0x8],rax
   0x00000000004005ee <+24>:	xor    eax,eax
   0x0000000000400618 <+66>:	mov    rdx,QWORD PTR [rbp-0x8]
   0x000000000040061c <+70>:	xor    rdx,QWORD PTR fs:0x28
   0x0000000000400625 <+79>:	je     0x40062c <main+86>
   0x0000000000400627 <+81>:	call   0x4004a0 <__stack_chk_fail@plt>
```

64비트 기준으로 QWORD PTR fs:0x28에 canary가 저장됩니다. (32bit는 gs:0x14) canary 는 `__libc_start_main` 함수에서 지정해줍니다. 

main+11 : fs:0x28에 저장되어있는 canary를 rax에 저장해줍니다.

main+20 : canary를 rbp-0x8 위치에 저장합니다. 

main+24 : 레지스터 초기화해줍니다.

...

main+66 : rbp-0x8에 넣었던 canary를 rdx에 넣어줍니다.

main+70 : rbp-0x8과 fs:0x28에 있던 카나리 값과 같은지 비교해줍니다.

main+79 : 두 값이 같으면 main+86(0x40062c)으로 가고 아니면 그냥 밑에 코드를 실행합니다.

main+81 : __stack_chk_fail 함수를 실행합니다.

<br />

## __stack_chk_fail

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
extern char **__libc_argv attribute_hidden;
void
__attribute__ ((noreturn))
__stack_chk_fail (void)
{
  __fortify_fail_abort (false, "stack smashing detected");
}
strong_alias (__stack_chk_fail, __stack_chk_fail_local)
```

gdb로 자세히 보면 `__fortify_fail` 함수를 실행시켜줍니다. 내부에서  `__libc_message` 함수로 `stack smashing detected`  띄워주고 `raise` 함수 호출해서 syscall 234번 `sys_tgkill` 함수를 불러 pid를 죽이고 signal을 띄워줘서 종료시킵니다. *버전 마다 다를 수도 있습니다.*

추가로 함수 리턴 값에 오버플로우가 나지 않는 코드는 컴파일하면서 Canary를 `__stack_chk_guard` 라는 전역변수에 저장합니다.

<br />

## TCB (Task Control Block)



```c
typedef struct
{
  void *tcb;		/* Pointer to the TCB.  Not necessarily the
			   thread descriptor used by libpthread.  */
  dtv_t *dtv;
  void *self;		/* Pointer to the thread descriptor.  */
  int multiple_threads;
  uintptr_t sysinfo;
  uintptr_t stack_guard;
  uintptr_t pointer_guard;
  int gscope_flag;
#ifndef __ASSUME_PRIVATE_FUTEX
  int private_futex;
#else
  int __unused1;
#endif
  /* Reservation of some values for the TM ABI.  */
  void *__private_tm[5];
} tcbhead_t;
```



.. 추가 예정

<br />

틀린 부분은 댓글로 알려주시면 감사하겠습니다 ㅎㅎ