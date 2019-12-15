---
title: "0x00ctf - Challenge 004"
date: 2017-12-19 03:01:00
tags: [ctf]
categories: [ctf]
---

<!--more-->
![Image0](/images/0x00ctf/i1.png)

```x86asm
; Attributes: noreturn
	public start
start	proc near
	xor	ebp, ebp
	mov	r9, rdx
	pop	rsi
	mov	rdx, rsp
	and	rsp, 0FFFFFFFFFFFFFFF0h
	push	rax
	push	rsp
	mov	r8, offset nullsub_1
	mov	rcx, offset loc_400B90  ; init routine
	mov	rdi, offset sub_400B62  ; main routine
	call	__libc_start_main
	hlt
start	endp

; the main routine
sub_400B62  proc near		    ; DATA XREF: start+1D
	push	rbp
	mov	rbp, rsp
	mov	edi, offset aHello	    ; "Hello World!\n"
	call	puts
	mov	eax, 0
	pop	rbp
	retn
sub_400B62  endp
```

Run the program from terminal, and we find this

![iMage](/images/0x00ctf/i2.png)

But the main routine prints just "Hello World" followed by two newlines.  
WTF !!

Well, let's go to the init routine which is called before main.

```x86asm
loc_400B90:				; DATA XREF: start+16o
	push	r15
	mov	r15d, edi
	push	r14
	mov	r14, rsi
	push	r13
	mov	r13, rdx
	push	r12
	lea	r12, off_601E08         ; array of functions
	push	rbp
	lea	rbp, off_601E18
	push	rbx
	sub	rbp, r12
	xor	ebx, ebx
	sar	rbp, 3
	sub	rsp, 8
	call	_init_proc
	test	rbp, rbp
	jz	short loc_400BE6
	nop	dword ptr [rax+rax+00000000h]

loc_400BD0:
	mov	rdx, r13
	mov	rsi, r14
	mov	edi, r15d
	call	qword ptr [r12+rbx*8]    ; execute each function in the array
	add	rbx, 1
	cmp	rbx, rbp
	jnz	short loc_400BD0

loc_400BE6:
	add	rsp, 8
	pop	rbx
	pop	rbp
	pop	r12
	pop	r13
	pop	r14
	pop	r15
	retn

; -------------------------------------------------
off_601E08: dq offset sub_4007B0, offset sub_400B49
; -------------------------------------------------

sub_400B49  proc near
    push    rbp
    mov rbp, rsp
    mov [rbp-8], offset off_602020    ; points to puts routine
    mov rax, [rbp-8]
    mov qword ptr [rax], offset sub_400AC4
    pop rbp
    retn
sub_400B49  endp
```

The second routine 'sub\_400B49' is quite interesting.  
This routine changes the pointer to **puts** routine to a new function **sub\_400AC4**. So that when puts is called, sub\_400AC4 is called instead of the **libc puts** routine.

```x86asm
sub_400AC4	proc near

s		= qword	ptr -18h
var_8		= dword	ptr -8
var_4		= dword	ptr -4

	push	rbp
	mov	rbp, rsp
	sub	rsp, 20h
	mov	[rbp+s], rdi
	mov	[rbp+var_8], 0
	mov	[rbp+var_4], 0
	mov	esi, 0
	mov	edi, 0
	call	sub_400B77	; ptrace
	mov	[rbp+var_4], eax
	cmp	[rbp+var_4], 0
	jns	short loc_400B02
	mov	cs:is_debugger_present, 1
	jmp	short loc_400B0C
loc_400B02:
	mov	cs:is_debugger_present, 0
loc_400B0C:
	mov	eax, cs:is_debugger_present
	test	eax, eax
	jnz	short loc_400B22
	mov	eax, 0
	call	sub_400A03
	jmp	short loc_400B42
loc_400B22:
	mov	rax, [rbp+s]
	mov	rdi, rax	; s
	call	strlen
	mov	rdx, rax	; n
	mov	rax, [rbp+s]
	mov	rsi, rax	; buf
	mov	edi, 1		; fd
	call	write
loc_400B42:
	mov	eax, 0
	leave
	retn
sub_400AC4	endp

sub_400B77	proc near
	mov	ebx, 0C3050Fh    ; 0fh, 05h -- syscall and 0c3h -- ret
	lea	r12, sub_400B77
	inc	r12
	push	r12
	mov	eax, 65h         ; sys_ptrace
	retn
sub_400B77	endp
```

In sub\_400B77, we see that the routine jumps to one byte after itself, which is `syscall ret`.  
So the routine first checks if a debugger is running. If it's being run in a debugger, **ptrace** returns -1 and the routine prints "Hello World" using **write** syscall. Otherwise it calls sub\_400A03 and exits.

The strings are decoded with the following algorithm

```c
void decode(char* str, int len)
{
    char buf[] = {0x12, 0xf4, 0xe8, 0x2a, 0x0a, 0xe2};
    for (int i = 0; i < len; ++i)
        putchar(buf[i%6]^str[i]);
    fflush(stdout);
}
```

```x86asm
sub_400A03	proc near		; CODE XREF: sub_400AC4+57p

password	= byte ptr -90h
var_8		= qword	ptr -8

		push	rbp
		mov	rbp, rsp
		sub	rsp, 90h
		mov	rax, fs:28h
		mov	[rbp+var_8], rax
		xor	eax, eax
		mov	edx, cs:dword_6020A0
		mov	rax, cs:off_6020A8
		mov	esi, edx
		mov	rdi, rax
		call	decode                  ; "Welcome to the Twinlight Zone!!!"
		mov	edx, cs:dword_6020B0
		mov	rax, cs:off_6020B8
		mov	esi, edx
		mov	rdi, rax
		call	decode                  ; "Password: "
		lea	rax, [rbp+password]
		mov	edx, 80h	; n
		mov	esi, 0		; c
		mov	rdi, rax	; s
		call	memset
		lea	rax, [rbp+password]
		mov	edx, 80h	; nbytes
		mov	rsi, rax	; buf
		mov	edi, 0		; fd
		call	read
		cmp	rax, 9                  ; So len(password) must be 8
		jnz	short invalid_passwd
		lea	rax, [rbp+password]
		mov	rdi, rax
		call	check_password

invalid_passwd:				; CODE XREF: sub_400A03+7Ej
		mov	edx, cs:dword_6020C0
		mov	rax, cs:off_6020C8
		mov	esi, edx
		mov	rdi, rax
		call	decode                  ; "Keep Trying!"
		mov	eax, 0
		mov	rcx, [rbp+var_8]
		xor	rcx, fs:28h
		jz	short finish
		call	__stack_chk_fail
; ---------------------------------------------------------------------------

finish:				; CODE XREF: sub_400A03+B8j
		leave
		retn
sub_400A03	endp
```

From the above listing, the program first prints the welcome message and if the length of password is not 9, the program prints "Keep Trying" otherwise it proceeds to 'check\_password'.

```c
void check_password(char* password)
{
    char xor[] = {0x30, 0x78, 0x30, 0x30, 0x43, 0x54, 0x46, 0x7b};
    char str[] = {
        0x01, 0x16, 0x79, 0x44, 0x04, 0x64, 0x12,
        0x5A, 0x01, 0x0C, 0x2F, 0x21, 0x72, 0x53,
        0x60, 0x16, 0x02, 0x2A, 0x16, 0x24, 0x33,
        0x62, 0x60, 0x7B, 0x02, 0x13, 0x43
    };
    for (int i = 0; i < 8; ++i) {
        if (password[i]^str[i]^xor[i])
            return -1;
    }
    /* Print Flag */
    for (int i = 0; i < 27; ++i) {
        putchar(str[i]^password[i%8]);
    }
}
```

Now, I think you can find out the password :)

![Image1](/images/0x00ctf/i3.png)
