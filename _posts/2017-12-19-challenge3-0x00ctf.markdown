---
title: "0x00ctf - Challenge 003"
date: 2017-12-19 05:21:00
tags: [ctf]
categories: [ctf]
---

<!--more-->
![Image0](/images/0x00ctf/i0.png)

This application uses **Process Hollowing**.  
Lets take a look at the entry point.

```x86asm
    public start
start   proc near
    sub esp, 1Ch
    mov [esp], 2
    call    ds:__set_app_type
    call    _Start
start   endp
```

Since this is a GUI App (\_\_set\_app\_type \{GUI\}), there must be a call to WinMain with first argument a the module base. At the end of the \_Start routine, before the call to \_cexit, we have the call to \_Start1 at 0x41eff0. This routine prepares the arguments to be passed to WinMain.

```x86asm
loc_41F074:			; CODE XREF: sub_41EFF0+7Ej
	mov	[esp+74h+lpStartupInfo], 0 ; lpModuleName
	call	GetModuleHandleA
	sub	esp, 4
	mov	[esp+0Ch], esi          ; wShowFlags
	mov	[esp+8], ebx            ; lpszCmdLine
	mov	dword ptr [esp+4], 0    ; hPrevInstance
	mov	[esp], eax              ; hInstance
	call	sub_401C24              ; WinMain
	sub	esp, 10h
	lea	esp, [ebp-0Ch]
	pop	ecx
	pop	ebx
	pop	esi
	pop	ebp
	lea	esp, [ecx-4]
	retn


; int __stdcall	WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
WinMain		proc near		; CODE XREF: sub_41EFF0+A6p

var_18		= dword	ptr -18h
hInstance	= dword	ptr  8
hPrevInstance	= dword	ptr  0Ch
lpCmdLine	= dword	ptr  10h
nShowCmd	= dword	ptr  14h

		push	ebp
		mov	ebp, esp
		push	esi
		push	ebx
		sub	esp, 10h
		mov	[esp+18h+var_18], 10h
		call	sub_41E040
		mov	ecx, eax
		mov	ebx, eax
		call	sub_401CA4
		mov	ecx, ebx
		call	sub_401D80
		mov	ecx, ebx
		call	sub_401EE0
		mov	ecx, ebx
		call	sub_401F2C
		mov	ecx, ebx
		call	sub_401F96
		test	ebx, ebx
		jz	short loc_401C84
		mov	ecx, ebx
		call	sub_401D28
		mov	[esp+18h+var_18], ebx
		call	sub_41DFE0
		jmp	short loc_401C84
; ---------------------------------------------------------------------------
		mov	esi, eax
		mov	[esp+18h+var_18], ebx
		call	sub_41DFE0
		mov	[esp+18h+var_18], esi
		call	sub_40D690

loc_401C84:				; CODE XREF: WinMain+3Bj WinMain+4Cj
		add	esp, 10h
		xor	eax, eax
		pop	ebx
		pop	esi
		pop	ebp
		retn	10h
WinMain		endp
```

The routine sub\_401f96 is quite big. But we can see a lot of calls to **GetProcAddress** and **LoadLibrary**. When we step through in the debugger (putting a breakpoint after each call to **GetProcAddress**), the app first calls **CreateProcess** to fork itself and the new process is in suspended state. It then the program stores its **CONTEXT** in a local variable and unmaps its text section in the newly created process.

It then allocates a new region memory at its base address of 0xA5000 bytes with RWX permission. It then writes new bytes from 0x600020 to its module base (0x400000), changes the CONTEXT of the new process and calls **ResumeThread** (at .text:00402538).  
Don't let the process execute the ResumeThread.

Now fire up another instance of the debugger you are using and attach to the new process (the new process is in suspended state). Let the new debugger instance break on access to the module. If you are using IDA, then right click on challenge-003.exe in the modules window and select "Break on Access".

Now let the first process execute the ResumeThread routine. You'll see that the debugger breaks into the newly created process.

Here is what the new process looks like

```x86asm
main proc near				; CODE XREF: challenge_003.exe:0045555Ap

var_34=	byte ptr -34h
var_12=	byte ptr -12h
var_4= dword ptr -4

    push	ebp
    mov	    ebp, esp
    sub	    esp, 34h
    mov	    eax, dword_498EA4
    xor	    eax, ebp
    mov	    [ebp+var_4], eax
    call	sub_401090
    test	al, al
    jnz	    short failure
    push	30h
    lea	    eax, [ebp+var_34]
    push	0
    push	eax
    call	sub_456760
    add	    esp, 0Ch
    lea	    eax, [ebp+var_34]		 ; zeroed 23 bytes
    push	eax
    sub	    esp, 8
    call	find_flag
    add	    esp, 0Ch
    mov	    [ebp+var_12], 0
    lea	    eax, [ebp+var_34]
    push	40h                     ; MB_ICONINFORMATION
    push	offset aCongratulation	; "Congratulations!"
    push	eax                     ; Our Flag
    push	0                       ; hWnd
    call	off_46F15C              ; MessageBox

failure:				; CODE XREF: main+17j
    mov	    ecx, [ebp+var_4]
    xor	    eax, eax
    xor	    ecx, ebp
    call	sub_45539A
    mov	    esp, ebp
    pop	    ebp
    retn	10h
main endp
```

We can get the flag by zeroing the **eax** register after the routine sub\_401090 returns or by changing the **eip** to the instruction ```push 30h```
