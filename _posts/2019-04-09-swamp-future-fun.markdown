---
title: "Deobfuscating MoVfuscator - Part 2"
date: 2019-04-09
categories: ["reversing", "movfuscator"]
tags: ["reversing", "movfuscator"]
---

Hello there !  
Today I'll be analyzing another MoVfuscated binary, from Swamp CTF 2019 using IDA Free

    Deep on the web, I discovered a secret key validation.
    It appeared to be from the future, and it only had one sentence: "Risk speed for security".
    Something seems fishy, you should try to break the key and find the secret inside!

    -= Created by noopnoop =-
<!--more-->

We know that the MoVfuscator stack consists of an array of addresses.  
Let `stack[i]` store the value `&A[i]`. Then we have the invariant `stack[i]-&stack[i] == 0x200064`  

`fp` and `NEW_STACK` are pointers to the array `stack`. `fp` denotes the frame pointer, and `NEW_STACK` denotes the stack top pointer.

We also know that the stack grows towards lower address. So, how do we push and pop ?

## Push

```
&stack[i]   = stack[i] - 0x200064
&stack[i+1] = &stack[i] - 4
            = stack[i] - 0x200068
stack[i+1]  = *(stack[i] - 0x200068)
stack[i+2]  = *(stack[i+1] - 0x200068)
...
```

![push](/images/swamp/push.png)

## Pop

```
&stack[i]   = stack[i] - 0x200064
&stack[i-1] = &stack[i] + 4
            = stack[i] - 0x200060
stack[i-1]  = *(stack[i] - 0x200060)
stack[i-2]  = *(stack[i-1] - 0x200060)
...
```

![pop](/images/swamp/pop.png)

## Function Call

###  User Defined Functions

![call_user](/images/swamp/call.png)

It pushes the return address, and then sets the `target` variable to `branch_temp`. So, the above sequence, skips through until it reaches 0x805036A

###  External Functions

![ecall](/images/swamp/ecall.png)

These functions are called through a **SIGSEGV**.

Every movfuscator instruction except the ALU ops are conditional. That is the operation depends on `on` variable. So, how are jumps, conditionals implemented ?

Jumps and conditionals are implemented using a `target` variable. Whenever you see `target` being compared with a virtual address, you can tell it is the **beginning of a basic block**.

3.  Loops  
For example, let's consider the following for loop

```c
for (int i = 0; i < 10; i++)
{
    // ...
}
```

It would compile to something like this

```x86asm
    mov i, 0
    jmp L2
L1:
    ; ...
    add i, 1
L2:
    cmp i, 10
    jl L1
```

And the movfuscator equivalent is

```x86asm
master_loop:
    ; ...
    mov target, offset L2

L1:
    cmp target, offset L1
    jnz L2

    ; ... loop body ...
    mov target, offset L2

L2:
    cmp target, offset L2
    jnz next_block

    ; ... loop check ...
    mov target, offset L1

    ; ... remaining code ...
    ; throw a SIGILL to jump to master_loop
```

In fact, there is only one loop (the `master_loop`).  So, it's the `target` variable that controls the flow.

The `master_loop` executes the following

```x86asm
master_loop:
    mov esp, NEW_STACK
    mov eax, sesp
    mov edx, 4
    add eax, edx
    push eax
    push dword [eax-4]
    push 0x804854e          ; return address after calling 0x805036a
    mov target, 0x805036a   ; main()
    ; ...
```

Every basic block begins with the following sequence of instructions

```x86asm
mov eax, target
cmp eax, 0xABCD
```

For example,
![main_start](/images/swamp/basic_block.png)

The block is executed if the comparison is true. The function prologue consists of a sequence of register saves into the stack.

```x86asm
.text:08050544                 mov     eax, fp
.text:08050549                 mov     stack_temp, eax
.text:0805054E                 mov     eax, offset NEW_STACK
.text:08050553                 mov     edx, on
.text:08050559                 mov     data_p, eax
.text:0805055E                 mov     eax, sel_data[edx*4]
.text:08050565                 mov     edx, NEW_STACK
.text:0805056B                 mov     edx, [edx-200068h]
.text:08050571                 mov     [eax], edx
.text:08050573                 mov     eax, NEW_STACK
.text:08050578                 mov     edx, on
.text:0805057E                 mov     data_p, eax
.text:08050583                 mov     eax, sel_data[edx*4]
.text:0805058A                 mov     edx, stack_temp
.text:08050590                 mov     [eax], edx
 ... snip ...
.text:08050709                 mov     eax, NEW_STACK
.text:0805070E                 mov     edx, on
.text:08050714                 mov     data_p, eax
.text:08050719                 mov     eax, sel_data[edx*4]
.text:08050720                 mov     edx, stack_temp
.text:08050726                 mov     [eax], edx
.text:08050728                 mov     edx, dword_81FD234
.text:0805072E                 mov     [eax+4], edx

.text:08050731                 mov     eax, offset fp
.text:08050736                 mov     edx, on
.text:0805073C                 mov     data_p, eax
.text:08050741                 mov     eax, sel_data[edx*4]
.text:08050748                 mov     edx, NEW_STACK
.text:0805074E                 mov     [eax], edx
```

These instructions push **fp**, **R1**, **R2**, **R3**, **F1**, **dword_81FD234**, **D1** in order.
Then assigns **fp** to the current stack pointer. This looks like

```x86asm
push fp
push R1
push R2
push R3
push F1
push D2
push D1
mov fp, esp
```

Now we can write the deobfuscated assembly

## Deobfuscated Code

```x86asm
_start:
    mov sesp, esp
    mov esp, NEW_STACK
    mov [esp-16+0], SIGSEGV
    mov [esp-16+4], offset sa_dispatch
    mov [esp-16+8], 0
    call _sigaction
    mov [esp-12+0], SIGILL
    mov [esp-12+4], offset sa_loop
    mov [esp-12+8], 0
    call _sigaction

master_loop:
    mov esp, NEW_STACK
    mov eax, sesp
    mov edx, 4
    add eax, edx
    push ecx
    push dword [ecx-4]
    push 0x804854e
    mov target, 0x805036a

_804854E:
    cmp target, 0x804854e
    jnz check_element

    push 0
    call _exit

check_element:
    cmp target, 0x8048794
    jnz _80493B8

    push fp
    push R1
    push R2
    push R3
    push F1
    push D2
    push D1
    mov fp, esp
    sub esp, 12
    lea R3, [fp+9*4]
    lea R2, [fp+9*4]
    mov dl, [R2]
    mov [R3], dl
    mov R3, [fp+8*4]
    mov R2, 0x15
    add R3, R2
    mov [fp-4], R3
    mov R3, [fp-4]
    mov R2, 2
    xor R3, R2
    mov [fp-8], R3
    mov R3, [fp-8]
    mov R2, 0x1e
    sub R3, R2
    mov [fp-12], R3
    movsx R3, byte [fp-12]
    movsx R2, byte [fp+9*4]
    cmp R3, R2
    mov R0, 0
    cmovnz target, 0x80493B8
    cmovz target, 0x804959C

_80493B8:
    cmp target, 0x80493B8
    mov R0, 1

    jnz _804959C

_804959C:
    cmp target, 0x804959C
    jnz waste_time

    mov esp, fp
    ; pop regs ...
    pop fp
    mov target, [esp]


waste_time:
    cmp target, 0x8049a88
    jnz _8049fc7

    ; ...
    mov target, 0x804fa1c

_8049fc7:
    cmp target, 0x8049fc7
    jnz main
    ; ...

main:
    cmp target, 0x805036a
    jnz _8051028

    push fp, R1, R2, R3, F1, D1
    mov fp, esp
    sub esp, 20*4
    lea R3, [fp-9*4]
    mov R2, 0x80540f0
    push 29
    push R2
    push R3
    call __inline_memcpy
    mov [fp-20*4], 29
    lea R3, [fp-19*4]
    mov R2, offset input
    push 40
    push R2
    push R3
    call __inline_memcpy
    mov [fp-4], 0
    push offset aGiveTheKeyIfYo
    call _puts
    add esp, 4
    push offset stdin@@GLIBC_2_0
    push 0x28
    lea R3, [fp-19*4]
    push R3
    call _fgets

    lea esp, [esp+4*3]

    mov [fp-4], 0
    mov target, 0x8052455

_8051028:
    cmp target, 0x8051028
    jnz _8051985

    push 0x8051012
    mov target, 0x8049a88  ; waste_time

_8051012:
    cmp target, 0x8051012
    jnz _8051985

    push esp
    mov R3, [fp-4]
    lea R2, [fp-19*4]
    add R2, R3
    movsz R0, byte [R2]
    push R0

    lea R2, [fp-9*4]
    add R3, R2
    movsx R0, byte [R3]
    push R0

    push 0x8051985
    mov target, 0x8048794   ; check_element

_8051985:
    cmp target, 0x8051985
    jnz _8051f38

    lea esp, [esp+8]

    cmp R0, 0
    cmovz target, 0x8051fa6

    push 1
    call _exit

_8051f38:
    lea esp, [esp+8]

_8051fa6:
    cmp target, 0x8051fa6
    jnz _8052180

_8052180:
    cmp target, 0x8052180
    jnz _8052455

    mov R3, [fp-4]
    mov R2, 1
    add R3, R2
    mov [fp-4], R3

_8052455:
    cmp target, 0x8052455
    jnz _805294d

    mov R3, [fp-4]
    mov R2, [fp-20*4]
    cmp R3, R2
    cmovl target, 0x8051028

_805294D:
    cmp target, 0x805294d
    jnz _8052b1f

    push offset aGoodJob
    call _puts

    lea esp, [esp+4]

_8052B1F:
    mov R0, 0
    cmp target, 0x8052b1f
    jnz next

    mov esp, fp
    pop R1, R2, R3, F1, D1
    pop fp
    mov target, [esp]  ; return addr

next:
    ; raise SIGILL now
```

## Analysis

Cleaning up a bit, we have **main** as

```x86asm

check_element:
    push fp, R1, R2, R3, F1, D2, D1
    mov fp, esp
    sub esp, 12

    lea R3, [fp+9*4]    ; arg2
    lea R2, [fp+9*4]
    mov dl, [R2]
    mov [R3], dl

    mov R3, [fp+8*4]    ; arg1
    mov R2, 0x15
    add R3, R2
    mov [fp-4], R3

    mov R3, [fp-4]
    mov R2, 2
    xor R3, R2
    mov [fp-8], R3

    mov R3, [fp-8]
    mov R2, 0x1e
    sub R3, R2
    mov [fp-12], R3

    movsx R3, byte [fp-12]
    movsx R2, byte [fp+9*4]
    cmp R3, R2
    mov R0, 0
    jz L3
    mov R0, 1
L3:
    mov esp, fp
    ; pop regs
    pop fp
    ret

main:
    push fp, R1 ...
    mov fp, esp
    sub esp, 80

    lea R3, [fp-36]
    mov R2, 0x80540f0
    push 29
    push R2
    push R3
    call __inline_memcpy

    mov [fp-80], 29

    lea R3, [fp-76]
    mov R2, offset input
    push 40
    push R2
    push R3
    call __inline_memcpy

    mov [fp-4], 0
    push offset aGiveTheKeyIfYo ; "Give the key, if you think you are worthy."
    call puts
    add esp, 4

    push offset stdin@GLIBC_2_0
    push 0x28
    lea R3, [fp-76]
    push R3
    call fgets
    add esp, 12

    mov [fp-4], 0
    jmp _8052455

_8051028:
    call waste_time

    mov R3, [fp-4]
    lea R2, [fp-76]
    add R2, R3
    movsx R0, byte [R2]
    push R0

    lea R2, [fp-36]
    add R3, R2
    movsx R0, byte [R3]
    push R0

    call check_element
    add esp, 8

    cmp R0, 0
    jz _8051fa6

    push 1
    call exit

_8051fa6:
    mov R3, [fp-4]
    mov R2, 1
    add R3, R2
    mov [fp-4], R3

_8052455:
    mov R3, [fp-4]
    mov R2, [fp-80]
    cmp R3, R2
    jl _8051028

_805294D:
    push offset aGoodJob
    call puts
    add esp, 4

    mov esp, fp
    pop R1, R2, R3, F1, D1
    pop fp
    ret
```

So, we have a for loop that iterates 29 times, calling **waste_time** first and then **check_element** with two params - magic[i] and input[i] where **magic** is the array of 29 bytes at **0x80540f0** and input is the array at **fp-76**.  
**check_element** checks whether **(magic[i]+0x15^2)-0x1e == input[i]**. On mismatch the program terminates with exit code 1.

## Solution

```python
magic = [
    0x71, 0x73, 0x68, 0x72, 0x86, 0x72, 0x37,
    0x37, 0x6B, 0x6A, 0x7B, 0x6F, 0x38, 0x79, 0x72,
    0x3C, 0x6A, 0x71, 0x37, 0x7D, 0x6A, 0x82, 0x3B,
    0x38, 0x7B, 0x70, 0x79, 0x72, 0x84
]
f = lambda i: chr((i+0x15^2)-0x1e)
print "".join(map(f, x))
```

So, the flag is `flag{g00d_th1ng5_f0r_w41ting}`


## References

[MoV is Turing complete](https://stedolan.net/research/mov.pdf)
