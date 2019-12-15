---
title: "InCTF 2018 - mast3r"
tags: [reversing, inctf]
categories: [reversing, inctf]
date: 2018-10-07 04:38:15
---

<!--more-->
![Image0](/images/inctf18_mast3r.png)

Opening the file in IDA, we can see the program reads two strings (one for each stage), and validates them.

### Stage-1 Validation

```x86asm
.text:0000000000400E93         mov     rax, 787D6B6F613D7478h
.text:0000000000400E9D         mov     qword ptr [rbp+var_20], rax
.text:0000000000400EA1         mov     rax, 3C7E617D73617E3Dh
.text:0000000000400EAB         mov     [rbp+var_18], rax
.text:0000000000400EAF         mov     [rbp+var_10], 7D77783Ch
.text:0000000000400EB6         mov     rax, [rbp+s]    ; first argument
.text:0000000000400EBA         mov     rdi, rax        ; s
.text:0000000000400EBD         call    _strlen
.text:0000000000400EC2         add     rax, 5
.text:0000000000400EC6         add     rax, rax
.text:0000000000400EC9         cmp     rax, 32h
.text:0000000000400ECD         jz      short loc_400EE8
.text:0000000000400ECF         mov     edi, offset aInvalidLength ; "\nInvalid Length"
.text:0000000000400ED4         mov     eax, 0
.text:0000000000400ED9         call    _printf
.text:0000000000400EDE         mov     edi, 0          ; status
.text:0000000000400EE3         call    _exit
```

Cool, we have a magic array at var\_20 and the string length must be 25.

```x86asm
.text:0000000000400EE8         lea     rax, [rbp+var_28]
.text:0000000000400EEC         mov     rdx, rax
.text:0000000000400EEF         mov     esi, 0    ; UC_MODE_ARM
.text:0000000000400EF4         mov     edi, 1    ; UC_ARCH_ARM
.text:0000000000400EF9         call    _uc_open
.text:0000000000400EFE         mov     [rbp+var_2C], eax
.text:0000000000400F01         cmp     [rbp+var_2C], 0
.text:0000000000400F05         jz      short loc_400F32
.text:0000000000400F07         mov     eax, [rbp+var_2C]
.text:0000000000400F0A         mov     edi, eax
.text:0000000000400F0C         call    _uc_strerror
```

Great! it seems like the stage 1 is gonna execute some arm instructions

```x86asm
.text:0000000000400F32         mov     rax, [rbp+var_28]
.text:0000000000400F36         mov     ecx, 7
.text:0000000000400F3B         mov     edx, 200000h
.text:0000000000400F40         mov     esi, 10000h
.text:0000000000400F45         mov     rdi, rax
.text:0000000000400F48         call    _uc_mem_map
.text:0000000000400F4D         mov     rax, [rbp+var_28]
.text:0000000000400F51         mov     ecx, 48h
.text:0000000000400F56         mov     edx, offset unk_4016B0
.text:0000000000400F5B         mov     esi, 10000h
.text:0000000000400F60         mov     rdi, rax
.text:0000000000400F63         call    _uc_mem_write
.text:0000000000400F68         mov     rax, [rbp+s]    ; string argument
.text:0000000000400F6C         mov     rdi, rax        ; s
.text:0000000000400F6F         call    _strlen
.text:0000000000400F74         mov     rcx, rax
.text:0000000000400F77         mov     rax, [rbp+var_28]
.text:0000000000400F7B         mov     rdx, [rbp+s]
.text:0000000000400F7F         mov     esi, 11000h
.text:0000000000400F84         mov     rdi, rax
.text:0000000000400F87         call    _uc_mem_write
.text:0000000000400F8C         lea     rax, [rbp+var_20]
.text:0000000000400F90         mov     rdi, rax        ; s
.text:0000000000400F93         call    _strlen
.text:0000000000400F98         mov     rcx, rax
.text:0000000000400F9B         mov     rax, [rbp+var_28]
.text:0000000000400F9F         lea     rdx, [rbp+var_20]
.text:0000000000400FA3         mov     esi, 12000h
.text:0000000000400FA8         mov     rdi, rax
.text:0000000000400FAB         call    _uc_mem_write
.text:0000000000400FB0         mov     rax, [rbp+var_28]
.text:0000000000400FB4         mov     r8d, 0
.text:0000000000400FBA         mov     ecx, 0
.text:0000000000400FBF         mov     edx, 10044h
.text:0000000000400FC4         mov     esi, 10000h
.text:0000000000400FC9         mov     rdi, rax
.text:0000000000400FCC         call    _uc_emu_start
```

It maps 2 MiB space at virtual address 0x10000 as RWX. 0x48 bytes from 0x4016b0 are written into the address 0x10000. Then it writes the input string into the next page at 0x11000 and var\_20 (magic string) at the virtual address 0x12000. Execution begins at 0x10000 and terminates at 0x10044. Lets see what the arm code at 0x4016b0 does

```armasm
0x00000000:    mov r0, #0x11000    ; input string
0x00000004:    mov r5, #0x12000    ; magic string
0x00000008:    mov fp, #1
0x0000000c:    mov r1, #0
0x00000010:    ldrb r2, [r0, r1]
0x00000014:    eor r2, r2, #5
0x00000018:    and r2, r2, #0xff
0x0000001c:    add r2, r2, #7
0x00000020:    ldrb r3, [r5, r1]
0x00000024:    and r3, r3, #0xff
0x00000028:    add r1, r1, #1
0x0000002c:    cmp r2, r3
0x00000030:    beq #0x3c
0x00000034:    mov fp, #0
0x00000038:    b #0x44
0x0000003c:    cmp r1, #0x13
0x00000040:    ble #0x10
0x00000044:    nop
```

Pretty simple, **magic[i] == (input[i]^5)+7**. And we have

```bash
┌─[x0r19x91@x0r19x91]─[~/Desktop/ctf/inctf]
└──╼ $ cat mast3r.py
#!/usr/bin/env python

magic = [0x78, 0x74, 0x3d, 0x61, 0x6f, 0x6b, 0x7d, 0x78, 0x3d, 0x7e, 0x61, 0x73, 0x7d, 0x61, 0x7e, 0x3c, 0x3c, 0x78, 0x77, 0x7d]

print ''.join(map(lambda i: chr(i-7^5), magic))
┌─[x0r19x91@x0r19x91]─[~/Desktop/ctf/inctf]
└──╼ $ python mast3r.py
th3_mast3r_is_r00tus
┌─[x0r19x91@x0r19x91]─[~/Desktop/ctf/inctf]
└──╼ $
```

So, the input for the first stage is **th3\_mast3r\_is\_r00tus**.


### Stage-2 Validation

```x86asm
.text:0000000000401057        mov     rax, [rbp+input_string]
.text:000000000040105B        movzx   eax, byte ptr [rax]
.text:000000000040105E        movsx   eax, al
.text:0000000000401061        mov     [rbp+var_6C], eax
.text:0000000000401064        mov     rax, [rbp+input_string]
.text:0000000000401068        add     rax, 8
.text:000000000040106C        movzx   eax, byte ptr [rax]
.text:000000000040106F        movsx   eax, al
.text:0000000000401072        mov     [rbp+var_68], eax
.text:0000000000401075        mov     rax, [rbp+input_string]
.text:0000000000401079        add     rax, 0Dh
.text:000000000040107D        movzx   eax, byte ptr [rax]
.text:0000000000401080        movsx   eax, al
.text:0000000000401083        mov     [rbp+var_64], eax
.text:0000000000401086        mov     rax, [rbp+input_string]
.text:000000000040108A        mov     rdi, rax        ; s
.text:000000000040108D        call    _strlen
.text:0000000000401092        add     rax, 1
.text:0000000000401096        add     rax, rax
.text:0000000000401099        cmp     rax, 32h
.text:000000000040109D        jz      short loc_4010B8
```

Nothing to explain here, **var\_6C, var\_68, var\_64 = input\_string[0], input\_string[8], input\_string[13]**. input\_string must be of length 24

```x86asm
.text:00000000004010B8 loc_4010B8:
.text:00000000004010B8         mov     rax, [rbp+input_string]
.text:00000000004010BC         lea     rdx, [rax+10h]
.text:00000000004010C0         lea     rax, [rbp+dest]
.text:00000000004010C4         mov     rsi, rdx        ; src
.text:00000000004010C7         mov     rdi, rax        ; dest
.text:00000000004010CA         call    _strcpy
.text:00000000004010CF         mov     rax, [rbp+input_string]
.text:00000000004010D3         lea     rcx, [rax+1]
.text:00000000004010D7         lea     rax, [rbp+var_30]
.text:00000000004010DB         mov     edx, 7          ; n
.text:00000000004010E0         mov     rsi, rcx        ; src
.text:00000000004010E3         mov     rdi, rax        ; dest
.text:00000000004010E6         call    _strncpy
.text:00000000004010EB         mov     rax, [rbp+input_string]
.text:00000000004010EF         lea     rcx, [rax+9]
.text:00000000004010F3         lea     rax, [rbp+var_20]
.text:00000000004010F7         mov     edx, 7          ; n
.text:00000000004010FC         mov     rsi, rcx        ; src
.text:00000000004010FF         mov     rdi, rax        ; dest
.text:0000000000401102         call    _strncpy
.text:0000000000401107         lea     rax, [rbp+dest]
.text:000000000040110B         mov     esi, offset s2  ; "un1c0rn!"
.text:0000000000401110         mov     rdi, rax        ; s1
.text:0000000000401113         call    _strcmp
.text:0000000000401118         test    eax, eax
.text:000000000040111A         jz      short loc_401126
```

So, we have **dest, var\_30, var\_20 = input_string[16:], input_string[1:8], input_string[9:16]** and **dest == "un1c0rn!"**

```x86asm
.text:0000000000401126         lea     rax, [rbp+var_40]
.text:000000000040112A         mov     rdx, rax
.text:000000000040112D         mov     esi, 4       ; UC_MODE_MIPS32
.text:0000000000401132         mov     edi, 3       ; UC_ARCH_MIPS
.text:0000000000401137         call    _uc_open
.text:000000000040113C         mov     [rbp+var_44], eax
.text:000000000040113F         cmp     [rbp+var_44], 0
.text:0000000000401143         jz      short loc_401170
```

Here I initially mistook the architecture to be x86 because I overlooked the fact that **UC\_ARCH\_ARM = 1** is defined in the **enum uc\_arch**.

```x86asm
.text:0000000000401170         movzx   eax, [rbp+var_20]
.text:0000000000401174         movsx   eax, al
.text:0000000000401177         mov     [rbp+var_60], eax
.text:000000000040117A         movzx   eax, [rbp+var_1F]
.text:000000000040117E         movsx   eax, al
.text:0000000000401181         mov     [rbp+var_5C], eax

[ ... snip ... ]

.text:00000000004012EE         push    0
.text:00000000004012F0         mov     r9d, 1
.text:00000000004012F6         mov     r8d, 0
.text:00000000004012FC         mov     ecx, offset sub_400C26
.text:0000000000401301         mov     edx, 4       ; UC_HOOK_CODE
.text:0000000000401306         mov     rdi, rax
.text:0000000000401309         mov     eax, 0
.text:000000000040130E         call    _uc_hook_add
.text:0000000000401313         add     rsp, 10h
.text:0000000000401317         mov     rax, [rbp+var_40]
.text:000000000040131B         mov     r8d, 0
.text:0000000000401321         mov     ecx, 0
.text:0000000000401326         mov     edx, 100F8h
.text:000000000040132B         mov     esi, 10000h
.text:0000000000401330         mov     rdi, rax
.text:0000000000401333         call    _uc_emu_start
```

It then creates a 2 MiB address space at virtual address 0x10000. Code of length 0xf8 is written into 0x10000 from 0x401758. var\_30 is written into the next page i.e., at 0x11000. Then the code sets up some registers, as follows

```
regs[11] = input_string[0]      ; r9, t1
regs[12] = input_string[8]      ; r10, t2
regs[13] = input_string[13]     ; r11, t3
regs[15] = input_string[9]      ; r13, t5
regs[16] = input_string[10]     ; r14, t6
regs[17] = input_string[11]     ; r15, t7
regs[26] = input_string[12]     ; r24, t8
regs[27] = input_string[13]     ; r25, t9
regs[18] = input_string[14]     ; r16, s0
regs[19] = input_string[15]     ; r17, s1
```

A hook callback 0x400C28 is registered, which gets called during the execution of the code. Execution starts at 0x10000 and terminates at 0x100f8.
Let's take a look at the hook callback

```x86asm
.text:0000000000400D48         cmp     [rbp+address], 10010h
.text:0000000000400D50         jnz     short loc_400D96
.text:0000000000400D52         lea     rdx, [rbp+var_34]
.text:0000000000400D56         mov     rax, [rbp+engine]
.text:0000000000400D5A         mov     esi, 0Bh
.text:0000000000400D5F         mov     rdi, rax
.text:0000000000400D62         call    _uc_reg_read
.text:0000000000400D67         mov     eax, [rbp+var_34]
.text:0000000000400D6A         cmp     eax, 200h
.text:0000000000400D6F         jz      short loc_400D96
.text:0000000000400D71         mov     edi, offset format ; "Try Again!"
.text:0000000000400D76         mov     eax, 0
.text:0000000000400D7B         call    _printf

[ ... snip ... ]

.text:0000000000400D96         cmp     [rbp+address], 10020h
.text:0000000000400D9E         jnz     short loc_400DE4
.text:0000000000400DA0         lea     rdx, [rbp+var_30]
.text:0000000000400DA4         mov     rax, [rbp+engine]
.text:0000000000400DA8         mov     esi, 0Ch
.text:0000000000400DAD         mov     rdi, rax
.text:0000000000400DB0         call    _uc_reg_read
.text:0000000000400DB5         mov     eax, [rbp+var_30]
.text:0000000000400DB8         cmp     eax, 100h

[ ... snip ... ]

.text:0000000000400DE4         cmp     [rbp+address], 10030h
.text:0000000000400DEC         jnz     short loc_400E32
.text:0000000000400DEE         lea     rdx, [rbp+var_2C]
.text:0000000000400DF2         mov     rax, [rbp+engine]
.text:0000000000400DF6         mov     esi, 0Dh
.text:0000000000400DFB         mov     rdi, rax
.text:0000000000400DFE         call    _uc_reg_read
.text:0000000000400E03         mov     eax, [rbp+var_2C]
.text:0000000000400E06         cmp     eax, 400h

[ ... snip ... ]

.text:0000000000400E32         cmp     [rbp+address], 100D0h
.text:0000000000400E3A         jnz     short loc_400E61
.text:0000000000400E3C         mov     edi, offset aYouCanDoBetter ; "\nYou can do better!"
.text:0000000000400E41         mov     eax, 0
.text:0000000000400E46         call    _printf
```

Here the code validates the registers. When $pc is at 0x10010, the value of regs[11] which is $t1 must be 0x200. At 0x10020, $t2 must be 0x100 and at 0x10030 $t3 should be 0x400. Finally, $pc must not execute at 0x100d0.

Let's disassemble the MIPS code

```mipsasm
0x00000000:     addiu $t0, $zero, 0xa
0x00000004:     mul $t1, $t1, $t0
0x00000008:     addiu $t0, $zero, 2
0x0000000c:     add $t1, $t1, $t0
0x00000010:     addiu $t0, $zero, 0xa       ; $t1 == 0x200

0x00000014:     mul $t2, $t2, $t0
0x00000018:     addiu $t0, $zero, 0xfe
0x0000001c:     sub $t2, $t2, $t0
0x00000020:     addiu $t0, $zero, 0x14      ; $t2 == 0x100

0x00000024:     mul $t3, $t3, $t0
0x00000028:     addiu $t0, $zero, 4
0x0000002c:     add $t3, $t3, $t0
0x00000030:     nop                         ; $t3 == 0x400

0x00000034:     lui $t0, 1
0x00000038:     ori $t0, $t0, 0x1000        ; $t0 = 0x11000
0x0000003c:     lb $t4, ($t0)
0x00000040:     addiu $t0, $t0, 1
0x00000044:     addiu $t1, $zero, 0x72
0x00000048:     bne $t4, $t1, 0xcc
0x0000004c:     nop
0x00000050:     lb $t4, ($t0)
0x00000054:     addiu $t0, $t0, 1
0x00000058:     addiu $t1, $zero, 0x5f
0x0000005c:     bne $t4, $t1, 0xcc
0x00000060:     nop
0x00000064:     lb $t4, ($t0)
0x00000068:     addiu $t0, $t0, 1
0x0000006c:     addiu $t1, $zero, 0x61
0x00000070:     bne $t4, $t1, 0xcc
0x00000074:     nop
0x00000078:     lb $t4, ($t0)
0x0000007c:     addiu $t0, $t0, 1
0x00000080:     addiu $t1, $zero, 0x6e
0x00000084:     bne $t4, $t1, 0xcc
0x00000088:     nop
0x0000008c:     lb $t4, ($t0)
0x00000090:     addiu $t0, $t0, 1
0x00000094:     addiu $t1, $zero, 0x64
0x00000098:     bne $t4, $t1, 0xcc
0x0000009c:     nop
0x000000a0:     lb $t4, ($t0)
0x000000a4:     addiu $t0, $t0, 1
0x000000a8:     addiu $t1, $zero, 0x5f
0x000000ac:     bne $t4, $t1, 0xcc
0x000000b0:     nop
0x000000b4:     lb $t4, ($t0)
0x000000b8:     addiu $t0, $t0, 1
0x000000bc:     addiu $t1, $zero, 0x68
0x000000c0:     bne $t4, $t1, 0xcc
0x000000c4:     nop
0x000000c8:     b 0xd4
0x000000cc:     nop         ; don't execute the next nop
0x000000d0:     nop         ; means we need to jump to 0xd4
0x000000d4:     nop
0x000000d8:     addiu $t5, $t5, 1
0x000000dc:     addiu $t6, $t6, 2
0x000000e0:     addiu $t7, $t7, 3
0x000000e4:     addiu $t8, $t8, 4
0x000000e8:     addiu $t9, $t9, 5
0x000000ec:     addiu $s0, $s0, 6
0x000000f0:     addiu $s1, $s1, 7
0x000000f4:     nop
```

We have,

1. 0x200 = 2+10\*$t1 => $t1 = '3'
2. 0x100 = 10\*$t2-0xfe => $t2 = '3'
3. 0x400 = 4+$t3\*0x14 => $t3 = '3'

Therefore, input\_string[0] = input\_string[8] = input\_string[13] = '3'
The code from 0x34 validates var\_30. So, **var\_30 = "\x72\x5f\x61\x6e\x64\x5f\x68"** which is **r\_and\_h**.

```x86asm
.text:00000000004013FF         mov     eax, [rbp+_t5]       ; $t5
.text:0000000000401402         cmp     eax, 60h
.text:0000000000401405         jnz     short loc_401437
.text:0000000000401407         mov     eax, [rbp+_t6]       ; $t6
.text:000000000040140A         cmp     eax, 6Eh
.text:000000000040140D         jnz     short loc_401437
.text:000000000040140F         mov     eax, [rbp+_t7]       ; $t7
.text:0000000000401412         cmp     eax, 33h
.text:0000000000401415         jnz     short loc_401437
.text:0000000000401417         mov     eax, [rbp+_t8]       ; $t8
.text:000000000040141A         cmp     eax, 7Ah
.text:000000000040141D         jnz     short loc_401437
.text:000000000040141F         mov     eax, [rbp+_t9]       ; $t9
.text:0000000000401422         cmp     eax, 38h
.text:0000000000401425         jnz     short loc_401437
.text:0000000000401427         mov     eax, [rbp+_s0]       ; $s0
.text:000000000040142A         cmp     eax, 79h
.text:000000000040142D         jnz     short loc_401437
.text:000000000040142F         mov     eax, [rbp+_s1]       ; $s1
.text:0000000000401432         cmp     eax, 66h
.text:0000000000401435         jz      short loc_40144A
```

Now, we can find out input\_string[9:16], which is

```python
print ''.join(map(lambda (i, j): chr(j-i), zip(xrange(1, 8), [0x60, 0x6e, 0x33, 0x7a, 0x38, 0x79, 0x66])))
```

So, the string for stage2 is input\_string[0] + var\_30 + input\_string[8] + var\_20 + dest = **"3r\_and\_h3\_l0v3s\_un1c0rn!"**

```x86asm
.text:0000000000401565         mov     edi, offset aStage2Complete ; "\nStage 2 completed!"
.text:000000000040156A         call    _puts
.text:000000000040156F         mov     edi, offset aGoodWork ; "\nGood Work!!"
.text:0000000000401574         call    _puts
.text:0000000000401579         lea     rdx, [rbp+stage2_input]
.text:000000000040157D         lea     rax, [rbp+stage1_input]
.text:0000000000401581         mov     rsi, rdx
.text:0000000000401584         mov     rdi, rax
.text:0000000000401587         call    sub_401471

.text:0000000000401471 sub_401471      proc near
.text:0000000000401471
.text:0000000000401471 var_10          = qword ptr -10h
.text:0000000000401471 var_8           = qword ptr -8
.text:0000000000401471
.text:0000000000401471         push    rbp
.text:0000000000401472         mov     rbp, rsp
.text:0000000000401475         sub     rsp, 10h
.text:0000000000401479         mov     [rbp+var_8], rdi
.text:000000000040147D         mov     [rbp+var_10], rsi
.text:0000000000401481         mov     edi, offset s   ; "-------------------"
.text:0000000000401486         call    _puts
.text:000000000040148B         mov     rdx, [rbp+var_10]
.text:000000000040148F         mov     rax, [rbp+var_8]
.text:0000000000401493         mov     rsi, rax
.text:0000000000401496         mov     edi, offset aTheFlagIsInctf ; "The FLAG is: inctf{\%s\%s}\n"
.text:000000000040149B         mov     eax, 0
.text:00000000004014A0         call    _printf
.text:00000000004014A5         nop
.text:00000000004014A6         leave
.text:00000000004014A7         retn
.text:00000000004014A7 sub_401471      endp
```

Great! now we have the flag - "inctf{" + stage1\_input + stage2\_input + "}" = **"inctf{th3\_mast3r\_is\_r00tus3r\_and\_h3\_l0v3s\_un1c0rn!}"**
