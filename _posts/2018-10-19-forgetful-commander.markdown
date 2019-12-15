---
title: "HackLu 2018 - Forgetful Commander"
date: 2018-10-19 07:00:00
tags: [hacklu, reversing]
categories: [hacklu, reversing]
---

<!--more-->
I'll do static analysis using radare.  
<!--more-->

```bash

┌─[x0r19x91@x0r19x91]─[~/Desktop/ctf/hacklu/ForgetfulCommander/public]
└──╼ $ objdump -d -M intel -j.text forgetful_commander

forgetful_commander:     file format elf32-i386

Disassembly of section .text:

00002050 <.text>:
    2050:       99                      cdq    
    2051:       67 cd 30                addr16 int 0x30
    2054:       a5                      movs   DWORD PTR es:[edi],DWORD PTR ds:[esi]
    2055:       02 fc                   add    bh,ah
    ...

```

Ahh ! So we have garbage in .text. Fire up radare :-)

```x86asm
0x0000d000      50             push eax
0x0000d001      60             pushal
0x0000d002      9c             pushfd
0x0000d003      81ec00500000   sub esp, 0x5000
0x0000d009      b855000000     mov eax, 0x55               ; 'U'
0x0000d00e      6878650000     push 0x6578                 ; 'xe'
0x0000d013      686c662f65     push 0x652f666c             ; 'lf/e'
0x0000d018      68632f7365     push 0x65732f63             ; 'c/se'
0x0000d01d      682f70726f     push 0x6f72702f             ; '/pro'
0x0000d022      89e3           mov ebx, esp
0x0000d024      8d8c24104000.  lea ecx, [arg_4010h]        ; 0x4010
0x0000d02b      baff0f0000     mov edx, 0xfff
;-- syscall.readlink:
0x0000d030      cd80           int 0x80
0x0000d032      83c410         add esp, 0x10
0x0000d035      83f800         cmp eax, 0
0x0000d038      0f8e92010000   jle 0xd1d0
0x0000d03e      89c7           mov edi, eax
0x0000d040      8d8c04004000.  lea ecx, [esp + eax + 0x4000]
0x0000d047      c6010a         mov byte [ecx], 0xa
0x0000d04a      47             inc edi
0x0000d04b      b805000000     mov eax, 5
0x0000d050      6861707300     push 0x737061               ; 'aps'
0x0000d055      686c662f6d     push 0x6d2f666c             ; 'lf/m'
0x0000d05a      68632f7365     push 0x65732f63             ; 'c/se'
0x0000d05f      682f70726f     push 0x6f72702f             ; '/pro'
0x0000d064      89e3           mov ebx, esp
0x0000d066      31c9           xor ecx, ecx
;-- syscall.open:
0x0000d068      cd80           int 0x80
0x0000d06a      83c410         add esp, 0x10
0x0000d06d      83f800         cmp eax, 0
0x0000d070      0f8c5a010000   jl 0xd1d0
0x0000d076      89c6           mov esi, eax
```

So, the program reads the path of its executable, i.e., the path for 'forgetful_commander' using **sys\_readlink** and opens the file **'/proc/self/maps'**  

```x86asm
0x0000d078      b803000000     mov eax, 3
0x0000d07d      89f3           mov ebx, esi
0x0000d07f      89e1           mov ecx, esp
0x0000d081      ba00400000     mov edx, 0x4000
;-- syscall.read:
0x0000d086      cd80           int 0x80
0x0000d088      83f800         cmp eax, 0
0x0000d08b      0f8ee9000000   jle 0xd17a
0x0000d091      31c9           xor ecx, ecx
0x0000d093      31d2           xor edx, edx
0x0000d095      bd01000000     mov ebp, 1   ; flag for breaking loop
; CODE XREFS from entry0 (0xd0b7, 0xd0c6)
0x0000d09a      39c1           cmp ecx, eax
0x0000d09c      0f8d29000000   jge 0xd0cb
0x0000d0a2      0fb61c0c       movzx ebx, byte [esp + ecx]
0x0000d0a6      41             inc ecx
0x0000d0a7      389c14004000.  cmp byte [esp + edx + 0x4000], bl
0x0000d0ae      0f8510000000   jne 0xd0c4
0x0000d0b4      42             inc edx
0x0000d0b5      39fa           cmp edx, edi
0x0000d0b7      0f85ddffffff   jne 0xd09a
0x0000d0bd      31ed           xor ebp, ebp
0x0000d0bf      e907000000     jmp 0xd0cb
; CODE XREF from entry0 (0xd0ae)
0x0000d0c4      31d2           xor edx, edx
0x0000d0c6      e9cfffffff     jmp 0xd09a
; CODE XREFS from entry0 (0xd09c, 0xd0bf)
0x0000d0cb      85ed           test ebp, ebp
0x0000d0cd      0f85a5ffffff   jne 0xd078
```

Here we have a loop which reads a block of 16K bytes and searches for the path to its executable followed by a newline. The loop breaks when **ecx** is the offset of the newline in the string.  

```x86asm
0x0000d0d3      31db           xor ebx, ebx
0x0000d0d5      49             dec ecx
0x0000d0d6      83f900         cmp ecx, 0
0x0000d0d9      0f9fc3         setg bl
0x0000d0dc      807c0cff0a     cmp byte [esp + ecx - 1], 0xa ; prev newline
0x0000d0e1      0f95c7         setne bh
0x0000d0e4      84fb           test bl, bh
0x0000d0e6      0f85e7ffffff   jne 0xd0d3
```

This loop searches for the offset of the previous newline and breaks when **ecx** points to the beginning of line containing the executable path.

```x86asm
0x0000d0ec      31d2           xor edx, edx
0x0000d0ee      89cd           mov ebp, ecx
0x0000d0f0      83c108         add ecx, 8   ; 32bit address
; CODE XREFS from entry0 (0xd118, 0xd140, 0xd168)
0x0000d0f3      39cd           cmp ebp, ecx
0x0000d0f5      0f8d7f000000   jge 0xd17a
0x0000d0fb      c1c204         rol edx, 4
0x0000d0fe      31db           xor ebx, ebx
0x0000d100      803c2c30       cmp byte [esp + ebp], 0x30  ; '0'
0x0000d104      0f9dc3         setge bl
0x0000d107      803c2c39       cmp byte [esp + ebp], 0x39  ; '9'
0x0000d10b      0f9ec7         setle bh
0x0000d10e      802c2c30       sub byte [esp + ebp], 0x30  ; '0'
0x0000d112      32142c         xor dl, byte [esp + ebp]
0x0000d115      45             inc ebp
0x0000d116      84fb           test bl, bh
0x0000d118      0f85d5ffffff   jne 0xd0f3
0x0000d11e      4d             dec ebp
0x0000d11f      32142c         xor dl, byte [esp + ebp]
0x0000d122      80042c30       add byte [esp + ebp], 0x30  ; '0'
0x0000d126      31db           xor ebx, ebx
0x0000d128      803c2c61       cmp byte [esp + ebp], 0x61  ; 'a'
0x0000d12c      0f9dc3         setge bl
0x0000d12f      803c2c7a       cmp byte [esp + ebp], 0x7a  ; 'z'
0x0000d133      0f9ec7         setle bh
0x0000d136      802c2c57       sub byte [esp + ebp], 0x57  ; 'W'
0x0000d13a      32142c         xor dl, byte [esp + ebp]
0x0000d13d      45             inc ebp
0x0000d13e      84fb           test bl, bh
0x0000d140      0f85adffffff   jne 0xd0f3
0x0000d146      4d             dec ebp
0x0000d147      32142c         xor dl, byte [esp + ebp]
0x0000d14a      80042c61       add byte [esp + ebp], 0x61  ; 'a'
0x0000d14e      31db           xor ebx, ebx
0x0000d150      803c2c41       cmp byte [esp + ebp], 0x41  ; 'A'
0x0000d154      0f9dc3         setge bl
0x0000d157      803c2c5a       cmp byte [esp + ebp], 0x5a  ; 'Z'
0x0000d15b      0f9ec7         setle bh
0x0000d15e      802c2c37       sub byte [esp + ebp], 0x37  ; '7'
0x0000d162      32142c         xor dl, byte [esp + ebp]
0x0000d165      45             inc ebp
0x0000d166      84fb           test bl, bh
0x0000d168      0f8585ffffff   jne 0xd0f3
```

This loop parses the address pointed to by **ecx** into **edx**. The base address of the map  

```x86asm
0x0000d183      85d2           test edx, edx
0x0000d185      0f8445000000   je 0xd1d0
0x0000d18b      81c250200000   add edx, 0x2050
0x0000d191      899424245000.  mov dword [arg_5024h], edx ; return addr
0x0000d198      83ea50         sub edx, 0x50
0x0000d19b      89c5           mov ebp, eax     ; eax = 0
0x0000d19d      40             inc eax
0x0000d19e      40             inc eax
; CODE XREF from entry0 (0xd1c2)
0x0000d19f      be78756c46     mov esi, 0x466c7578         ; 'xulF'
0x0000d1a4      31db           xor ebx, ebx
0x0000d1a6      39e8           cmp eax, ebp
0x0000d1a8      0f8419000000   je 0xd1c7
0x0000d1ae      b900040000     mov ecx, 0x400
; CODE XREF from entry0 (0xd1bf)
0x0000d1b3      311a           xor dword [edx], ebx
0x0000d1b5      3132           xor dword [edx], esi
0x0000d1b7      c1ce08         ror esi, 8
0x0000d1ba      8b1a           mov ebx, dword [edx]
0x0000d1bc      83c204         add edx, 4
0x0000d1bf      e2f2           loop 0xd1b3
0x0000d1c1      48             dec eax
0x0000d1c2      e9d8ffffff     jmp 0xd19f
```

Return address is **edx+0x2050**. This loop decrypts the 2*4K bytes or 2 pages mapped from 0x2000 and then jumps to **edx+0x2050**.

```bash
┌─[x0r19x91@x0r19x91]─[~/Desktop/ctf/hacklu/ForgetfulCommander/public]                                                                                                                                                                       
└──╼ $ readelf --program-headers forgetful_commander

Elf file type is DYN (Shared object file)
Entry point 0xd000
There are 12 program headers, starting at offset 52

Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  ...
  LOAD           0x002000 0x00002000 0x00002000 0x00338 0x00338 RWE 0x1000
  LOAD           0x003000 0x00003000 0x00003000 0x004f0 0x004f0 RW  0x1000
  ...
```

So we need to decrypt **0x338 bytes** at **offset 0x2000** and **0x4f0 bytes** at **offset 0x3000**

```c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdint.h>
#include <string.h>

void decrypt(char* base, size_t size)
{
    uint32_t* addr = (uint32_t*) mem;
    uint32_t k = 0;
    uint32_t u = 'Flux';
    size >>= 2;
    for (int j = 0; j < size; ++j) {
        *addr ^= k^u;
        asm volatile ("rorl $8, %0" :: "m"(u));
        k = *addr++;
    }
}

int main()
{
    int file = open("forgetful_commander", 0);
    int file_size = 0x338 >> 2;
    struct stat sBuf;
    fstat(file, &sBuf);
    char* mem = mmap(0, sBuf.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, file, 0);
    decrypt(mem+0x2000, 0x338);
    decrypt(mem+0x3000, 0x4f0);
    int outfile = open("forgetful", O_WRONLY|O_CREAT|O_TRUNC, 0777);
    write(outfile, mem, sBuf.st_size);
    munmap(mem, sBuf.st_size);
    close(outfile);
    close(file);
}

```

Now lets open 'forgetful' in radare and disassemble at offset 0x2050.

```x86asm
;-- section..text:
0x00002050      31ed           xor ebp, ebp
0x00002052      5e             pop esi
0x00002053      89e1           mov ecx, esp
0x00002055      83e4f0         and esp, 0xfffffff0
0x00002058      50             push eax
0x00002059      54             push esp
0x0000205a      52             push edx
0x0000205b      e822000000     call __pc_thunk_bx
0x00002060      81c3a02f0000   add ebx, 0x2fa0
0x00002066      8d8320d3ffff   lea eax, [ebx - 0x2ce0]
0x0000206c      50             push eax
0x0000206d      8d83c0d2ffff   lea eax, [ebx - 0x2d40]
0x00002073      50             push eax
0x00002074      51             push ecx
0x00002075      56             push esi
0x00002076      ffb3f8ffffff   push dword [ebx - 8] ; 0x2190
0x0000207c      e8bfffffff     call sym.imp.__libc_start_main
0x00002081      f4             hlt
```

Great ! This is the new entry point. Lets move on to **main** which is at offset 0x2190

```x86asm
0x00002190      55             push ebp
0x00002191      89e5           mov ebp, esp
0x00002193      53             push ebx
0x00002194      57             push edi
0x00002195      56             push esi
0x00002196      83ec2c         sub esp, 0x2c            ; ','
0x00002199      e800000000     call __get_pc_thunk_ebx
0x0000219e      58             pop eax
0x0000219f      81c0622e0000   add eax, 0x2e62          ; eax = 0x5000
0x000021a5      8b4d0c         mov ecx, dword [arg_ch]  ; argv
0x000021a8      8b5508         mov edx, dword [arg_8h]  ; argc
0x000021ab      c745f0000000.  mov dword [local_10h], 0
0x000021b2      837d0802       cmp dword [arg_8h], 2
0x000021b6      8945d8         mov dword [local_28h], eax
0x000021b9      894dd4         mov dword [local_2ch], ecx
0x000021bc      8955d0         mov dword [local_30h], edx
0x000021bf      0f840c000000   je 0x21d1
0x000021c5      c745f0010000.  mov dword [local_10h], 1 ; exit code
0x000021cc      e9d7000000     jmp 0x22a8
```

So we need to pass 2 arguments to the commander. Lets to to 0x21d1...

```x86asm
0x000021d1      c745ec000000.  mov dword [local_14h], 0
0x000021d8      c745e8050000.  mov dword [local_18h], 5
0x000021df      c745e4050000.  mov dword [local_1ch], 5
0x000021e6      c745e0000000.  mov dword [local_20h], 0

0x000021ed      8b45e0         mov eax, dword [local_20h]   ; loop counter
0x000021f0      8b4d0c         mov ecx, dword [arg_ch]
0x000021f3      8b4904         mov ecx, dword [ecx + 4]
0x000021f6      89e2           mov edx, esp
0x000021f8      890a           mov dword [edx], ecx
0x000021fa      8b5dd8         mov ebx, dword [local_28h]
0x000021fd      8945cc         mov dword [local_34h], eax
0x00002200      e82bfeffff     call sym.imp.strlen
0x00002205      8b4dcc         mov ecx, dword [local_34h]
0x00002208      39c1           cmp ecx, eax
; local_20h < len(argv[1])
0x0000220a      0f837b000000   jae 0x228b

0x00002210      8b450c         mov eax, dword [arg_ch]
0x00002213      8b4004         mov eax, dword [eax + 4]
0x00002216      8b4de0         mov ecx, dword [local_20h]
0x00002219      8a1408         mov dl, byte [eax + ecx]
0x0000221c      8855df         mov byte [local_21h], dl     ; argv[1][local_20h]
0x0000221f      8b45e8         mov eax, dword [local_18h]
```

Here's some anti-debugging code

```x86asm
0x00002222      9c             pushfd
0x00002223      5a             pop edx
0x00002224      89d1           mov ecx, edx
0x00002226      81e100010000   and ecx, 0x100   ; EFLAGS.Trap

; Clear EFLAGS.Trap from edx
0x0000222c      31ca           xor edx, ecx

; Copy EFLAGS.Trap to EFLAGS.ZeroFlag
0x0000222e      c1c902         ror ecx, 2
0x00002231      31ca           xor edx, ecx

0x00002233      52             push edx
0x00002234      89c2           mov edx, eax
0x00002236      9d             popfd

; ecx = 0x100 >> 2 i.e. 0x40 if EFLAGS.Trap is set
0x00002237      0f44d1         cmove edx, ecx
0x0000223a      89d0           mov eax, edx
0x0000223c      8945e8         mov dword [local_18h], eax
```

So, **local\_18h** is 0x40 if **EFLAGS.Trap** is set otherwise 0x05

```x86asm
0x0000223f      0fbe45df       movsx eax, byte [local_21h]
0x00002243      8b4de0         mov ecx, dword [local_20h]
0x00002246      8b75d8         mov esi, dword [local_28h]   ; offset 0x5000
0x00002249      0fbe8c0ef1e3.  movsx ecx, byte [esi + ecx - 0x1c0f]
0x00002251      8b7de8         mov edi, dword [local_18h]
0x00002254      8b5de0         mov ebx, dword [local_20h]
0x00002257      0faf5de4       imul ebx, dword [local_1ch]
0x0000225b      01df           add edi, ebx
0x0000225d      0fbebc3e08e0.  movsx edi, byte [esi + edi - 0x1ff8]
0x00002265      31f9           xor ecx, edi
0x00002267      39c8           cmp eax, ecx
0x00002269      0f8509000000   jne 0x2278
0x0000226f      8b45ec         mov eax, dword [local_14h]
0x00002272      83c001         add eax, 1
0x00002275      8945ec         mov dword [local_14h], eax
; CODE XREF from sub.strlen_19e (0x2269)
0x00002278      e900000000     jmp 0x227d
; CODE XREF from sub.strlen_19e (0x2278)
0x0000227d      8b45e0         mov eax, dword [local_20h]
0x00002280      83c001         add eax, 1
0x00002283      8945e0         mov dword [local_20h], eax
0x00002286      e962ffffff     jmp 0x21ed
```

Okay, this is a simple validation loop

```python
m = 5
if debugging:
    m = 0x40
for i in xrange(len(sys.argv[1])):
    argv[1][i] == ((base+0x3008)[5*i+m] ^ (base+0x33f1)[i])
```

```python
┌─[x0r19x91@x0r19x91]─[~/Desktop/ctf/hacklu/ForgetfulCommander/public]
└──╼ $ cat solve.py
#!/usr/bin/env python

def getFlag(text, size, isDebugging=False):
    ans = ''
    delta = 5 + 0x3b*isDebugging
    for i in xrange(size):
        ans += chr(ord(text[5*i+delta+0x3008])^ord(text[i+0x33f1]))
    return ans

with open('forgetful', 'rb') as f:
    data = f.read()
    print '[*] Flag -', getFlag(data, 58)
    # if we have the trap flag set, we get
    print '[*] Fake Flag -', getFlag(data, 58, True)

┌─[x0r19x91@x0r19x91]─[~/Desktop/ctf/hacklu/ForgetfulCommander/public]
└──╼ $ python solve.py
[*] Flag - flag{Just_type__Please__and_the_missles_will_be_launched.}
[*] Fake Flag - This_is_not_the_flag._Tough_luck..........................
```

Yay !!
