---
title: "InsHack 2019 - PaPaVM"
date: 2019-05-06
categories: ["inshack", "reversing"]
tags: ["inshack", "reversing"]
---

    Are you a psychopath ? I am.

    ** PLEASE READ UNTIL THE END **

    NOTA: NO BRUTEFORCE. FLAG IS PRINTABLE. Flag only contains letters, numbers, symbols.

    This binary accepts more than one valid input, if you found one, please head over here: ssh -p 2231 user@papavm.ctf.insecurity-insa.fr (password: user) and enter your flag!

<!--more-->
This is another awesome challenge after xHell.
I've used IDAFree and gdb for this challenge.

The [papavm binary](https://mega.nz/#!AYJxEIAC!nexcIuiA1-P0MgiG76Py1UrTG0CpXietctxFT2-hmQg) is upx packed. Put a breakpoint at **0x470d3c** (`jmp r13`)
Now put another breakpoint at offset **0xea6** wrt the base address stored in **rdi** register.

When the gdb hits the second breakpoint, step through 4 instructions and we land at the main entry point.
The main entry point is at **0x401a30**

```x86asm
0x401a30:	endbr64
0x401a34:	xor    ebp,ebp
0x401a36:	mov    r9,rdx
0x401a39:	pop    rsi
0x401a3a:	mov    rdx,rsp
0x401a3d:	and    rsp,0xfffffffffffffff0
0x401a41:	push   rax
0x401a42:	push   rsp
0x401a43:	mov    r8,0x402d40    ; fini
0x401a4a:	mov    rcx,0x402ca0   ; init
0x401a51:	mov    rdi,0x401d79   ; main
...
```
Now that the binary is unpacked, I dumped it so that I can analyze it with IDA.

```
gef➤  vmmap
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r--
0x0000000000401000 0x0000000000480000 0x0000000000000000 r-x
0x0000000000480000 0x00000000004a4000 0x0000000000000000 r--
0x00000000004a4000 0x00000000004a5000 0x0000000000000000 ---
0x00000000004a5000 0x000000000050f000 0x0000000000000000 rw- [heap]
0x00007ffff7f87000 0x00007ffff7f88000 0x0000000000000000 r-- /home/x0r19x91/Desktop/Capture The Flag/InsHack/PAPAVM/papavm
0x00007ffff7ffa000 0x00007ffff7ffd000 0x0000000000000000 r-- [vvar]
0x00007ffff7ffd000 0x00007ffff7fff000 0x0000000000000000 r-x [vdso]
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
```

I dumped 3 segments - [text](https://mega.nz/#!JEYTla4Y!KKebclGQwd8ig-wtvVFym2t-O-unLS6utS4hD-tMDks) at **0x401000**, [rodata](https://mega.nz/#!oRAhlCbZ!h6elYdELzTXgxr_e-2tZFiEADcP3tIOx3dH4OxObeBg) at **0x480000** and the [heap](https://mega.nz/#!NFJXDSII!Jf6N-jKG4G-B63NmmHHEwOYXMoONhVAhFO7AgkyxXds).
I opened the text segment dump in IDA at offset **0x401000** and rodata, heap as additional input files at offsets **0x480000**, **0x4a5000**

Let's now go back to the original entry point - **0x401a30**. The **main** function is at **0x401d79**. It registers a SIGTRAP handler at **0x401d61**. The SIGTRAP handler dumps an executable and uses **fexecve** to execute it. The binary is stored as - the bytes at even offset are at **0x4a80c0** and the bytes at odd offset are at **0x4c8200**

I was lazy so, I put a breakpoint on **0x401d45** and dumped 0x40261 bytes at address stored in **rax**
```
seg000:0000000000401D3D                 mov     esi, 40261h
seg000:0000000000401D42                 mov     rdi, rax
seg000:0000000000401D45                 call    sub_401B55  ; write to temp file and fexecve
```

Or here's the script

```python
even = 0x30c0
odd = 0x23200
size = 0x40261

dump = open("heap", "rb").read()
elf = open("elf_dump.bin", "wb")
for i in xrange(0, size, 2):
    elf.write(dump[even+i/2])
    elf.write(dump[odd+i/2])
elf.close()
```

Now let's analyze [elf_dump.bin](https://mega.nz/#!RER3kAhS!pZhUYroeBiF-e-SVIMwUeAqKiPsocndu7xM1xFa3XU0) in IDA. Here's the main function

```x86asm
lea     rdi, command    ; "killall -q gdb"
call    _system
lea     rdi, aKillallQStrace ; "killall -q strace"
call    _system
lea     rdi, aKillallQLtrace ; "killall -q ltrace"
call    _system
mov     eax, 0
call    sub_1499
```

These are some anti-debugging measures which terminates all instances of gdb, strace and ltrace.
The function **sub_1499** does rot19 on "SBVZYBVFMVYLAZHTLOATHP"[::-1] which is "IAMTHEMASTEROFYOURSOUL". It is used as the key for decoding another binary. It then proceeds to unpack another binary which is xored with "IAMTHEMASTEROFYOURSOUL".

```python
offset = 0x30a0
size = 0x3C9E1
key = "IAMTHEMASTEROFYOURSOUL"
d = open("elf_dump.bin", "rb").read()
w = open("elf2_dump.bin", "wb")
for i in xrange(size):
    b = ord(key[i % len(key)])
    ch = ord(d[offset+i]) ^ b
    w.write(chr(ch))
w.close()
```

Now here comes the fun part. On opening [elf2_dump.bin](https://mega.nz/#!oQYxEI4L!4LGdLwvXWkVXzjoBoA5mnlGCAdNcKKeWCyS3EXtr8gk) in IDA, we can see in the function list, that there is a function named **main**. This function executes another elf binary. It's a [rust executable](https://mega.nz/#!5QRHgIJA!SSzKiVMYeGEtUhysm8l_Id-QZngLKAHAmde1QXbqQlU) which prints **INSA{I_r34lLy_L0v3_tR0ll1nG !}** a fake flag!

Now lets go to the entrypoint of **elf2_dump.bin**.

![i0](/images/inshack/papavm/main.png)

Now this looks familiar. This is the original executable. It allows three commands - launch, help, quit. If the command is launch, it then reads input using **fgets** and **doesn't remove the newline**.

![i1](/images/inshack/papavm/i1.png)

**fill_mem** initializes mem using - `mem[i] = 31**(i+1) % 2**32`.

## The VM

![i2](/images/inshack/papavm/init_vm.png)

A block of 0x60 bytes is allocated for the vm. The VM has the following structure

```
struct vm_t {
    int64_t ip;         /* Instruction pointer */
    int64_t regs[11];   /* General purpose registers - R0 ... R10 */
};
```

The register R6 is set to the length of the input. R0 is set to the address of **mem** which contains powers of 31. R1 points to the input string.

**run_vm** reads instructions from **0x3CEA0**. The instructions are stored in little-endian format.

```c
struct insn_t {
    signed op: 8;   /* opcode */
    signed dst: 8;   /* destination register */
    signed src: 8;   /* source register */
    signed dd: 8;   /* unused */
};
```

There are 8 different instructions (excluding opcode 0 - which is invalid). The instructions are as follows:

1.  **sub_1542** - Move Immediate

    ```x86asm
    mov regs[dst], src
    ```

2.  **sub_1599** - Compare and set flag

    ```x86asm
    cmp regs[dst], regs[src]
    setz R10
    ```

    It checks if the register R3 is greater than 0x2d. If it is, the program terminates.

3.  **sub_162D** - Conditional Jump

    ```x86asm
    cmp regs[10], 1
    jz regs[dst]
    ```

4.  **sub_1689** - Memory access

    ```c
    if (regs[dst] == 5) {
        regs[dst] = *(byte*) regs[src];
    } else {
        regs[dst] = *(int*) regs[src];
    }
    ```

5.  **sub_1736** - Addition

    ```x86asm
    add regs[dst], regs[src]
    ```

6.  **sub_17AE** - Unconditional Jump

    ```x86asm
    jmp regs[dst]
    ```

7.  **sub_17EA** - Set return value

    ```x86asm
    mov regs[9], regs[dst]
    ```

8.  **sub_1826** - Multiplication

    ```x86asm
    imul regs[dst], regs[src]
    ```

The following code is executed by the VM

```x86asm
mov R0, offset mem
mov R1, offset input
mov R6, len(input)

0000	mov R2, 0
0001	mov R3, 0
0002	mov R7, 0x4
0003	mov R8, 0x1
0004	cmp R3, R6
0004	setz R10
0004	cmp R3, 0x2d
0004	jg exit
0005	cmp R10, 1
0005	jz 0x0e
0006	movsx R4, dword ptr [R0]
0007	movsx R5, byte ptr [R1]
0008	imul R4, R5
0009	add R2, R4
000a	add R0, R7
000b	add R1, R8
000c	add R3, R8
000d	jmp 0x04
000e	mov R9, R2
000e	ret
```

If one line number spans multiple instructions, it means that group is executed by a single function.
Okay, so this function computes a hash by multiplying each byte of input with each dword in **mem**, and adding them. This is a modified version of **String.hashCode** in java. The difference lies in the fact that in java's hashCode, the bytes are multiplied with decreasing powers of 31 ending with 1, whereas in this algorithm the bytes are multiplied with increasing powers of 31 staring from 31.

The value of **R9** is returned by **run_vm** and is compared to **0x0FFFFFFC8B0EB3225**. I wasted a lot of time assuming that the input starts with **INSA{** but the admin told me that input need not start with **INSA{** because there are multiple solutions. The flag will be printed if the input if valid.

I've used z3 to solve it. Here's my initial script

```python
#!/usr/bin/python
from z3 import *

def work(size):
    b = [BitVec('%d' % i, 8) for i in xrange(size)]
    s = Solver()
    t = BitVecVal(0, 64)
    p = 1
    s.add(b[-1] == 10)          # fgets keeps newline
    for i in xrange(size):
        p = p*31 & 0xffffffff
        t += p*SignExt(56, b[i])
    s.add(t == 0xffffffc8b0eb3225)
    if s.check() == sat:
        flag = ""
        ans = s.model()
        for i in b:
            flag += chr(ans[i].as_long())
        print "[*] Found:", flag.encode("base64")

i = 1
while i < 45:
    work(i)
    i += 1
```

This does not produce correct results as the variable **p** is  **unsigned**. The modified script is

```python
#!/usr/bin/python
from z3 import *

def work(size):
    b = [BitVec('%d' % i, 8) for i in xrange(size)]
    s = Solver()
    t = BitVecVal(0, 64)
    p = BitVecVal(1, 32)
    s.add(b[-1] == 10)
    for i in xrange(size):
        p *= 31
        t += SignExt(32, p)*SignExt(56, b[i])
    s.add(t == 0xffffffc8b0eb3225)
    if s.check() == sat:
        flag = ""
        ans = s.model()
        for i in b:
            flag += chr(ans[i].as_long())
        print "[*] Found:", flag.encode("base64")

i = 1
while i < 45:
    work(i)
    i += 1
```

And here's the output

```
[*] Found: lxFXLH7HnQo=
[*] Found: HwDS/2kBggsK
[*] Found: fn/o2/cyx1ckCg==
[*] Found: cWUJbJOIEAgETwo=
[*] Found: onNXD8a9Tk4rXTcK
...
```

Now entering any of these strings for **launch** command will print out the flag - `INSA{P4p4VM_w4Z_r34llY_4m4z1nG_I_L0v3_1t}`

![i3](/images/inshack/papavm/solved.png)
