---
title: "ESET Crackme Challenge"
date: 2019-11-16
tags: [reversing, eset]
categories: [reversing, eset]
---

While searching the internet for good crackmes, I found this one!  

[CrackMe](https://join.eset.com/en/challenges/crack-me)


<!--more-->

I first tried to solve it in 2018. Out of 3 passwords, I could only find two! The second time I tried was on October 19, 2019. This time I could solve it completely.  

Let's dive into it :-)

# Task-1

```x86asm
.text:004013F6                 call    ds:IsDebuggerPresent
.text:004013FC                 test    eax, eax
.text:004013FE                 jz      short loc_401408
.text:00401400                 push    0               ; uExitCode
.text:00401402                 call    ds:ExitProcess
.text:00401408 ; ---------------------------------------------------------------------------
.text:00401408
.text:00401408 loc_401408:                             ; CODE XREF: _main+E↑j
.text:00401408                 mov     [ebp+NumberOfCharsWritten], 0
.text:0040140F                 push    3
.text:00401411                 push    25h
.text:00401413                 push    1Fh
.text:00401415                 push    offset aPleaseEnterVal ; "Please enter valid password : "
.text:0040141A                 call    EncodeDecode
.text:0040141F                 push    0               ; lpReserved
.text:00401421                 lea     eax, [ebp+NumberOfCharsWritten]
.text:00401424                 push    eax             ; lpNumberOfCharsWritten
.text:00401425                 push    offset aPleaseEnterVal ; "Please enter valid password : "
.text:0040142A                 call    _strlen
.text:0040142F                 add     esp, 4
.text:00401432                 push    eax             ; nNumberOfCharsToWrite
.text:00401433                 push    offset aPleaseEnterVal ; lpBuffer
.text:00401438                 mov     ecx, hConsoleOutput
.text:0040143E                 push    ecx             ; hConsoleOutput
.text:0040143F                 call    ds:WriteConsoleA
```

**EncodeDecode** is a simple xor encoding. A small IDA script can save the time :-)

```py
def EncodeDecode(ea, size, xor, inc):
    for i in xrange(size):
        PatchByte(ea, Byte(ea)^xor)
        xor = xor+inc & 0xff
```

The second anti-debugging check is present at

```x86asm
.text:00401622                 mov     eax, large fs:30h        ; PEB
.text:00401628                 movzx   eax, byte ptr [eax+2]    ; PEB.BeingDebugged
.text:0040162C                 test    eax, eax
.text:0040162E                 jnz     short loc_401632
.text:00401630                 jmp     short loc_40163A
.text:00401632 ; ---------------------------------------------------------------------------
.text:00401632
.text:00401632 loc_401632:                             ; CODE XREF: _main+23E↑j
.text:00401632                 push    0               ; uExitCode
.text:00401634                 call    ds:ExitProcess
```

The third anti-debugging check uses `GetTickCount`

```x86asm
.text:00401475                 call    ds:GetTickCount
.text:0040147B                 mov     [ebp+var_14], eax
;
;   ... flag checking stuff ...
;
.text:0040163A loc_40163A:                             ; CODE XREF: _main+240↑j
.text:0040163A                 call    ds:GetTickCount
.text:00401640                 mov     [ebp+var_10], eax
.text:00401643                 mov     eax, [ebp+var_10]
.text:00401646                 sub     eax, [ebp+var_14]
.text:00401649                 cmp     eax, 64h
.text:0040164C                 jbe     short loc_401656
.text:0040164E                 push    0               ; uExitCode
.text:00401650                 call    ds:ExitProcess
```

The flag checking stuff is a series of equations which are validated

```
szInput[7]+szInput[6] == 0xcd &&
szInput[8]+szInput[5] == 0xc9 &&
szInput[7]+szInput[6]+szInput[3] == 0x13a &&
szInput[9]+szInput[4]+szInput[8]+szInput[5] == 0x16f &&
szInput[1]+szInput[0] == 0xc2 &&
szInput[0]+...+szInput[9] == 0x39b
```

From the above equations, we get
```
szInput[3] = 0x13a-0xcd
szInput[2] = 0x39b-(0x16f+0x13a+0xc2)
szInput[0] = ?
szInput[1] = 0xc2-szInput[0]
szInput[4] = ?
szInput[9] = 0x16f-0xc9-szInput[4]
szInput[5] = ?
szInput[8] = 0xc9-szInput[5]
szInput[6] = ?
szInput[7] = 0xcd-szInput[6]
```

If these equations are satisfied, and you bypass the anti-debugging checks, you get

```
.text:00401656 loc_401656:                             ; CODE XREF: _main+25C↑j
.text:00401656                 push    0Ah
.text:00401658                 lea     ecx, [ebp+Buffer]
.text:0040165B                 push    ecx
.text:0040165C                 call    Ror9Hash         ; compute hash
.text:00401661                 cmp     eax, 1928F914h
.text:00401666                 jnz     short loc_4016C9
```

**Ror9Hash** does something like this

```py
def Ror9Hash(buf, size):
    ans = 0
    for i in xrange(size):
        ans = ror(ans, 9)^buf[i]
    return ans
```

So, now do we need to brute 4 bytes for matching the hash? No! Why ??? Analyze a bit more before looking below ....

If the hash matches, the following is printed

```
.data:00418038 aGoodWorkLittle db '!Good work. Little help:',0Ah
.data:00418038                                         ; DATA XREF: _main+2DF↑o
.data:00418038                                         ; _main+2EF↑o ...
.data:00418038                 db 'char[8] = 85',0Ah
.data:00418038                 db 'char[0] + char[2] = 128',0Ah
.data:00418038                 db 'char[4] - char[7] = -50',0Ah
.data:00418038                 db 'char[6] + char[9] = 219',0Ah,0
```

From these equations, we get the key

```py
# solution.py
N = 10
b = ['' for _ in xrange(N)]
b[8] = 85
# 0+2 = 128, 4-7 = -50, 6+9 = 219
# 7+6 = 0xcd
# 8+5 = 0xc9
b[5] = 0xc9-b[8]
# 7+6+3 = 0x13a
b[3] = 0x13a-0xcd
# 9+4+8+5 = 0x16f
# 1+0 = 0xc2
# sum = 0x39b
# sum(0..3) = 351

# 4+5+6+7+8+9 = 572
# 4+7 = 152
# 4-7 = -50

b[4] = 51
b[7] = 50+b[4]
b[6] = 0xcd-b[7]
b[9] = 219-b[6]
# 0+1+2 = 242
b[2] = 242-0xc2
b[1] = 242-128
b[0] = 0xc2 - b[1]

print "".join(map(chr, b))
```

Which yields - `Pr0m3theUs`

But on entering the key, it prints out

```
Congratulations! You guessed the right password, but the message you see is wrong.
Try to look for some unreferenced data, that can be decrypted the same way as this text.
```

So, we missed out something :(

Let's take a step back and look at the ctors (called by `__cinit`)

```x86asm
.text:00402AE8                 mov     esi, offset dword_412144
.text:00402AED                 mov     edi, offset dword_412154
.text:00402AF2                 jmp     short loc_402AFF
.text:00402AF4 ; ---------------------------------------------------------------------------
.text:00402AF4
.text:00402AF4 loc_402AF4:                             ; CODE XREF: __cinit+65↓j
.text:00402AF4                 mov     eax, [esi]
.text:00402AF6                 test    eax, eax
.text:00402AF8                 jz      short loc_402AFC
.text:00402AFA                 call    eax
.text:00402AFC
.text:00402AFC loc_402AFC:                             ; CODE XREF: __cinit+5C↑j
.text:00402AFC                 add     esi, 4
.text:00402AFF
.text:00402AFF loc_402AFF:                             ; CODE XREF: __cinit+56↑j
.text:00402AFF                 cmp     esi, edi
.text:00402B01                 jb      short loc_402AF4
;
; .... stuff ...
;
.rdata:00412144 dword_412144    dd 0                    ; DATA XREF: __cinit+4C↑o
.rdata:00412148                 dd offset InitStdIn
.rdata:0041214C                 dd offset InitStdOut
.rdata:00412150                 dd offset sub_411390
```

**sub_411390** searches for the module whose *Ror9Hash* matches **19B9AC28h**. It happens to be kernel32. The routine then searches the export table for the hash - **0D9A63D0Dh** which resolves to `GetModuleFileName`

```x86asm
.text:0040124B                 mov     ecx, [ebp+var_48]
.text:0040124E                 mov     [ebp+fnGetModuleFileName], ecx
.text:00401251                 push    104h
.text:00401256                 lea     edx, [ebp+szModuleName]
.text:0040125C                 push    edx
.text:0040125D                 push    0
.text:0040125F                 call    [ebp+fnGetModuleFileName]
.text:00401262                 mov     [ebp+var_74], eax
.text:00401265                 push    0               ; char *
.text:00401267                 lea     eax, [ebp+var_478]
.text:0040126D                 push    eax             ; char *
.text:0040126E                 push    0               ; char *
.text:00401270                 push    0               ; char *
.text:00401272                 lea     ecx, [ebp+szModuleName]
.text:00401278                 push    ecx             ; char *
.text:00401279                 call    __splitpath
.text:0040127E                 add     esp, 14h
.text:00401281                 mov     [ebp+var_38], 'C'
.text:00401285                 mov     [ebp+var_37], 'r'
.text:00401289                 mov     [ebp+var_36], '4'
.text:0040128D                 mov     [ebp+var_35], 'c'
.text:00401291                 mov     [ebp+var_34], 'k'
.text:00401295                 mov     [ebp+var_33], 'M'
.text:00401299                 mov     [ebp+var_32], '3'
.text:0040129D                 mov     [ebp+var_31], 0
.text:004012A1                 lea     edx, [ebp+var_38]
.text:004012A4                 push    edx             ; char *
.text:004012A5                 lea     eax, [ebp+var_478]
.text:004012AB                 push    eax             ; char *
.text:004012AC                 call    _strcmp
```

Now I guess we know what to do. Just rename the file `crackme.exe` to `Cr4ckM3.exe` and
```sh
tr1n1ty@tr1n1ty /cygdrive/c/Users/tr1n1ty/Desktop/ESET
$ ./Cr4ckM3.exe
Please enter valid password : Pr0m3theUs
https://join.eset.com/ae50b61499d27d7da010c718f265a9a1/crackme.zip
```

Yeah !! Now we have the actual crackme!


# Task-2


```x86asm
.text:00402375                 push    104h            ; nSize
.text:0040237A                 lea     eax, [ebp+Filename]
.text:00402380                 push    eax             ; lpFilename
.text:00402381                 push    0               ; hModule
.text:00402383                 call    GetModuleFileNameA
.text:00402389                 lea     eax, [ebp+Filename]
.text:0040238F                 lea     ecx, [eax+1]
.text:00402392
.text:00402392 loc_402392:                             ; CODE XREF: start+55↓j
.text:00402392                 mov     dl, [eax]
.text:00402394                 inc     eax
.text:00402395                 test    dl, dl
.text:00402397                 jnz     short loc_402392
.text:00402399                 sub     eax, ecx
.text:0040239B                 mov     [ebp+eax+var_105], 'l'
.text:004023A3                 lea     eax, [ebp+eax+var_106]
.text:004023AA                 mov     word ptr [eax-1], 'ld'
.text:004023B0                 lea     eax, [ebp+Filename]
.text:004023B6                 push    eax             ; lpLibFileName
.text:004023B7                 call    LoadLibraryA
.text:004023BD                 mov     eset_dll, eax
```

The entry point is simple, it just loads EsetCrackme2015.dll

Now in the DllEntryPoint we have

```x86asm
.text:10000231                 mov     eax, large fs:30h
.text:10000237                 mov     eax, [eax+0Ch]
.text:1000023A                 mov     eax, [eax+14h]   ; InMemoryOrderModuleList
.text:1000023D                 push    esi
.text:1000023E                 mov     esi, eax
.text:10000240                 test    eax, eax
.text:10000242                 jz      loc_100002E2
.text:10000248                 push    ebx
.text:10000249                 push    edi
.text:1000024A
.text:1000024A loc_1000024A:                           ; CODE XREF: DllEntryPoint+6B↓j
.text:1000024A                 mov     ecx, [eax+28h]   ; BaseDllName
.text:1000024D                 test    ecx, ecx
.text:1000024F                 jz      loc_100002E0
.text:10000255                 cmp     word ptr [ecx], 0
.text:10000259                 mov     edi, 811C9DC5h
.text:1000025E                 jz      short loc_1000028B
.text:10000260
.text:10000260 loc_10000260:                           ; CODE XREF: DllEntryPoint+5B↓j
.text:10000260                 mov     dl, [ecx]
.text:10000262                 add     ecx, 2
.text:10000265                 lea     ebx, [edx-61h]
.text:10000268                 cmp     bl, 19h
.text:1000026B                 ja      short loc_10000270
.text:1000026D                 add     dl, -20h
.text:10000270
.text:10000270 loc_10000270:                           ; CODE XREF: DllEntryPoint+45↑j
.text:10000270                 movsx   edx, dl
.text:10000273                 xor     edx, edi
.text:10000275                 imul    edx, 1000193h
.text:1000027B                 cmp     word ptr [ecx], 0
.text:1000027F                 mov     edi, edx
.text:10000281                 jnz     short loc_10000260
.text:10000283                 cmp     edi, 0FC706866h
.text:10000289                 jz      short loc_10000295
.text:1000028B
.text:1000028B loc_1000028B:                           ; CODE XREF: DllEntryPoint+38↑j
.text:1000028B                 mov     esi, [esi]
.text:1000028D                 mov     eax, [esi]
.text:1000028F                 test    eax, eax
.text:10000291                 jnz     short loc_1000024A
```

It searches through the list of loaded modules for the hash **0FC706866h** which happens to be **EsetCrackme2015.exe**. The hash algorithm used is

```py
def hash16(name):
    ans = 0x811c9dc5
    for i in name:
        ans = (ans^ord(i.upper()))*0x1000193 & 0xffffffff
    return ans
```

```x86asm
.text:10000295                 mov     eax, [eax+10h]   ; BaseAddress
.text:10000298                 test    eax, eax
.text:1000029A                 jz      short loc_100002E0
.text:1000029C                 mov     ecx, 1000h
.text:100002A1                 mov     edx, 1010101h
.text:100002A6
.text:100002A6 loc_100002A6:                           ; CODE XREF: DllEntryPoint+B0↓j
.text:100002A6                 mov     esi, [ecx+eax]
.text:100002A9                 add     esi, edx
.text:100002AB                 cmp     esi, 0FB131506h
.text:100002B1                 jnz     short loc_100002CF
.text:100002B3                 mov     esi, [ecx+eax+4]
.text:100002B7                 add     esi, edx
.text:100002B9                 cmp     esi, 20C16ADFh
.text:100002BF                 jnz     short loc_100002CF
.text:100002C1                 mov     esi, [ecx+eax+8]
.text:100002C5                 add     esi, edx
.text:100002C7                 cmp     esi, 0C43360A2h
.text:100002CD                 jz      short loc_100002DA
.text:100002CF
.text:100002CF loc_100002CF:                           ; CODE XREF: DllEntryPoint+8B↑j
.text:100002CF                                         ; DllEntryPoint+99↑j
.text:100002CF                 inc     ecx
.text:100002D0                 cmp     ecx, 2F00h
.text:100002D6                 jb      short loc_100002A6
.text:100002D8                 jmp     short loc_100002E0
.text:100002DA ; ---------------------------------------------------------------------------
.text:100002DA
.text:100002DA loc_100002DA:                           ; CODE XREF: DllEntryPoint+A7↑j
.text:100002DA                 lea     eax, [ecx+eax+0Ch]
.text:100002DE                 call    eax
```

So, it finds the address of the following sequence of bytes in **EsetCrackme2015.exe**  
`05 14 12 fa de 69 c0 1f a1 5f 32 c3​`, which happens to be

```x86asm
.text:00401E93 add eax, 0DEFA1214h
.text:00401E98 imul eax, 325FA11Fh
.text:00401E9E retn
```

So, the real entry point is 0x401e93+0xc = `0x401e9f`

I've renamed the real entry point as **Main**

```x86asm
.text:00401E9F Main            proc near
.text:00401E9F                 push    edi
.text:00401EA0                 xor     edi, edi
.text:00401EA2                 cmp     zero, edi
.text:00401EA8                 jz      short loc_401ED9
.text:00401EAA                 push    esi
.text:00401EAB                 call    getKernel32
.text:00401EB0                 mov     esi, eax
.text:00401EB2                 push    Sleep           ; Sleep
.text:00401EB7                 call    resolve_export_hash
.text:00401EBC                 push    edi
.text:00401EBD                 push    edi
.text:00401EBE                 push    eax
.text:00401EBF                 push    offset Thread1_Proc
.text:00401EC4                 push    edi
.text:00401EC5                 push    edi
.text:00401EC6                 push    CreateThread    ; CreateThread
.text:00401ECB                 mov     zero, edi
.text:00401ED1                 call    resolve_export_hash
.text:00401ED6                 call    eax
.text:00401ED8                 pop     esi
.text:00401ED9
.text:00401ED9 loc_401ED9:                             ; CODE XREF: Main+9↑j
.text:00401ED9                 pop     edi
.text:00401EDA                 retn
.text:00401EDA Main            endp
;
;   ...
;
.text:0040101C Name            db 'EsetCrackme2015',0  ; DATA XREF: start+9↓o
.text:0040102C eset_dll        dd 0CCCCCCCCh           ; DATA XREF: start+7B↓w
.text:00401030 zero            dd 0ED174512h
```

Here's a small IDAPy script to rename imported hashes

```py
def hashIt(name):
    ans = 0x811c9dc5
    for ch in name:
        ans = (ans ^ ord(ch)) * 0x1000193 & 0xffffffff
    return ans

x = AddEnum(-1, "Global", idaapi.decflag())
names = open("kernel_user32.txt").read().split()
for name in names:
    AddConstEx(x, name, hashIt(name), -1)
```

where **kernel_user32.txt** contains a list of kernel32+user32 exports  

`resolve_export_hash` uses **hash16** algorithm to find a function, given a hash, from the export table of the module base in **esi**. **Thread1_Proc** calls **sub_40213B** with **eax** pointing to **EsetCrackme2015.dll**'s base address.  

The routine **sub_40213B** is interesting. It sets up a data structure at **ebp-0x138**

```no-highlight
+--------------------------------------------------------------------------------+
| +0     | Base address of EsetCrackme2015.dll                                   |
| +4     | EsetCrackme2015_dll.SizeofImage                                       |
| +8     | 128 words initialized to 0 (Marked Array), Initially Unmarked         |
| +0x108 | bStopProcessing (initially 0)                                         |
| +0x109 | bResourcesLoaded (initially 0)                                        |
| +0x10b | dwTagToExtract (initially 1)                                          |
| +0x10d | Handle returned by CreateEvent                                        |
| +0x111 | _resolve_export                                                       |
| +0x115 | xor_string                                                            |
| +0x119 | unpack_pe                                                             |
| +0x11d | unpack_pe_key (“SXJyZW4lMjBpc3QlMjBtZW5zY2hsaWNo”)                    |
| +0x121 | hPipe ("\\.\pipe\EsetCrackmePipe")                                    |
+--------------------------------------------------------------------------------+
```

```x86asm
.text:004021E8                 push    101h
.text:004021ED                 mov     [esi+125h], eax
.text:004021F3                 mov     dword ptr [esi+115h], offset xor_string
.text:004021FD                 mov     dword ptr [esi+111h], offset _resolve_export
.text:00402207                 mov     [esi+108h], bl
.text:0040220D                 call    _lookup_tag
.text:00402212                 push    3
.text:00402214                 mov     edi, eax
.text:00402216                 call    _lookup_tag
.text:0040221B                 pop     ecx
.text:0040221C                 pop     ecx
.text:0040221D                 cmp     edi, ebx
.text:0040221F                 jz      loc_4022D5
.text:00402225                 cmp     eax, ebx
.text:00402227                 jz      loc_4022D5
```

Here the binary loads some resources with id's 3 and 0x101. The resources have the following layout

```c
struct resource_t
{
    uint16_t tag;
    uint32_t size;
    uint8_t data[];
};
```

```x86asm
.text:0040222D                 mov     edx, [ebp+hKernel32]
.text:00402230                 push    20h
.text:00402232                 add     edx, 4Dh
.text:00402235                 push    edx
.text:00402236                 push    dword ptr [eax+2]
.text:00402239                 lea     ecx, [eax+6]
.text:0040223C                 push    ecx
.text:0040223D                 mov     [ebp+pe], ecx
.text:00402240                 call    xor_string
.text:00402245                 mov     eax, [ebp+pe]
.text:00402248                 push    eax
.text:00402249                 mov     [esi+11Dh], eax
.text:0040224F                 push    dword ptr [edi+2]
.text:00402252                 lea     esi, [edi+6]
.text:00402255                 push    esi
.text:00402256                 call    unpack_pe
.text:0040225B                 push    esi
.text:0040225C                 push    esi
.text:0040225D                 call    relocate_pe
.text:00402262                 mov     eax, [edi+406h]
.text:00402268                 add     esp, 24h
.text:0040226B                 mov     [ebp+pe], eax
```

From this code, its certain that resource **0x151** is a PE file and resource **3** is the key for unpacking the PE file.

```c
void xor_string(char* buf, int size, char* str, int len)
{
    for (i = 0; i < size; ++i)
        buf[i] ^= str[i%len];
}
```

The resource with id 3 is decoded with the above algorithm, by passing 32 for len and "!This program cannot be run in DOS mode." for str.  
So, resource with id 3 contains `SXJyZW4lMjBpc3QlMjBtZW5zY2hsaWNo​` which is base64 of ​`escape("Irren ist menschlich")`​.  The address of the data is stored in [ebp-0x1B]

Finally the thread calls **[ebp+pe]** in a loop, with a single argument to ecx which is the address of the data structure (ebp-0x138)

```x86asm
.text:00402270 loc_402270:                             ; CODE XREF: sub_40213B+14D↓j
.text:00402270                                         ; sub_40213B+198↓j
.text:00402270                 pushaw
.text:00402272                 mov     ecx, ebp_138h
.text:00402278                 call    [ebp+pe]
.text:0040227B                 movzx   eax, ax
.text:0040227E                 mov     [ebp+hKernel32], eax
.text:00402281                 popaw
.text:00402283                 xor     ebx, ebx
.text:00402285                 cmp     [ebp+hKernel32], ebx
.text:00402288                 jnz     short loc_402270
.text:0040228A                 mov     esi, ebp_138h
.text:00402290                 cmp     [esi+108h], bl
.text:00402296                 jnz     short loc_4022D5
.text:00402298                 push    0FFFFFFFFh
.text:0040229A                 push    dword ptr [esi+10Dh]
.text:004022A0                 xor     eax, eax
.text:004022A2                 mov     [esi+10Bh], ax
.text:004022A9                 mov     esi, [esi+129h]
.text:004022AF                 sub     esi, 54ED3267h
.text:004022B5                 push    WaitForSingleObject
.text:004022BA                 xor     esi, 0AB12CD99h
.text:004022C0                 call    resolve_export_hash
.text:004022C5                 call    eax
.text:004022C7
.text:004022C7 loc_4022C7:                             ; CODE XREF: sub_40213B+133↑j
.text:004022C7                 mov     esi, ebp_138h
.text:004022CD                 cmp     [esi+108h], bl
.text:004022D3                 jz      short loc_402270
```

Let’s take a look at the function executed by Thread 2 at 0x0401F13. Let’s call it **Thread2_Proc**.

```x86asm
.text:00401F19                 push    2
.text:00401F1B                 call    _lookup_tag
.text:00401F20                 pop     ecx
.text:00401F21                 test    eax, eax
.text:00401F23                 jnz     short loc_401F2D
.text:00401F25                 or      eax, 0FFFFFFFFh
.text:00401F28                 jmp     locret_402099
.text:00401F2D ; ---------------------------------------------------------------------------
.text:00401F2D
.text:00401F2D loc_401F2D:                             ; CODE XREF: Thread2_Proc+10↑j
.text:00401F2D                 mov     [ebp+var_4], 223F043Eh
.text:00401F34                 add     [ebp+var_4], 23114512h   ; "PIPE"
.text:00401F3B                 push    4
.text:00401F3D                 lea     edx, [ebp+var_4]
.text:00401F40                 push    edx
.text:00401F41                 push    dword ptr [eax+2]
.text:00401F44                 lea     ecx, [eax+6]
.text:00401F47                 push    ecx
.text:00401F48                 mov     [ebp+szPipeName], ecx
.text:00401F4B                 call    xor_string
```

Cool. So resource 2 contains the pipe path, xor encoded using the string `"PIPE"`.

```x86asm
.text:00401F50                 mov     eax, ebp_138h
.text:00401F55                 add     esp, 10h
.text:00401F58                 cmp     byte ptr [eax+108h], 0
.text:00401F5F                 jnz     loc_402097
.text:00401F65                 push    ebx
.text:00401F66                 push    esi
.text:00401F67                 push    edi
.text:00401F68                 mov     ebx, 54ED3267h
.text:00401F6D                 mov     edi, 0AB12CD99h
.text:00401F72
.text:00401F72 loc_401F72:                             ; CODE XREF: Thread2_Proc+17B↓j
.text:00401F72                 mov     esi, [eax+129h]
.text:00401F78                 xor     edx, edx
.text:00401F7A                 push    edx
.text:00401F7B                 push    edx
.text:00401F7C                 mov     ecx, 200h
.text:00401F81                 push    ecx
.text:00401F82                 push    ecx
.text:00401F83                 push    0FFh
.text:00401F88                 push    edx
.text:00401F89                 push    3
.text:00401F8B                 push    [ebp+szPipeName] ; "\\.\pipe\EsetCrackmePipe"
.text:00401F8E                 sub     esi, ebx
.text:00401F90                 push    CreateNamedPipeA
.text:00401F95                 xor     esi, edi
.text:00401F97                 call    resolve_export_hash
.text:00401F9C                 call    eax
```

So, it creates a named pipe "\\.\pipe\EsetCrackmePipe"

```x86asm
.text:00401FEE                 lea     eax, [ebp+b1]
.text:00401FF1                 push    eax             ; buffer
.text:00401FF2                 push    1               ; size
.text:00401FF4                 call    read_pipe
.text:00401FF9                 lea     eax, [ebp+b2]
.text:00401FFC                 push    eax             ; buffer
.text:00401FFD                 push    2               ; size
.text:00401FFF                 call    read_pipe
.text:00402004                 push    dword ptr [ebp+b2]
.text:00402007                 push    dword ptr [ebp+b1]
.text:0040200A                 call    process
.text:0040200F                 mov     eax, ebp_138h
.text:00402014                 mov     esi, [eax+129h]
.text:0040201A                 add     esp, 18h
.text:0040201D                 push    dword ptr [eax+121h]
.text:00402023                 sub     esi, ebx
.text:00402025                 push    FlushFileBuffers
.text:0040202A                 xor     esi, edi
.text:0040202C                 call    resolve_export_hash
.text:00402031                 call    eax
.text:00402033                 mov     eax, ebp_138h
.text:00402038                 mov     esi, [eax+129h]
.text:0040203E                 push    dword ptr [eax+121h]
.text:00402044                 sub     esi, ebx
.text:00402046                 push    DisconnectNamedPipe
.text:0040204B                 xor     esi, edi
.text:0040204D                 call    resolve_export_hash
.text:00402052                 call    eax
```

It reads a byte followed by a int16 and then processes it. This is repeated while **bStopProcessing** is 0.  

```x86asm
.text:00401E1C                 lea     eax, [ebp+b1]
.text:00401E1F                 push    eax             ; buffer
.text:00401E20                 push    1               ; size
.text:00401E22                 call    write_pipe
.text:00401E27                 lea     eax, [ebp+b2]
.text:00401E2A                 push    eax             ; buffer
.text:00401E2B                 push    2               ; size
.text:00401E2D                 call    write_pipe
.text:00401E32                 add     esp, 10h
.text:00401E35                 cmp     [ebp+b1], 1
.text:00401E39                 jnz     short loc_401E65
.text:00401E3B                 push    [ebp+b2]
.text:00401E3E                 call    _lookup_tag
.text:00401E43                 mov     edi, eax
.text:00401E45                 pop     ecx
.text:00401E46                 test    edi, edi
.text:00401E48                 jz      short loc_401E87
.text:00401E4A                 lea     esi, [edi+2]
.text:00401E4D                 push    esi             ; buffer
.text:00401E4E                 push    4               ; size
.text:00401E50                 call    write_pipe
.text:00401E55                 add     edi, 6
.text:00401E58                 push    edi             ; buffer
.text:00401E59                 push    dword ptr [esi] ; size
.text:00401E5B                 call    write_pipe
.text:00401E60                 add     esp, 10h
.text:00401E63                 jmp     short loc_401E8F
.text:00401E65 ; ---------------------------------------------------------------------------
.text:00401E65
.text:00401E65 loc_401E65:                             ; CODE XREF: process+22↑j
.text:00401E65                 cmp     [ebp+b1], 2
.text:00401E69                 jnz     short loc_401E77
.text:00401E6B                 mov     esi, [ebp+b2]
.text:00401E6E                 call    _mark
.text:00401E73
.text:00401E73 loc_401E73:                             ; CODE XREF: process+6E↓j
.text:00401E73                 push    0
.text:00401E75                 jmp     short loc_401E89
.text:00401E77 ; ---------------------------------------------------------------------------
.text:00401E77
.text:00401E77 loc_401E77:                             ; CODE XREF: process+52↑j
.text:00401E77                 cmp     [ebp+b1], 3
.text:00401E7B                 jnz     short loc_401E87
.text:00401E7D                 mov     esi, [ebp+b2]
.text:00401E80                 call    _clear_mark
```

So, process writes the bytes into the pipe in the order they were read. The first byte can take three values only - 1, 2 and 3.  

1. Lookup tag whose id is the next two bytes and write the resource preceded by its length
2. Mark tag of the given 2 byte id (in the marked array, at offset +8 wrt ebp-0x138)
3. Clear marked tag

### Extracting Resources

Here's a small C program to extract the resources

```c
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

typedef void (*FUNC) (void*, DWORD, char*);

char g_szKey[] = "SXJyZW4lMjBpc3QlMjBtZW5zY2hsaWNo";

char* lookup(void* hDll, short tag)
{
    char* ptr = (char*) hDll;
    while (*(short*)(ptr) != tag)
    {
        ptr += 6+*(int*)(ptr+2);
    }
    return ptr;
}

int main(int argc, char** argv)
{
    if (argc == 1)
    {
        printf("Usage: %s [tag bUnpack? file_name]*\n", argv[0]);
        exit(0);
    }

    HMODULE hExe = LoadLibrary("EsetCrackme2015.exe");
    HMODULE hDll = LoadLibraryEx("EsetCrackme2015.dll", NULL, 1);

    FUNC unpackMe = (FUNC) ((char*) hExe + 0x1000 + 0xd11 - 0x200);

    for (char** p = argv; *++p; p += 2)
    {
        short m_tag;
        sscanf(p[0], "%hi", &m_tag);
        char* tag = lookup(hDll, m_tag);
        
        if (p[1][0] == '1')
            unpackMe(tag+6, *(DWORD*)(tag+2), g_szKey);
        FILE* dp = fopen(p[2], "wb");
        fwrite(tag+6, 1, *(DWORD*)(tag+2), dp);
        fclose(dp);
    }
}
```

## Resource 0x101

```x86asm
.text:004009A9                 push    ebp
.text:004009AA                 mov     ebp, esp
.text:004009AC                 sub     esp, 104h
.text:004009B2                 push    esi
.text:004009B3                 mov     esi, ecx
.text:004009B5                 mov     ebp_138h, esi
.text:004009BB                 call    is_initialized?
.text:004009C0                 test    al, al
.text:004009C2                 jz      short loc_4009CE
.text:004009C4                 call    LoadResources
.text:004009C9                 jmp     loc_400BA5
.text:004009CE ; ---------------------------------------------------------------------------
.text:004009CE
.text:004009CE loc_4009CE:                             ; CODE XREF: sub_4009A9+19↑j
.text:004009CE                 call    has_all_extracted?
.text:004009D3                 test    al, al
.text:004009D5                 jz      short loc_4009E1
.text:004009D7                 call    FreeResources
.text:004009DC                 jmp     loc_400BA5
```

**LoadResources** fetches resources - 0x102, 0x103 and 0x104

```x86asm
.text:004009E1                 push    0BB01h
.text:004009E6                 call    is_marked?
.text:004009EB                 pop     ecx
.text:004009EC                 test    al, al
.text:004009EE                 jz      loc_400A75
.text:004009F4                 push    0BB02h
.text:004009F9                 call    is_marked?
.text:004009FE                 pop     ecx
.text:004009FF                 test    al, al
.text:00400A01                 jz      short loc_400A75
.text:00400A03                 push    0BB03h
.text:00400A08                 call    is_marked?
.text:00400A0D                 pop     ecx
.text:00400A0E                 test    al, al
.text:00400A10                 jz      short loc_400A75
.text:00400A12                 push    0FF01h
.text:00400A17                 call    is_marked?
.text:00400A1C                 pop     ecx
.text:00400A1D                 test    al, al
.text:00400A1F                 jz      short loc_400A75
.text:00400A21                 push    offset aUser32Dll ; "user32.dll"
.text:00400A26                 push    LoadLibraryA
.text:00400A2B                 call    dword ptr [esi+111h]
.text:00400A31                 call    eax
.text:00400A33                 push    40h
.text:00400A35                 push    offset aInfo    ; "Info"
.text:00400A3A                 push    offset aThatsAllCongra ; "Thats all. Congratulations!"
.text:00400A3F                 push    0
.text:00400A41                 push    offset aMessageboxa ; "MessageBoxA"
.text:00400A46                 push    eax
.text:00400A47                 mov     eax, ebp_138h
.text:00400A4C                 push    GetProcAddress
.text:00400A51                 call    dword ptr [eax+111h]
.text:00400A57                 call    eax
.text:00400A59                 call    eax
.text:00400A5B                 mov     ecx, ebp_138h
.text:00400A61                 mov     eax, 0FFFFh
.text:00400A66                 mov     [ecx+10Bh], ax   ; mark finished
```

So, resources 0xbb01, 0xbb02, 0xbb03 and 0xff01 must be marked to complete the entire challenge. Initially none of these are marked.  
Also, dwTagToExtract is 1. So the following code is executed

```x86asm
.text:00400AA8                 mov     esi, offset aSvchostExe ; "\\svchost.exe"
.text:00400AAD                 movsd
.text:00400AAE                 movsd
.text:00400AAF                 movsd
.text:00400AB0                 lea     eax, [ebp+szSystem32Path]
.text:00400AB6                 push    eax
.text:00400AB7                 movsb
.text:00400AB8                 call    spawn_svchost
.text:00400ABD                 mov     esi, ebp_138h
.text:00400AC3                 pop     ecx
.text:00400AC4                 push    2
.text:00400AC6                 pop     eax
.text:00400AC7                 mov     [esi+109h], ax
```

a RunPE technique is used to execute the PE file, resource 0x151.  
If dwTagToExtract is 0xbb01, then **drv.zip** is extracted

```x86asm
.text:00400ADC                 push    1
.text:00400ADE                 push    offset aDrvZip  ; "drv.zip"
.text:00400AE3                 mov     eax, 152h
.text:00400AE8                 call    extract_resource
```

If dwTagToExtract is 0xaa01, then **PuncherMachine** and **PunchCardReader** are extracted

```x86asm
.text:00400B11                 push    1
.text:00400B13                 push    offset aPunchcardreade ; "PunchCardReader.exe"
.text:00400B18                 mov     eax, 154h
.text:00400B1D                 call    extract_resource
.text:00400B22                 push    1
.text:00400B24                 push    offset aPunchermachine ; "PuncherMachine.exe"
.text:00400B29                 mov     eax, 153h
.text:00400B2E                 call    extract_resource
.text:00400B33                 push    1               ; bUnpack
.text:00400B35                 push    4               ; "\\?\GLOBALROOT\Device\45736574\"
.text:00400B37                 call    get_resource
```

## Resource 0x102 - A Virtual Machine

Here is my analysis of the resource 0x102.

#### ldr(type, index, size)
```no-highlight
if type == 0:
    if size == 0:
        return (byte) regs[index]
    elif size == 1:
        return (word) regs[index]
    else:
        return (dword) regs[index]
elif type == 1:
    if size == 0:
        return *(byte*) regs[index]
    elif size == 1:
        return *(word*) regs[index]
    else:
        return *(dword*) regs[index]
elif type == 2:
    if size == 0:
        return _get_int8()
    elif size == 1:
        return _get_int16()
    else:
        return _get_int32()
elif type == 3:
    return vm[0x45a] + _get_int32()
```
#### str(type,size,data,index)
```no-highlight
if type == 1:
    regs[index] = data
elif type == 2:
    ssize = size == 0 ? 'byte' : size == 1 ? 'word' : 'dword'
    *([ssize]*) regs[index] = data
```
#### call()
```no-highlight
o = read1()
fn = ldr(o.type, o.index, 2)
sesp = esp
esp = stack_top
call fn(eax=regs[0])
stack_top=esp
esp = sesp
regs[0]=eax
```

#### CALL_STDLIB()
```no-highlight
o = read2()
iFnHash = ldr(o.ldr_type, o.str_index, 2)
iModHash = ldr(o.str_type, o.ldr_index, 2)
if o.ldr_type == 3:
    iFnHash = *(dword) iFnHash
if o.str_type == 3:
    iModHash = *(dword) iModHash
if iModHash == 0:
    hModBase = vm[0x409]
else:
    hModBase = ResolveModule(iModHash)
if hModBase == 0:
    hModBase = _probably_LoadModule(iModHash)
fn = ResolveExport(hModBase, iFnHash)
sesp = esp
esp = stack_top
call fn(eax=regs[0])
stack_top=esp
esp = sesp
regs[0]=eax
```
#### PUSH()
```no-highlight
o = read1()
data = ldr(o.type, o.index, o.word_size)
vm.stack.push(data)
```

#### POP_REG()
```no-highlight
o = read1()
regs[o.index] = pop()
```

#### CMP()
```no-highlight
o = read2()
d = ldr(o.ldr_type, o.ldr_index, o.str_type)
r = regs[o.str_index]
if o.word_size == 0:
    vm.flags = r == d
elif o.word_size == 1:
    vm.flags = r != d
elif o.word_size == 2:
    vm.flags = r >= d
```

#### JMP()
```no-highlight
o = read1()
d = ldr(2, 0, 2)
if o == 0:
    vm.next_insn_offset = d
elif o == 1:
    if vm.flags:
        vm.flags = 0
        vm.next_insn_offset = d
```

#### CALL_VM()
```no-highlight
d = ldr(2, 0, 2)
vm.stack.push(vm.next_insn_offset)
vm.next_insn_offset = d
```

#### RET_VM()
```no-highlight
vm.next_insn_offset = vm.stack.pop()
```

#### ALU()
```no-highlight
o = read2()
d = ldr(o.ldr_type, o.ldr_index, o.str_type)
if o.word_size == 0:
    regs[o.str_index] ^= d
elif o.word_size == 1:
    regs[o.str_index] += d
elif o.word_size == 2:
    regs[o.str_index] -= d
elif o.word_size == 3:
    regs[o.str_index] <<= d
elif o.word_size == 4:
    regs[o.str_index] >>= d
elif o.word_size == 5:
    rol = lambda a, b, c: a<<b|a>>8*c-b
    regs[o.str_index] = rol(regs[o.str_index], d, 2**o.str_type)
elif o.word_size == 6:
    ror = lambda a, b, c: a<<b|a>>8*c-b
    regs[o.str_index] = ror(regs[o.str_index], d, 2**o.str_type)
elif o.word_size == 7:
    regs[o.str_index] %= d
```

#### MALLOC()
```no-highlight
o = read1()
d = ldr(o.type, o.index, o.word_size)
regs[0] = VirtualAlloc(size=d, flags=0x40)
```

#### FREE()
```no-highlight
o = read1()
d = ldr(o.type, o.index, o.word_size)
free(d)
```

#### EMULATE()
```no-highlight
o = read2()
d1 = ldr(o.ldr_type, o.str_index, 2)
d2 = ldr(o.str_type, o.ldr_index, o.word_size)
mem = alloc(size=d2<<2, flags=0x40)
for i in xrange(d2):
    mem[i] = vm.stack.pop()
vm2 = {}
vm2.init()
vm2.run(d1, vm.kernel32, d2, mem)
vm2.free()
```

```no-highlight
RunVM(lpRes, hModule, nElem, lpArray)
{
    if (hModule || vm.bModuleLoaded)
        vm.hModule = hModule
    else
        vm.hModule = ResolveModule("kernel32")
    mem = alloc(lpRes.size, flags=0x40)
    memcpy(mem, lpRes, lpRes.size)
    vm[0x45a] = mem+[lpRes+6]
    vm[0x3fd] = mem
    vm[0x401] = lpRes.size
    vm.insn_base = mem+0x12
    stk = alloc(0x400000, flags=4)
    if (vm.stack_base)
        free(vm.stack_base)
    vm.stack_base = stk
    vm.stack_top = stk+4*0xfffff
    memset(vm.regs, 0, 0x10*4)
    vm.regs[6] = vm.stack_top
    vm.regs[7] = vm[0x3fd]
    vm.regs[8] = vm[0x401]
    vm.regs[9] = vm.hModule
    for i in xrange(vm.nArgs):
        vm.regs[i+10] = vm.lpArgs[i]
    if (lpRes.sign != 0x1337)
        LoopVM()    // decrypt vm code
    vm.insn_base = &lpResource.code_offset
    Return LoopVM()
}

LoopVM()
{
    vm.insn_base = lpRes.insn_base
    while (vm.bRunning)
    {
        vm.func[_get_byte()]()
    }
    return vm.regs[0]
}
```

```no-highlight
+0      STOP
+4      MOV
+8      CALL
+0xc    CALL_STDLIB
+0x10   PUSH
+0x14   POP_REG
+0x20   CMP
+0x24   JMP
+0x28   CALL_VM
+0x28   RET_VM
+0x30   ALU
+0x34   MALLOC
+0x38   FREE
+0x40   EMULATE
+0x44   STOP
...
+0x3f8  STOP
+0x3fc  bRunning
+0x3fd  lpResource
+0x401  lpResource.size
+0x405  bModuleLoaded? ([lpResource+0xe])
+0x409  hModule (kernel32)
+0x40d  nArgs
+0x411  lpArgs
+0x415  flags
+0x416  regs
+0x42e  stack_top
+0x456  insn_base
+0x45a  data_base
+0x45e  next_insn_offset
+0x462  stack_top
+0x466  stack_base
```

```c
struct insn8
{
    unsigned index: 4;
    unsigned type: 2;
    unsigned word_size:2;
};

struct insn16
{
    unsigned str_index: 4;
    unsigned ldr_index: 4;
    unsigned ldr_type: 2;
    unsigned str_type: 2;
    unsigned word_size: 3;
    unsigned __pad:1;
};
```

### File Layout (0x102)

```no-highlight
+------------------------+
|+0    |  signature      |
|+2    |  code_offset    |
|+6    |  data_offset    |
|+0xa  |  size           |
|+0xe  |  bModuleLoaded? |
+------------------------+
```

If signature is not 0x1337, then code is encrypted, which must be decrypted using the signature as the xor key. Let’s look at the disassembly of resource 0x103.

```no-highlight
00    ldr X, R7             
      str X, R0             
03    ldr X, byte ptr [R0]  
      str X, R1             
06    ldr X, 0x1            
      add R0, X             
0a    ldr X, byte ptr [R0]  
      str X, R2             
0d    ldr X, 0x1            
      add R0, X             
11    ldr X, dword ptr [R0] 
      str X, R3             
14    ldr X, R8             
      str X, R0             
17    ldr X, R7             
      add R0, X             
1a    ldr X, R7             
      add R3, X             
1d    ldr X, byte ptr [R3]  
      str X, R4             
20    ldr X, R1             
      xor R4, X             
23    ldr X, R2             
      add R1, X             
26    ldr X, R4             
      str X, byte ptr [R3]  
29    ldr X, 0x1            
      add R3, X             
2d    ldr X, R0             
      cmp.ge X, R3          
30    ldr X, 0x1d           
      jmp.cc X              
36    ldr X, R7             
      str X, R0             
39    ldr X, 0x37           
      str X, byte ptr [R0]  
3d    ldr X, 0x1            
      add R0, X             
41    ldr X, 0x13           
      str X, byte ptr [R0]  
45    hlt
```

Yeah, it's a xor encryption

```py
key = b.sign[0]
incr = b.sign[1]

for i in xrange(b.code_offset, b.code_offset+b.size):
    b[i] = (b[i]^key) + incr & 0xff
```

## Resource 0x151

```x86asm
.text:004019FB                 mov     eax, 0DF09C20Dh
.text:00401A00                 mov     esi, [ebp+hWnd]
.text:00401A03                 mov     ecx, offset dword_412EF0
.text:00401A08                 mov     hWnd, esi
.text:00401A0E                 call    initialize
.text:00401A13                 lea     ecx, [ebp+uMsg]
.text:00401A16                 push    ecx             ; lpThreadId
.text:00401A17                 push    0               ; dwCreationFlags
.text:00401A19                 push    offset dword_412EF0 ; lpParameter
.text:00401A1E                 push    offset StartAddress ; lpStartAddress
.text:00401A23                 push    0               ; dwStackSize
.text:00401A25                 push    0               ; lpThreadAttributes
.text:00401A27                 call    ds:CreateThread
.text:00401A2D                 mov     hDlg, esi
.text:00401A33                 call    AcquireDebugPriv
.text:00401A38                 call    GetResource
```

The function **GetResource** fetches resources 0xbb01 and 0xbb02. 0xbb01 is xor encrypted using **"PIPE"**. Decoding gives three sha160 hashes.  
**initialize** initializes **dword_412EF0** with **_resolve_sha1** and **dword_412EF4** with `LoadLibraryA`.  

```x86asm
.text:0040228A                 mov     eax, [ebp+var_10]
.text:0040228D                 mov     eax, [eax]
.text:0040228F                 mov     ecx, [edi+8]
.text:00402292                 push    0
.text:00402294                 push    eax
.text:00402295                 push    0
.text:00402297                 push    ecx
.text:00402298                 call    ebx
.text:0040229A                 push    offset Edit_Handler
.text:0040229F                 push    GWLP_WNDPROC
.text:004022A1                 push    eax
.text:004022A2                 mov     _loadLib_sha1, edi
.text:004022A8                 call    esi             ; SetWindowLong
.text:004022AA                 mov     [edi+0Ch], eax
;
; ....
;
.text:004022ED                 push    offset lstrcmpA
.text:004022F2                 push    eax
.text:004022F3                 call    ecx
.text:004022F5                 mov     edx, [edi+4]
.text:004022F8                 push    eax
.text:004022F9                 call    edx
.text:004022FB                 jmp     short loc_4022FF
.text:004022FD ; ---------------------------------------------------------------------------
.text:004022FD
.text:004022FD loc_4022FD:                             ; CODE XREF: sub_402170+175↑j
.text:004022FD                                         ; sub_402170+17B↑j
.text:004022FD                 xor     eax, eax
.text:004022FF
.text:004022FF loc_4022FF:                             ; CODE XREF: sub_402170+18B↑j
.text:004022FF                 mov     [edi+114h], eax ; lstrcmpA
```

Here the message handler for the first text box is changed to **Edit_Handler**. Let's see what **Edit_Handler** does

```x86asm
.text:004023EC                 mov     ecx, eax
.text:004023EE                 call    base64_size
.text:004023F3                 mov     edi, eax
.text:004023F5                 push    edi             ; size_t
.text:004023F6                 call    operator new(uint)
.text:004023FB                 add     esp, 4
.text:004023FE                 push    ebx
.text:004023FF                 lea     ecx, [ebp+szInput]
.text:00402402                 mov     esi, eax
.text:00402404                 push    ecx
.text:00402405                 mov     ecx, [ebp+var_4C]
.text:00402408                 mov     [ebp+var_5C], esi
.text:0040240B                 call    toBase64
.text:00402410                 xor     eax, eax
.text:00402412                 mov     byte ptr [esi+edi-1], 0
```

Okay, so the input is first converted to base64

```x86asm
.text:00402420 loc_402420:                             ; CODE XREF: Edit_Handler+BB↑j
.text:00402420                                         ; Edit_Handler+CB↓j
.text:00402420                 mov     dl, al
.text:00402422                 and     dl, 1
.text:00402425                 sub     [eax+esi], dl
.text:00402428                 inc     eax
.text:00402429                 cmp     eax, edi
.text:0040242B                 jl      short loc_402420
```

Subtracts the parity of the offset of each byte from the bytes.  

```x86asm
.text:0040242D                 mov     eax, _loadLib_sha1   ; 0x00412EF0
.text:00402432                 mov     edx, [eax+114h]
.text:00402438                 lea     ecx, [eax+118h]
.text:0040243E                 push    ecx
.text:0040243F                 push    esi
.text:00402440                 call    edx  ; lstrcmpA
.text:00402442                 test    eax, eax
.text:00402444                 jnz     short loc_40246E
.text:00402446                 mov     [ebp+var_4C], eax
.text:00402449                 push    5               ; unk
.text:0040244B                 lea     eax, [ebp+var_4C]
.text:0040244E                 push    eax             ; buffer
.text:0040244F                 push    0BB01h          ; tag
.text:00402454                 push    2               ; cmd
.text:00402456                 call    Send
```

So, the string is located at **0x00412EF0+0x118** which is resource **0xbb02**

```x86asm
.data:00413008 BB02            db 44h dup(?)           ; DATA XREF: GetResources+B6↑o
```

```py
bb02 = bytearray("020f0674311f64230178163c340f282e50".decode("hex"), 'ascii')
for i in xrange(len(bb02)):
    bb02[i] ^= ord('PIPE'[i & 3])
    bb02[i] += i&1

print bb02.decode("base64")
```

which outputs `Devin Castle`. So, `Devin Castle` is the **first password**

## The Protocol

```no-highlight
               +-----------------+    Fetch Resource         +-------------------------+
               |                 +-------------------------> |        Thread2          |
               |   GUI Thread    |                           |  (EsetCrackme2015.exe)  |
               |                 |Length, Resource Data      |                         |
               |                 |  <------------------------+                         |
               |                 |   Notify Validation       |                         |
               |                 +-------------------------> |                         |
               +-----------------+                           +------------+------------+
                                                                          |
                                                              Command-2   |   Mark Resource
                                                                          |   Set last resource to id
                                                                          v
                    +-------------------+                    +------------+------------+
                    |                   |                    |                         |
           TRUE     |  0xbb01, 0xbb02,  |                    |        Thread1          |
        +-----------+  0xbb03, 0xff01   |   call [edi+0x406] |    (Event Signaled)     |
        |           |      marked?      +<-------------------+                         |
        |           |                   |                    +-------------------------+
        |           +---------+---------+
        |                     |
        v               FALSE |         +-----------------+               +------------------+
+-------+---------+           |         |                 |   TRUE        |                  |
|                 |           +-------->+  Last Resource  +-------------->+ Extract drv.zip  |
|    Congrats!    |                     |     0xbb01?     |               |                  |
|                 |                     |                 |               +------------------+
+-----------------+                     +--------+--------+
                                                 |
                                                 | FALSE
                                                 |
                                                 v
                                        +--------+--------+               +--------------------------+
             +----------+     FALSE     |                 |               |                          |
             |  RETURN  | <-------------+  Last Resource  |   TRUE        |  Extract -               |
             +----------+               |     0xaa10?     +-------------> |                          |
                                        |                 |               |  1. PunchCardReader      |
                                        +-----------------+               |  2. PuncherMachine       |
                                                                          |  3. PunchCard.bmp        |
                                                                          |                          |
                                                                          +--------------------------+

```

## PuncherMachine

Running DetectItEasy on PuncherMachine.exe it shows that its obfuscated by Obfuscar.
The symbols are renamed and the interesting fact is that the sequence of statements are put into a FSM, i.e. the implicit jump to from the current statement to the next statement is controlled by a FSM.

For example, if the code contains

stmt1;
stmt2;
stmt3;

The obfuscated code will look like

```cs
state = 6
for (;;)
{
    switch (state ^ 5)
    {
        case 1:
            // stmt2;
            state = 2;
            continue;

        case 7:
            // stmt3;
            state = 0;
            continue;

        case 3:
            // stmt1;
            state = 4;
            continue;

        default:
            goto finish;
    }
}

finish:
```

Of course, the constants used for representing states won’t be this small.  
The code first computes the MD5 of all Instance, Public, Static, and NonPublic methods in the assembly. The MD5 generated is **3C C0 21 F8 BC 62 3E C0 F5 45 0C 55 41 8B A1 20**  

The resources **0xFF01**, **0xFF02** are fetched (command 1) and decrypted (AES Algorithm) using the above MD5 as the key. The decrypted contents of **0xFF02** is **"95eceaa118dd081119e26be1c44da2cb"**, a MD5 hash.  

The program prompts for selecting an image. Once the image is selected, it calculates its MD5 hash and matches with the decrypted MD5 hash (0xFF02). If the hashes mismatch, the program displays “Calibration Error”. Otherwise, it fetches the resources **0xFF04** and **0xFF00** and decrypts them using the same key.  

The resource **0xFF04** is a **.NET DLL** file. It contains two classes - `DynMethod.DynMethodFactory` and `IlEmitHelp.ILEmitParticle`. The resource 0xFF00 contains **86 64-bit** integers.  

Now two textboxes appear with a button "Calibrate It". Here is the Deobfuscated algorithm  

```cs
List<char> lstChars = new List<char>();
List<int> lstInts = new List<int>();
Hashtable H;
delegate ulong HashIt(string);

Button.Click
{
    if (validate(text1.Text, text2.Text))
    {
        // good jump
    }
    else
    {
        MessageBox.Show("Calibration Error!", "Error");
    }
}


/*
 * lstChars and lstInts are initialized when the MD5 of the image is validated
 */
void Init()
{
    string temp = "0123456789ABCDEFGHIJKLMNOPQR/STUVWXYZabcdefghijklmnopqrstuvwxyz:#@\\\".<(+|$*);,%_>? -&";
    for(int i = 0; i < temp.Length; ++i)
        lstChars.Add(temp[i]);

    int[] arr = new int[] {
        0x200, 0x100, 0x80, 0x40, 0x20, 0x10, 8, 4, 2,
        1, 0x900, 0x880, 0x840, 0x820, 0x810, 0x808, 0x804,
        0x802, 0x801, 0x500, 0x480, 0x440, 0x420, 0x410,
        0x408, 0x404, 0x402, 0x401, 0x300, 0x280, 0x240,
        0x220, 0x210, 0x208, 0x204, 0x202, 0x201, 0xB00,
        0xA80, 0xA40, 0xA20, 0xA10, 0xA08, 0xA04, 0xA02,
        0xA01, 0xD00, 0xC80, 0xC40, 0xC20, 0xC10, 0xC08,
        0xC04, 0xC02, 0xC01, 0x680, 0x640, 0x620, 0x610,
        0x608, 0x604, 0x602, 0x601, 0x82, 0x42, 0x22, 0x12,
        0xA, 6, 0x842, 0x812, 0x80A, 0x806, 0x442, 0x422,
        0x412, 0x40A, 0x242, 0x222, 0x212, 0x20A, 0x206, 0, 0x400, 0x800
    };

    for (int i = 0; i < arr.Length; ++i)
        lstInts.Add(arr[i]);
}

bool validate(string str1, string str2)
{
    List<uint> iList = new List<uint>();
    for (int i = 0; i < str1.Length; i += 8)
    {
        iList.Add(Convert.ToInt32(str1.Substring(i, 8), 16));
    }
    if (str2.Length > lstChars.Count)
    {
        return false;
    }
    
    HashIt computeHash = GetMethod(iList.toArray());
    InitHashtable();
    Hashtable A = new Hashtable();

    for (int i = 0; i < lstChars.Count; ++i)
    {
        ulong hash = computeHash(i < str2.Length ? lstChars[i]+str2[i] : lstChars[i]);
        if (! H.containsKey(hash))
        {
            return false;
        }
        A.Add(lstChars[i], H[hash]);
    }

    return true;
}

HashIt GetMethod(List<uint> lst)
{
    MethodInfo methInfo = typeof(DynMethod.DynMethodFactory).GetMethod("createMethod");
    DynamicMethod dynMeth = methInfo.Invoke(null, new object[] { lst });
    return dynMeth.CreateDelegate(typeof(HashIt));
}

void InitHashtable()
{
    H = new Hashtable();
    byte[] data = GetDecryptedResource(0xFF00);
    for (int i = 0; i < lstChars.Count; ++i)
    {
        H.Add(BitConverter.ToUInt64(data, i*8), lstInts[i]);
    }
}
```

Now in `DynMethodFactory.CreateMethod`, we have

For all opcodes except **break**, a hashtable is created whose key consists of the hash and the corresponding value is an `OpCodes` instance. Here is the algorithm that maps an opcode to its hash

```c
unsigned hash(char* name)
{
    unsigned ans = 0;
    for (int i = 0; name[i]; ++i)
    {
        ans += name[i];
        ans += ans << 10;
        ans ^= ans >> 6;
    }
    ans += ans << 3;
    ans ^= ans >> 11;
    return ans + (ans << 15);
}
```

Now the createMethod takes an array of unsigned ints and produces the following code. Let’s name the array **arr** and the hashtable as **table**

```no-highlight
    nop
    ldc.i8 0x2AAAAAAAAAAAAB67      ; int1
    stloc.0
    ldc.i4.0
    stloc.1
    br.s L0
L1:
    nop
    ldloc.0
    table[arr[0]]
    ldloc.1
    callvirt [string!get_Chars]
    conv.u8
    add
    stloc.0
    ldloc.0
    ldc.i8 0x2AAAAAAAAAAAAB6F      ; int2
    table[arr[1]]
    stloc.0
    nop
    ldloc.1
    ldc.i4.1
    add
    stloc.1
L0:
    ldloc.1
    ldarg.0
    callvirt [string!get_Length]
    clt
    stloc.3
    ldloc.3
    brtrue.s L1
```

`get_Chars` takes two parameters - string, offset and returns the character at the given offset. Clearly, **arr[0]** must be the hash of the instruction **ldarg.0** as the first parameter must be a string.  

The hashtable H's keys are the contents of the decrypted resource 0xFF00. And each key is an unsigned int64. Notice that the integers labelled int1 and int2 differ by 8. So the candidate choices for arr[1] are **ADD**, **MUL**, **OR**. We cannot use _SUB_, _XOR_, _DIV_ as the resulting value would decrease to less than 64 bits and no unary operators can be used as there are two uint64 operands on the stack.  

To get the string str2 in validate routine, I have used bruteforce. Here's my code  

```cs
// run.cs
using System;
using System.IO;
using System.Reflection;
using System.Reflection.Emit;

public class CalibrationCode
{
    delegate bool HashChecker(ulong hash);
    delegate ulong Hash(string s);
    static void Main()
    {
        OpCode[] candidates = {
            OpCodes.Add, OpCodes.Mul, OpCodes.Or
        };
        var hashes = new ulong[86];
        var set =  "0123456789ABCDEFGHIJKLMNOPQR/STUVWXYZabcdefghijklmnopqrstuvwxyz:#@\\\".<(+|$*);,%_>? -&";

        using (var fS = new FileStream("FF00.bin_dec.bin",
            FileMode.Open, FileAccess.Read))
        {
            using (var binR = new BinaryReader(fS))
            {
                for (int i = 0; i < 86; ++i)
                    hashes[i] = binR.ReadUInt64();
            }
        }

        HashChecker isHashPresent = (hash) => {
            for (int i = 0; i < 86; ++i)
                if (hashes[i] == hash)
                    return true;
            return false;
        };

        var charAt = typeof(string).GetMethod("get_Chars");
        var len = typeof(string).GetMethod("get_Length");

        foreach (var op in candidates)
        {
            DynamicMethod dynMeth = new DynamicMethod("Hash",
                typeof(ulong), new Type[] { typeof(string) });
            var ilGen = dynMeth.GetILGenerator();

            ilGen.DeclareLocal(typeof(ulong), true);
            ilGen.DeclareLocal(typeof(int), true);
            ilGen.DeclareLocal(typeof(int), true);
            ilGen.Emit(OpCodes.Ldarg_0);
            ilGen.Emit(OpCodes.Call, len);
            ilGen.Emit(OpCodes.Stloc_2);
            ilGen.Emit(OpCodes.Ldc_I8, 3074457345618258791L);
            ilGen.Emit(OpCodes.Stloc_0);
            ilGen.Emit(OpCodes.Ldc_I4_0);
            ilGen.Emit(OpCodes.Stloc_1);
            Label l0 = ilGen.DefineLabel();
            Label l1 = ilGen.DefineLabel();
            ilGen.Emit(OpCodes.Br_S, l0);
            ilGen.MarkLabel(l1);
            ilGen.Emit(OpCodes.Ldarg_0);
            ilGen.Emit(OpCodes.Ldloc_1);
            ilGen.Emit(OpCodes.Call, charAt);
            ilGen.Emit(OpCodes.Conv_I8);
            ilGen.Emit(OpCodes.Ldloc_0);
            ilGen.Emit(OpCodes.Add);
            ilGen.Emit(OpCodes.Ldc_I8, 3074457345618258799L);
            ilGen.Emit(op);
            ilGen.Emit(OpCodes.Stloc_0);
            ilGen.Emit(OpCodes.Ldloc_1);
            ilGen.Emit(OpCodes.Ldc_I4_1);
            ilGen.Emit(OpCodes.Add);
            ilGen.Emit(OpCodes.Stloc_1);
            ilGen.MarkLabel(l0);
            ilGen.Emit(OpCodes.Ldloc_1);
            ilGen.Emit(OpCodes.Ldloc_2);
            ilGen.Emit(OpCodes.Blt_S, l1);
            ilGen.Emit(OpCodes.Ldloc_0);
            ilGen.Emit(OpCodes.Ret);

            Hash hashIt = (Hash) dynMeth.CreateDelegate(typeof(Hash));
            // check it now.
            string code = "";

            for (int i = 0; i < set.Length; ++i)
            {
                for (int j = 0; j < set.Length; ++j)
                {
                    string str = string.Format("{0}{1}", set[i], set[j]);
                    if (isHashPresent(hashIt(str)))
                        code += set[j];
                }
            }

            Console.WriteLine("[+] Using {0} => {1}", op.Name, code);
        }
    }
}
```

Which gives the output

```sh
tr1n1ty@tr1n1ty /cygdrive/c/Users/tr1n1ty/Desktop/ESET/crackme
$ ./run
[+] Using add =>
[+] Using mul => Infant Jesus of Prague
[+] Using or =>
```

So, the value of str2 in validate routine is `Infant Jesus of Prague` which is the third password. For str1, we need the hash values of **LDARG.0** and **MUL**  
Executing `hash()` and concatenating, we get str1 - **0364ABE72D29C96C**  

The program now sends MarkCommand (2) for the resource 0xFF00 to the EsetCrackmePipe. Command2 means mark the resource in the marked array.  

Now a multiline textbox appears and a button labelled 'Punch it!'. For each line in the multiline textbox, it encodes that line into an image and saves it with the name 'punch_card_X.bmp' where X is the index of the line.  

## PunchCardReader

The program first computes the MD5 of its assembly - **a26d11dee294284f38db8a724c119d74**. Then in Form_Load event, it fetches the resource **0xFF05** (command 1) and decrypts (AES) using the MD5 as the key.

The resource 0xFF05 is another **.NET DLL**. In the click event of the "Read punch cards" button, the program first decodes the images ("punch_card_X.bmp") generated by PuncherMachine. It then invokes the method returned by `DynMethod.createMethod`, using the decoded strings as arguments.  

In createMethod, a hashtable is created with keys as IL opcode names, with the corresponding IL opcode instances. And a dynamic method is returned which contains

```no-highlight
.local uint
.local uint
.local uint
.local uint
.local uint
.local uint
.local byte[]
.local uint
.local bool
.local bool

nop
ldc.i4 57005
stloc.0
ldc.i4 48879
stloc.1
ldc.i4 51966
stloc.2
ldc.i4 47806
stloc.3
ldc.i4 64206
stloc.s 4

ldloc.0
ldloc.1
OPCODE[instr[0]]                    ; t0 = i[0](57005, 48879)
ldloc.2
ldloc.3
OPCODE[instr[1]]                    ; t1 = i[1](51966, 47806)
xor
ldloc.s 4
xor
ldc.i4 -229612108
xor
stloc.s 5                           ; t0 ^ t1 ^ 64206 ^ -229612108

call Encoding.ASCII
ldstr "ESET"
callvirt GetBytes
stloc.s 6

ldloc.s 6
ldc.i4.0
call BitConverter.ToUInt32
stloc.s 7                           ; 0x54455345

ldloc.s 5
ldloc.s 7
ceq
ldc.i4.0
ceq
stloc.s 9
ldloc.s 9
brtrue.s L0
ldc.i4.1
stloc.s 8
br.s L1

L0:
    ldc.i4.0
    stloc.s 8
    br.s L1

L1:
    ldloc.s 8
    OPCODE[instr[2]]
```


So, two things are clear now. First the number of instructions is 3, i.e., we have to enter three lines in the PuncherMachine. Secondly, the last instruction (instr[2]) has to be **ret**

Now, the task is, find operators O1 and O2 such that the following holds

```no-highlight
O1(57005, 48879) ^ O2(51966, 47806) ^ 64206 ^ -229612108 == ‘ESET’[::-1].encode(‘hex’)

i.e., O1(57005, 48879) ^ O2(51966, 47806) ^ 64206 ^ -229612108 == 0x54455345
  =>  O1(57005, 48879) ^ O2(51966, 47806) == 64206 ^ -229612108 ^ 0x54455345
  =>  O1(57005, 48879) ^ O2(51966, 47806) == 0xa615cc3f
```

```cs
using System;
using System.Reflection;
using System.Reflection.Emit;

public class FindInstructions
{
    delegate bool Solver();

    static void Main()
    {
        OpCode[] candidates = {
            OpCodes.Add, OpCodes.Mul, OpCodes.Or, OpCodes.Xor
        };
        foreach (var op1 in candidates)
        {
            foreach (var op2 in candidates)
            {
                var methSolve = new DynamicMethod("Solver", typeof(bool), new Type[0]);
                var ilGen = methSolve.GetILGenerator();
                ilGen.Emit(OpCodes.Ldc_I4, 57005);
                ilGen.Emit(OpCodes.Ldc_I4, 48879);
                ilGen.Emit(op1);
                ilGen.Emit(OpCodes.Ldc_I4, 51966);
                ilGen.Emit(OpCodes.Ldc_I4, 47806);
                ilGen.Emit(op2);
                ilGen.Emit(OpCodes.Xor);
                ilGen.Emit(OpCodes.Ldc_I4, 0xa615cc3f);
                ilGen.Emit(OpCodes.Ceq);
                ilGen.Emit(OpCodes.Ret);
                Solver solve = (Solver) methSolve.CreateDelegate(typeof(Solver));
                if (solve())
                {
                    Console.WriteLine(
                        "First OpCode - {0}\nSecond OpCode - {1}",
                        op1.Name, op2.Name
                    );
                }
            }
        }
    }
}
```

Executing it, we get the first opcode - **mul** and the second opcode - **add**  

So, the first and second instructions are MUL, and ADD. Now we have to enter the strings - **MUL**, **ADD**, **RET** into the PuncherMachine to get three punch cards.

Now PunchCardReader sends command 2 (Mark Resource) for resource 0xFF01, and displays a message dialog "Verification passed ...""

Now that we have marked resources 0xBB01 and 0xFF01, we still have resources 0xBB02 and 0xBB03 left to be marked.

Decoding resource 0xBB01 by xoring with the key "PIPE", we get three hashes.  
If the hash of the second password matches **0F30181CF3A9857360A313DB95D5A169BED7CC37** and that of the third password matches **0B6A1C6651D1EB5BD21DF5921261697AA1593B7E**, the resources 0xBB02 and 0xBB03 get marked.  

Till now I’ve used a bitmap 600x259 consisting of a white background and bypassing `IEnumerable.SequenceEquals` for PuncherMachine, forcing it to return true while validating the image.

The only way to send a mark resource message for resources 0xBB02 and 0xBB03 is by matching the respective hashes. Finding by brute force is unacceptable.

So, the passwords must be encoded in the program itself. The crackme driver decodes the resources **0xAA02**, **0xAA06** using **RC4**, the key is **3531_4ever**

The driver creates a device **\Device\45736574** i.e., `"Eset".encode("hex")` and the main executable on receiving 0xAA10 mark command, extracts the resource **0x155** with name "PunchCard.bmp" into the path **\\?\GLOBALROOT\Device\45736574\PunchCard.bmp**  

## The Driver

The AddDevice routine of the driver extension sets up a FAT disk. In LoadFatEntries, it queries the FAT params like "Parameters", "DiskSize", etc. from the Registry otherwise sets up with default values. Default Disk size is 0x1E00000 bytes or 30MB. RootDirectoryEntries is set to 0x200 and 2 sectors per cluster. It then spawns two threads.  

The first thread sends a fetch command for resource 0xaa02 (**ESETConst**), decrypts it with rc4 key **3531_4ever** and spawns a new thread which reads the value of "ESETConst" registry key and stores in a global variable str (at end of data section)  

Thread2 initializes another virtual machine

```x86asm
.text:9C6B5329                 call    ds:ExAllocatePool
.text:9C6B532F                 mov     ecx, [ebp+var_14]
.text:9C6B5332                 mov     [ecx+64h], eax
.text:9C6B5335                 mov     edx, [ebp+var_14]
.text:9C6B5338                 mov     dword ptr [edx+68h], 21ACh
.text:9C6B533F                 push    21ACh           ; MaxCount
.text:9C6B5344                 push    offset vm_code  ; Src
.text:9C6B5349                 mov     eax, [ebp+var_14]
.text:9C6B534C                 mov     ecx, [eax+64h]
.text:9C6B534F                 push    ecx             ; Dst
.text:9C6B5350                 call    memcpy
.text:9C6B5355                 add     esp, 0Ch
.text:9C6B5358                 push    21ACh           ; size
.text:9C6B535D                 mov     edx, [ebp+var_14]
.text:9C6B5360                 mov     eax, [edx+64h]
.text:9C6B5363                 push    eax             ; buf
.text:9C6B5364                 call    RC4Decrypt
.text:9C6B5369                 push    2B5h            ; NumberOfBytes
.text:9C6B536E                 push    0               ; PoolType
.text:9C6B5370                 call    ds:ExAllocatePool
.text:9C6B5376                 mov     ecx, [ebp+var_14]
.text:9C6B5379                 mov     [ecx+70h], eax
.text:9C6B537C                 mov     edx, [ebp+var_14]
.text:9C6B537F                 mov     dword ptr [edx+74h], 2B5h
.text:9C6B5386                 push    2B5h            ; MaxCount
.text:9C6B538B                 push    offset code_to_exec ; Src
.text:9C6B5390                 mov     eax, [ebp+var_14]
.text:9C6B5393                 mov     ecx, [eax+70h]
.text:9C6B5396                 push    ecx             ; Dst
.text:9C6B5397                 call    memcpy
.text:9C6B539C                 add     esp, 0Ch
.text:9C6B539F                 push    2B5h            ; size
.text:9C6B53A4                 mov     edx, [ebp+var_14]
.text:9C6B53A7                 mov     eax, [edx+70h]
.text:9C6B53AA                 push    eax             ; buf
.text:9C6B53AB                 call    RC4Decrypt
```


So, it sets up offset +0x64 with the VM and +0x70 with the code to execute on the vm. It then fetches resource 0xaa06 which seems to be some patch to the code to execute. After decrypting 0xaa06 (rc4)  

```x86asm
.text:9C6B561E                 mov     eax, [ebp+Length]
.text:9C6B5621                 push    eax             ; MaxCount
.text:9C6B5622                 mov     ecx, [ebp+P]
.text:9C6B5625                 push    ecx             ; Src
.text:9C6B5626                 mov     edx, [ebp+var_14]
.text:9C6B5629                 mov     eax, [edx+70h]
.text:9C6B562C                 add     eax, 26Dh
.text:9C6B5631                 push    eax             ; Dst
.text:9C6B5632                 call    memcpy
```

The patched code is placed at +0x26d wrt the code to execute. Here’s the script that saves the patched code

```py
#!/usr/bin/env python

from Crypto.Cipher import ARC4

key = '3531_4ever'
d = open("0xaa06.bin", "rb").read()
d = ARC4.new(key).decrypt(d)

code = '''CAE23DEDCDE3016FB7080893AA91A5E3F599D4A36E81E7013512F4D971C64AF57B4428D746C58D05256B06684CB6CE8BDCDB85C77C1FC782C06150714B5C1AD028067029AC959DDEA4BF3F1210EAFA3100CC38BC08D90E933537D8683CD5707544A2D586B3257F7CDBE684B3F65F564A0F699A4C0F0C548D6352FF91DE8A13BFB8E13BDFBFDD3483CB3E93F7549251163DE2FDD7071D63D25EB771AB97B2DA722506805CE813D4E6066970E6E02C2C1823C4A58F2AB2641B87F784D84A7CF5B65B912EC8E5E10A1E5D5C52E382DF2BEB32CC673F6D6843D39615DBEC15095C5FDD20375678DFD28589FD01A92F3E47DCFABE014BC07C336D4A69489E07902A6E4CE44B760705FB531FECC745FCE1EC247A1698D8B186CCF36AF58FA01A1A4EE61926488B72B26B3EDF0B578CB25EE9359B99113A62FD17B03410A84D67239D157E01886B1168C10D064B909ACBFB123776E2F80E6C366BD63CC8EE86DCD754BF023FA2CD7ACD6C4A56643A26D1A29128518C9866EF0EBDF6407653A475A5DB1544CEFCFC33EE441A565975CA1CEC192B0D2A35B07FD68A0D12CBAA45F01490948464D15326F03C489F3D65B0E7F9A103236356CBAE883B0C4CD5348B80B08344CC61CA3E3DB4E1D49D7EA16BAC68E5AAD801AAF7B752A75B18BE07989BEA79D832F435F08B25AD387A8B893470CD0FD7748B5C3D13C63A5BF05DC484836BE4516D8D0D162E184311894E12E5A7BDAA8AFE219DFF6CE97621D9FDCF3B3E388A354BADB6231787E081AAF0FE26EA4AACCF1F5EF7632B4A33104B2C593014C639F71735179FDD5899394FA9D69BC217E578E961DE0769DB942855E1E2FDB608ADE61D30D7750F2CA67E839006372B71250DE6052293E108D6C62A884096513541464CDC38C2EBEE985AF75B6E211BA8CE4AEC8C2EC6FF5C7FD86EA27C65191A5E10CC179220622AD66AB656E4E020552DC14B8F544EB0'''
code = code.decode('hex')
code = ARC4.new(key).decrypt(code)
code = list(code)
for i in xrange(len(d)):
    code[0x26d+i] = d[i]

open("code.bin", 'wb').write(''.join(code))
```

![i0](/images/eset/i0.png)

It seems like the size of the VM (0x2b5) is placed at offset +0x2. Here’s the Driver VM layout  

```c
struct res_t
{
    char sign[2];
    int size;
    int code_off;
    int data_off;
    int bModuleLoaded;
    char stream[];
} __attribute__((packed));
```

```no-highlight
00    ldr X, 0
      cmp.eq X, R12
04    ldr X, 0x8a
      jmp.cc X
0a    ldr X, 0
      cmp.eq X, R13
0e    ldr X, 0x11e
      jmp.cc X
14    ldr X, R12
      str X, R2
17    ldr X, &[0x295]
      str X, R3
1e    ldr X, &[0x268]
      str X, R4
25    ldr X, R2
      str X, R5
28    ldr X, R13
      add R5, X
2b    ldr X, R3
      str X, R14
2e    ldr X, &[0x291]
      str X, R0
35    ldr X, dword ptr [R0]
      add R14, X
38    ldr X, R4
      str X, R15
3b    ldr X, 0x4
      add R15, X
3f    ldr X, R5
      cmp.neq X, R2
42    ldr X, 0x4b
      jmp.cc X
48    ldr X, R12
      str X, R2
4b    ldr X, R15
      cmp.neq X, R4
4e    ldr X, 0x5b
      jmp.cc X
54    ldr X, &[0x268]
      str X, R4
5b    ldr X, R14
      cmp.eq X, R3
5e    ldr X, 0x100
      jmp.cc X
64    ldr X, byte ptr [R2]
      str X, R0
67    ldr X, byte ptr [R3]
      xor R0, X
6a    ldr X, 0x1
      add R0, X
6e    ldr X, 0x1
      rolb R0, X
72    ldr X, byte ptr [R4]
      xor R0, X
75    ldr X, R0
      str X, byte ptr [R3]
78    ldr X, 0x1
      add R2, X
7c    ldr X, 0x1
      add R3, X
80    ldr X, 0x1
      add R4, X
84    ldr X, 0x3f
      jmp X
8a    ldr X, &[0x271]
      str X, R3
91    ldr X, &[0x268]
      str X, R4
98    ldr X, R3
      str X, R14
9b    ldr X, &[0x26d]
      str X, R0
a2    ldr X, dword ptr [R0]
      add R14, X
a5    ldr X, R4
      str X, R15
a8    ldr X, 0x4
      add R15, X
ac    ldr X, R15
      cmp.neq X, R4
af    ldr X, 0xbc
      jmp.cc X
b5    ldr X, &[0x268]
      str X, R4
bc    ldr X, R14
      cmp.eq X, R3
bf    ldr X, 0xe8
      jmp.cc X
c5    ldr X, 0
      str X, R0
c9    ldr X, byte ptr [R3]
      xor R0, X
cc    ldr X, 0x1
      add R0, X
d0    ldr X, 0x1
      rolb R0, X
d4    ldr X, byte ptr [R4]
      xor R0, X
d7    ldr X, R0
      str X, byte ptr [R3]
da    ldr X, 0x1
      add R3, X
de    ldr X, 0x1
      add R4, X
e2    ldr X, 0xac
      jmp X
e8    ldr X, &[0x26d]
      str X, R0
ef    ldr X, dword ptr [R0]
      str X, R0
f2    ldr X, R0
      push X
f4    ldr X, &[0x271]
      push X
fa    ldr X, 0x112
      jmp X
100    ldr X, &[0x291]
      str X, R0
107    ldr X, dword ptr [R0]
      str X, R0
10a    ldr X, R0
      push X
10c    ldr X, &[0x295]
      push X
112    ldr X, R11
      push X
114    ldr X, R10
      push X
116    emulate
11e    hlt
```

The arguments are - R12 contains str (the global variable containing "ESETConst" value), R13 contains len(str). The notation **&[X]** defines the **address of offset X**

So, if nothing is passed to "ESETConst", the control jumps to **0x8a**. This loop decrypts a 0x12 byte key  

```py
l = [0x82, 0x99, 0x8f, 0x92, 0x11, 0x9e, 0x18, 0x94, 0xb1, 0x8e, 0x8f, 0x11, 0x16, 0x9c, 0x11, 0x1a, 0x16, 0x9d, 0xa8]

def rol(x):
    return (x << 1 | x >> 7) & 0xff

k = 'ETSE'
for i in xrange(len(l)):
    t = rol(l[i]+1)
    l[i] = chr(ord(k[i&3])^t)

print ''.join(l)
```

It prints out `Barbakan Krakowski` which is the second password!

> Solved Finally!
