---
title: "InCTF 2018 - Decoy"
date: 2018-10-11 10:30:00
tags: [reversing, inctf]
categories: [reversing, inctf]
---

<!--more-->
![Image0](/images/inctf18_decoy.png)

It's a beautiful challenge. But there is an interesting thing about this challenge.
The author has tried to make a binary tree out of the basic blocks.

![Image1](/images/inctf18_decoy_0.png)

Let's get started ...

```x86asm
.text:00403411          call    sub_4017DE
.text:00403416          mov     [esp+70h+var_4], eax
.text:0040341A          cmp     [esp+70h+var_4], 4
.text:0040341F          jz      loc_403957
.text:00403425          mov     dword ptr [esp], offset aInput ; "\nInput: "
.text:0040342C          call    printf
.text:00403431          mov     eax, ds:_iob
.text:00403436          mov     [esp+8], eax    ; File
.text:0040343A          mov     dword ptr [esp+4], 2Dh ; MaxCount
.text:00403442          lea     eax, [esp+70h+Buf]
.text:00403446          mov     [esp], eax      ; Buf
.text:00403449          call    fgets

.text:00403957 loc_403957:
.text:00403957          mov     dword ptr [esp], offset aInput ; "\nInput: "
.text:0040395E          call    printf
.text:00403963          mov     eax, ds:_iob
.text:00403968          mov     [esp+8], eax    ; File
.text:0040396C          mov     dword ptr [esp+4], 2Dh ; MaxCount
.text:00403974          lea     eax, [esp+70h+Buf]
.text:00403978          mov     [esp], eax      ; Buf
.text:0040397B          call    fgets
.text:00403980          lea     eax, [esp+70h+Buf]
.text:00403984          mov     [esp+70h+input], eax
```

Oh ! Both looks similar. Which one to follow ??? sub\_4017DE knows the answer.

```x86asm
.text:004017E4          mov     [ebp+var_1C], 0BEEFh
.text:004017EB          mov     [ebp+var_20], 0DEADh
.text:004017F2          mov     [ebp+var_24], 0DECh

.text:004017F9          lea     eax, [ebp+var_1C]
.text:004017FC          mov     [ebp+var_10], eax
.text:004017FF          lea     eax, [ebp+var_20]
.text:00401802          mov     [ebp+var_14], eax
.text:00401805          lea     eax, [ebp+var_24]
.text:00401808          mov     [ebp+var_18], eax
.text:0040180B          mov     eax, [ebp+var_18]

.text:0040180E          mov     [esp+8], eax
.text:00401812          mov     eax, [ebp+var_14]
.text:00401815          mov     [esp+4], eax
.text:00401819          mov     eax, [ebp+var_10]
.text:0040181C          mov     [esp], eax
.text:0040181F          call    sub_401723
```

Nothing much to explain here. Let's move on

```x86asm
.text:00401704          push    ebp
.text:00401705          mov     ebp, esp
.text:00401707          sub     esp, 8
.text:0040170A          mov     eax, ds:IsDebuggerPresent
.text:0040170F          call    eax ; IsDebuggerPresent
.text:00401711          test    eax, eax
.text:00401713          jz      short good_boy
.text:00401715          mov     eax, 0Dh
.text:0040171A          jmp     short locret_401721
.text:0040171C good_boy:
.text:0040171C          mov     eax, 0Eh
.text:00401721
.text:00401721 locret_401721:
.text:00401721          leave
.text:00401722          retn
```

So, we want sub\_401704 to return 0xE

```x86asm
.text:00401729          call    sub_401704
.text:0040172E          mov     [ebp+debugger], eax
.text:00401731          mov     [ebp+var_10], 0Bh
.text:00401738          cmp     [ebp+debugger], 0Ah
.text:0040173C          jle     short loc_40178E
```

There was no necessary for if else here. Well, its contributing to the binary tree :-)

```x86asm
.text:0040173E          mov     eax, [ebp+arg_0]     ; addr of 1st int
.text:00401741          mov     edx, [eax]
.text:00401743          mov     eax, [ebp+arg_4]     ; addr of 2nd int
.text:00401746          mov     eax, [eax]
.text:00401748          add     edx, eax
.text:0040174A          mov     eax, [ebp+arg_8]     ; addr of 3rd int
.text:0040174D          mov     eax, [eax]
.text:0040174F          add     edx, eax
.text:00401751          mov     eax, [ebp+debugger]
.text:00401754          add     eax, edx
.text:00401756          mov     [ebp+var_10], eax
.text:00401759          sub     [ebp+var_10], 24F6h
.text:00401760          mov     ecx, [ebp+var_10]
.text:00401763          mov     edx, 21195767h
.text:00401768          mov     eax, ecx
.text:0040176A          imul    edx
.text:0040176C          sar     edx, 7
.text:0040176F          mov     eax, ecx
.text:00401771          sar     eax, 1Fh
.text:00401774          sub     edx, eax
.text:00401776          mov     eax, edx
.text:00401778          imul    eax, 990     ; 1 + (2**39 / 0x21195767)
.text:0040177E          sub     ecx, eax     ; mod 990
.text:00401780          mov     eax, ecx
.text:00401782          mov     [ebp+var_10], eax
.text:00401785          add     [ebp+var_10], 4
.text:00401789          mov     eax, [ebp+var_10]
```

This code returns
```
    (var_1C+var_20+var_24+debugger-0x24f6) % 990 + 4
```

```x86asm
.text:00401824          mov     [ebp+var_C], eax
.text:00401827          mov     eax, [ebp+var_1C]
.text:0040182A          cmp     eax, 2710h
.text:0040182F          jle     short loc_401867     ; false
.text:00401831          mov     eax, [ebp+var_20]
.text:00401834          cmp     eax, 0C350h
.text:00401839          jle     short loc_401851     ; false
.text:0040183B          mov     eax, [ebp+var_24]
.text:0040183E          cmp     eax, 7A120h
.text:00401843          jle     short loc_40184B     ; true

.text:0040184B loc_40184B:
.text:0040184B          sub     [ebp+var_C], 0Ah
.text:0040184F          jmp     short loc_40189B
```

The first two conditions are false as the variables are not modified by sub\_401723.
To sum up sub\_4017DE, it returns

```bash
echo $(( (0xbeef+0xdead+0xdec+0xe-0x24f6) % 990 + 4 - 10)) # => 4
```

Lets now go back to main. Recall that

```x86asm
.text:00403416          mov     [esp+70h+var_4], eax
.text:0040341A          cmp     [esp+70h+var_4], 4
.text:0040341F          jz      loc_403957          ; true :-)
```

Scroll up a bit and you can see the some lines in the listing of loc\_403957. It first reads a string of length atmost 0x2d into Buf.

```x86asm
.text:00403990          lea     eax, [esp+70h+Buf]
.text:00403994          mov     [esp], eax      ; char *
.text:00403997          call    length
.text:0040399C          mov     [esp+70h+var_20], eax
.text:004039A0          cmp     [esp+70h+var_20], 22
.text:004039A5          jle     badBoy

.text:004039AB          mov     eax, [esp+70h+input]
.text:004039AF          add     eax, 0Bh
.text:004039B2          mov     [esp], eax
.text:004039B5          call    sub_4018D9
.text:004039BA          mov     [esp+70h+var_C], eax
.text:004039BE          cmp     [esp+70h+var_C], 0Bh
.text:004039C3          jnz     loc_403C4F
```

The length of the input must be atleast 23 characters. Let's take a look at sub\_4018D9

```x86asm
.text:00401904 loc_401904:
.text:00401904          mov     edx, [ebp+var_4]
.text:00401907          mov     eax, [ebp+arg_0]    ; input+11
.text:0040190A          add     eax, edx
.text:0040190C          movzx   eax, byte ptr [eax]
.text:0040190F          xor     eax, 11
.text:00401912          mov     ecx, eax
.text:00401914          lea     edx, [ebp+var_1C]
.text:00401917          mov     eax, [ebp+var_4]
.text:0040191A          add     eax, edx
.text:0040191C          mov     [eax], cl   ; var_1C[var_4] = input[11+var_4]^11
.text:0040191E          add     [ebp+var_4], 1
.text:00401922
.text:00401922 loc_401922:
.text:00401922          cmp     [ebp+var_4], 0Ah
.text:00401926          jle     short loc_401904

.text:00401931 loc_401931:
.text:00401931          lea     edx, [ebp+var_1C]
.text:00401934          mov     eax, [ebp+var_4]
.text:00401937          add     eax, edx
.text:00401939          movzx   eax, byte ptr [eax]
.text:0040193C          xor     eax, 19
.text:0040193F          mov     ecx, eax
.text:00401941          lea     edx, [ebp+var_1C]
.text:00401944          mov     eax, [ebp+var_4]
.text:00401947          add     eax, edx
.text:00401949          mov     [eax], cl           ; var_1C[var_4] ^= 19
.text:0040194B          add     [ebp+var_4], 1
.text:0040194F
.text:0040194F loc_40194F:
.text:0040194F          cmp     [ebp+var_4], 0Ah
.text:00401953          jle     short loc_401931

.text:0040195E loc_40195E:
.text:0040195E          mov     eax, [ebp+var_8]
.text:00401961          add     eax, offset aFWlgL ; "#f}wLG{ L} "
.text:00401966          movzx   eax, byte ptr [eax]
.text:00401969          xor     eax, 11
.text:0040196C          mov     ecx, eax
.text:0040196E          lea     edx, [ebp+var_28]
.text:00401971          mov     eax, [ebp+var_8]
.text:00401974          add     eax, edx
.text:00401976          mov     [eax], cl   ; var_28[var_8] = aFWlgL[var_8]^11
.text:00401978          add     [ebp+var_8], 1
.text:0040197C
.text:0040197C loc_40197C:
.text:0040197C          cmp     [ebp+var_8], 0Ah
.text:00401980          jle     short loc_40195E

.text:0040198F loc_40198F:
.text:0040198F          lea     edx, [ebp+var_1C]
.text:00401992          mov     eax, [ebp+var_C]
.text:00401995          add     eax, edx
.text:00401997          movzx   edx, byte ptr [eax]
.text:0040199A          lea     ecx, [ebp+var_28]
.text:0040199D          mov     eax, [ebp+var_C]
.text:004019A0          add     eax, ecx
.text:004019A2          movzx   eax, byte ptr [eax]
.text:004019A5          cmp     dl, al      ; var_28[var_C] == var_1C[var_C]
.text:004019A7          jnz     short loc_4019B3
.text:004019A9          add     [ebp+status], 1
.text:004019AD          add     [ebp+var_C], 1
.text:004019B1          jmp     short loc_4019BE
.text:004019B3
.text:004019B3 loc_4019B3:
.text:004019B3          mov     [ebp+status], 0
.text:004019BA          add     [ebp+var_C], 1
.text:004019BE
.text:004019BE loc_4019BE:
.text:004019BE          cmp     [ebp+var_C], 0Ah
.text:004019C2          jle     short loc_40198F
```

At 0x004039BE, we see that the status returned by the above routine must be 11. Now we can find **input[11:]**  

```python
>>> ''.join(map(lambda i: chr(ord(i)^19), "#f}wLG{ L} "))
'0und_Th3_n3'
```

```x86asm
.text:004039C9          mov     eax, [esp+70h+input]
.text:004039CD          mov     [esp], eax
.text:004039D0          call    sub_401AB9
.text:004039D5          mov     [esp+70h+var_10], eax
.text:004039D9          cmp     [esp+70h+var_10], 0Bh
.text:004039DE          jz      loc_403B06
```

Now sub\_401AB9 must return 11 ...

```x86asm
.text:00401AE5 loc_401AE5:
.text:00401AE5          mov     eax, [ebp+var_C]
.text:00401AE8          add     eax, 6
.text:00401AEB          mov     ecx, [ebp+var_8]
.text:00401AEE          mov     edx, [ebp+arg_0]
.text:00401AF1          add     edx, ecx
.text:00401AF3          movzx   edx, byte ptr [edx]
.text:00401AF6          add     edx, 4      ;  var_24[var_C+6] = 4+input[var_8]
.text:00401AF9          mov     [ebp+eax+var_24], dl
.text:00401AFD          mov     eax, [ebp+var_8]
.text:00401B00          lea     edx, [eax+5]
.text:00401B03          mov     eax, [ebp+arg_0]
.text:00401B06          add     eax, edx
.text:00401B08          movzx   eax, byte ptr [eax]
.text:00401B0B          add     eax, 2
.text:00401B0E          mov     ecx, eax
.text:00401B10          lea     edx, [ebp+var_24]
.text:00401B13          mov     eax, [ebp+var_C]
.text:00401B16          add     eax, edx
.text:00401B18          mov     [eax], cl   ; var_24[var_C] = 2+input[var_8+5]
.text:00401B1A          add     [ebp+var_8], 1
.text:00401B1E          add     [ebp+var_C], 1
.text:00401B22
.text:00401B22 loc_401B22:
.text:00401B22          cmp     [ebp+var_8], 0
.text:00401B26          js      short loc_401B2E    ; can never be true
.text:00401B28          cmp     [ebp+var_8], 4
.text:00401B2C          jle     short loc_401AE5

.text:00401B2E          mov     eax, [ebp+arg_0]
.text:00401B31          add     eax, 10
.text:00401B34          movzx   eax, byte ptr [eax]
.text:00401B37          add     eax, 2
.text:00401B3A          mov     [ebp+var_1F], al
```

So, we have

```c
    var_24 = {
        input[5]+2, input[6]+2, input[7]+2, input[8]+2, input[9]+2,
        input[10]+2, /* var_1F */
        input[0]+4, input[1]+4, input[2]+4, input[3]+4, input[4]+4
    }
```

```x86asm
.text:00401B48 loc_401B48:
.text:00401B48          mov     eax, [ebp+var_14]
.text:00401B4B          add     eax, offset a2wahmrgxj ; "}[2waHmrgxj"
.text:00401B50          movzx   ebx, byte ptr [eax]
.text:00401B53          mov     edx, [ebp+var_10]   ; zero
.text:00401B56          mov     eax, [ebp+var_14]
.text:00401B59          lea     ecx, [edx+eax]
.text:00401B5C          mov     edx, 2E8BA2E9h
.text:00401B61          mov     eax, ecx
.text:00401B63          imul    edx
.text:00401B65          sar     edx, 1
.text:00401B67          mov     eax, ecx
.text:00401B69          sar     eax, 1Fh
.text:00401B6C          sub     edx, eax
.text:00401B6E          mov     eax, edx
.text:00401B70          shl     eax, 2
.text:00401B73          add     eax, edx
.text:00401B75          add     eax, eax
.text:00401B77          add     eax, edx
.text:00401B79          sub     ecx, eax    ; 1 + (2**33 / 0x2e8ba2e9)
.text:00401B7B          mov     edx, ecx    ; mod 11
.text:00401B7D          lea     eax, [ebp+var_24]
.text:00401B80          add     eax, edx
.text:00401B82          movzx   eax, byte ptr [eax]
.text:00401B85          cmp     bl, al  ; var_24[var_14 % 11] == a2wahmrgxj[var_14]
.text:00401B87          jnz     short loc_401B8D
.text:00401B89          add     [ebp+status], 1
.text:00401B8D
.text:00401B8D loc_401B8D:
.text:00401B8D          add     [ebp+var_14], 1
.text:00401B91
.text:00401B91 loc_401B91:
.text:00401B91          cmp     [ebp+var_14], 0Ah
.text:00401B95          jle     short loc_401B48
```

Therefore, first 11 characters are

```python
>>> s = "}[2waHmrgxj"
>>> ''.join(map(lambda i: chr(ord(i)-4), s[6:]) + map(lambda i: chr(ord(i)-2), s[:6]))
'inctf{Y0u_F'
```

So, the input string now is **"inctf{Y0u_F0und_Th3_n3"**

```x86asm
.text:00403B06 loc_403B06:
.text:00403B06          call    sub_4018A0      ; 2*IsDebuggerPresent()
.text:00403B0B          mov     [esp+70h+var_8], eax
.text:00403B0F          cmp     [esp+70h+var_8], 0
.text:00403B14          jnz     loc_403BC8

.text:00403B1A          lea     eax, [esp+70h+Buf]
.text:00403B1E          mov     [esp], eax      ; char *
.text:00403B21          call    length
.text:00403B26          mov     [esp+70h+var_20], eax
.text:00403B2A          cmp     [esp+70h+var_20], 44
.text:00403B2F          jnz     bad_boy
.text:00403B35          mov     dword ptr [esp], 0Ah ; Ch
.text:00403B3C          call    putchar
```

The length of the input must be 44. Now we have to find the last 22 characters of the input string.

```x86asm
.text:00403B41          mov     eax, [esp+70h+input]
.text:00403B45          add     eax, 33
.text:00403B48          mov     [esp], eax
.text:00403B4B          call    sub_401E73
.text:00403B50          mov     [esp+70h+var_14], eax
.text:00403B54          cmp     [esp+70h+var_14], 0Bh
.text:00403B59          jnz     short loc_403B90
```

Similar piece of code. It validates the last 11 characters of the input.

```x86asm
.text:00401EBC          mov     edx, [ebp+var_C]
.text:00401EBF          mov     eax, [ebp+arg_0]
.text:00401EC2          add     eax, edx
.text:00401EC4          movzx   eax, byte ptr [eax]     ; copy input[33:]
.text:00401EC7          lea     ecx, [ebp+var_2A]       ; to a local buffer
.text:00401ECA          mov     edx, [ebp+var_C]
.text:00401ECD          add     edx, ecx
.text:00401ECF          mov     [edx], al
.text:00401ED1          add     [ebp+var_C], 1
.text:00401ED5
.text:00401ED5 loc_401ED5:
.text:00401ED5          cmp     [ebp+var_C], 0Ah
.text:00401ED9          jle     short loc_401EBC

.text:00401EE4 loc_401EE4:
.text:00401EE4          lea     edx, [ebp+var_2A]
.text:00401EE7          mov     eax, [ebp+var_C]
.text:00401EEA          add     eax, edx
.text:00401EEC          movzx   eax, byte ptr [eax]
.text:00401EEF          mov     edx, eax
.text:00401EF1          mov     eax, [ebp+var_10]       ; constant = 1
.text:00401EF4          add     eax, edx
.text:00401EF6          mov     ecx, eax
.text:00401EF8          lea     edx, [ebp+var_2A]
.text:00401EFB          mov     eax, [ebp+var_C]
.text:00401EFE          add     eax, edx
.text:00401F00          mov     [eax], cl               ; var_2A[var_C]++
.text:00401F02          add     [ebp+var_C], 1
.text:00401F06 loc_401F06:
.text:00401F06          cmp     [ebp+var_C], 0Ah
.text:00401F0A          jle     short loc_401EE4

.text:00401F0C          mov     dword ptr [esp+8], 0Bh ; MaxCount
.text:00401F14          lea     eax, [ebp+var_2A]
.text:00401F17          mov     [esp+4], eax
.text:00401F1B          lea     eax, [ebp+var_1F]
.text:00401F1E          mov     [esp], eax
.text:00401F21          call    strncmp                 ; var_2A == var_1F
```

Great ! Now we get the last 11 characters :-)

```python
>>> var_1F = "\x7b\x60\x49\x35\x7a\x25\x75\x35\x64\x4c\x7e"
>>> var_1F
'{`I5z%u5dL~'
>>> ''.join(map(lambda i: chr(ord(i)-1), var_1F))
'z_H4y$t4cK}'
```

The string found till now is **"inctf{Y0u_F0und_Th3_n3???????????z_H4y$t4cK}"**  
Now we need to find **input[22:33]**

```x86asm
.text:00403B5B          mov     eax, [esp+70h+input]
.text:00403B5F          add     eax, 22
.text:00403B62          mov     [esp], eax
.text:00403B65          call    sub_4024C3
.text:00403B6A          mov     [esp+70h+var_18], eax
.text:00403B6E          cmp     [esp+70h+var_18], 0Bh
.text:00403B73          jz      short loc_403B7F        ; must be true

[ ... snip ... ]

.text:004024D8          mov     [ebp+var_10], 0Ah
.text:0040256E loc_40256E:
.text:0040256E          mov     eax, [ebp+var_10]
.text:00402571          mov     eax, [ebp+eax*4+var_6C] ; input[22+var_10]
.text:00402575          xor     eax, [ebp+var_8]
.text:00402578          mov     edx, eax
.text:0040257A          mov     eax, [ebp+var_10]
.text:0040257D          mov     [ebp+eax*4+var_6C], edx ; input[22+var_10]^var_8
.text:00402581          mov     eax, [ebp+var_10]
.text:00402584          mov     eax, [ebp+eax*4+var_6C]
.text:00402588          mov     [ebp+var_8], eax
.text:0040258B          mov     eax, [ebp+var_10]
.text:0040258E          mov     edx, [ebp+eax*4+var_6C]
.text:00402592          mov     eax, [ebp+var_10]
.text:00402595          mov     eax, [ebp+eax*4+var_40]
.text:00402599          cmp     edx, eax
.text:0040259B          jnz     short loc_4025A1
.text:0040259D          add     [ebp+status], 1
.text:004025A1
.text:004025A1 loc_4025A1:
.text:004025A1          sub     [ebp+var_10], 1
.text:004025A5
.text:004025A5 loc_4025A5:
.text:004025A5          cmp     [ebp+var_10], 0
.text:004025A9          jns     short loc_40256E
.text:004025AB          mov     eax, [ebp+status]
```

The above code, works like this

```c
int k = 1;
for (int i = 10; i >= 0; --i) {
    k = var_6C[i] ^= k;
    status += var_40[i] == var_6C[i];
}
```

i.e., **var\_6C[i]^var\_6C[i+1] == var\_40[i]**  
or **var\_6C[i] = var\_40[i]^var\_40[i+1]**, i < 10

```python
>>> s = map(ord, "\x6e\x5d\x39\x55\x66\x39\x70\x1e\x41\x15\x7d")
>>> print ''.join(map(lambda (i, j): chr(i^j), zip(s, s[1:]+[1])))
3dl3_In_Th|
```

So, the input string is **"inctf{Y0u_F0und_Th3_n33dl3_In_Th|z_H4y$t4cK}"**, which is also the flag :-)
Finally, the path to the leaf node is

![Image2](/images/inctf18_decoy_1.png)
