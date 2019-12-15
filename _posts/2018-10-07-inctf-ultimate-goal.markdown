---
title: "InCTF 2018 - Ultimate GOal"
date: 2018-10-07 01:35:11
tags: [reversing, inctf, golang]
categories: [reversing, inctf]
---

<!--more-->
![Image0](/images/inctf18_ultimategoal.png)

Its a golang binary. The first task is to find **'main\_main'** routine. Its located at 0x4ebcc0
```x86asm
.text:00000000004EBD15                 lea     rax, off_53B6E8
.text:00000000004EBD1C                 mov     [rsp+198h+var_190], rax
.text:00000000004EBD21                 call    runtime_deferproc

.rodata:000000000053B6E8 off_53B6E8    dq      offset main_final
.rodata:000000000053B6F0 off_53B6F0    dq      offset main_handleit
```

Okay, so we have a deferred call to **'main\_final'**. It prints 'Enter pass:' and calls Reader\_Read to read a string which is converted to a byte array using runtime\_stringtoslicebyte and calls **main\_obfus**, which looks like this

```python
def main_obfus(bytes)
    temp = bytes[::-1]
    return temp[9:11]+temp[11:13]+temp[:9]
```

**main\_main** then stores the array of bytes returned by **main\_obfus** and stores into a global variable at 0x5de130. It stores len(temp[9:11])+len(temp[11:13]) in 0x5de138, len(temp[:9]) in 0x5de148, and len(temp[:9]) in 0x5de140.

**main\_final** calls **main\_swap** with four arguments - the string at 0x5de130, 4, 0x5de134, 9. Let's take a look at **main\_swap**

```python
def main_swap(a, b, c, d)
    if main_check(a, b):
        exit()
    if '.' in c[:d]:
        exit()

def main_check(string, len):
    try:
        int(string[:len])
    except:
        exit()
```

So, 0x5de130 must contain 4 digits, followed by a string of length 9 without any '.'.
It calls **net\_Listen** on the string "%s:%s" % (0x5de134, 0x5de130)
Now, the password is clear. 0x5de134 stores the hostname which is of 9 letters without any dot - "localhost". And the 4 digits at 0x5de130 represent the port, for the tcp server.

Let's take the port as 1234. So, what will be our password ?
Go to **main\_obfus** and take a look. The first two characters of the input are insignificant the remaining is **"localhost1234"[::-1]**.

Let's try "xx4321tsohlacol" as input. Which will make **main\_final** start a tcp server at localhost:1234.

For every incoming connection, **main\_handleit** is called. In **main\_handleit**, the string written to the socket must be of length 16.

```x86asm
.text:00000000004ED125      call    rcx             ; net__ptr_TCPConn_Read
.text:00000000004ED127      mov     rax, [rsp+1D0h+var_98]
.text:00000000004ED12F      mov     [rsp+1D0h+var_1D0], rax
.text:00000000004ED133      mov     rcx, [rsp+1D0h+var_178]
.text:00000000004ED138      mov     [rsp+1D0h+var_1C8], rcx
.text:00000000004ED13D      mov     rdx, [rsp+1D0h+var_170]
.text:00000000004ED142      mov     [rsp+1D0h+var_1C0], rdx
.text:00000000004ED147      call    main_findlen
.text:00000000004ED14C      mov     rax, [rsp+1D0h+var_1B8]
.text:00000000004ED151      cmp     rax, 10h
.text:00000000004ED155      jnz     loc_4ED4D7
.text:00000000004ED15B      mov     rcx, [rsp+1D0h+port]
.text:00000000004ED160      xor     edx, edx
.text:00000000004ED162      jmp     short loc_4ED18E
```

We have an array of qwords computed as follows

```python
var_130 = [0x327, 0x125, 0x436, 0xc91, 0x167, 0x282]
var_100 = [0 for _ in xrange(len(var_130))]
for i in xrange(len(var_130)):
    var_100[i] = port % var_130[i]
```

It then calls **main\_obfus2** with the string read from the socket as argument

```x86asm
.text:00000000004ECD01      mov     rax, cs:port_len         ; 0x5de138
.text:00000000004ECD08      mov     rcx, cs:socket_address   ; 0x5de130
.text:00000000004ECD0F      mov     rdx, [rsp+60h+arg_8]     ; string length
.text:00000000004ECD14      cmp     rdx, rax
.text:00000000004ECD17      jge     loc_4ECF0C

[ ... snip ... ]

.text:00000000004ECF0C loc_4ECF0C:
.text:00000000004ECF0C      mov     rdx, [rsp+60h+arg_0]
.text:00000000004ECF11      mov     [rsp+60h+var_60], rdx    ; string read
.text:00000000004ECF15      mov     [rsp+60h+var_58], rax    ; port length
.text:00000000004ECF1A      mov     [rsp+60h+var_50], rcx    ; socket address - 1234localhost
.text:00000000004ECF1F      mov     [rsp+60h+var_48], rax    ; port length
.text:00000000004ECF24      call    runtime_eqstring
.text:00000000004ECF29      movzx   eax, byte ptr [rsp+60h+var_40]
.text:00000000004ECF2E      mov     rdx, [rsp+60h+arg_8]
.text:00000000004ECF33      jmp     loc_4ECD1F
```

Great, so the first 4 bytes of the input must be the port of the tcp server.

```x86asm
.text:00000000004ECD1F      test    al, al
.text:00000000004ECD21      jz      loc_4ECEFD
.text:00000000004ECD27      mov     rax, cs:host_len         ; length of host (in password)
.text:00000000004ECD2E      mov     rcx, cs:aHost            ; address in 0x5de140
.text:00000000004ECD35      cmp     rax, 7
.text:00000000004ECD39      jb      loc_4ECF3F
.text:00000000004ECD3F      mov     rax, [rsp+60h+arg_0]
.text:00000000004ECD44      mov     [rsp+60h+var_60], rax    ; string read from socket
.text:00000000004ECD48      mov     [rsp+60h+var_58], rdx    ; string length
.text:00000000004ECD4D      add     rcx, 4
.text:00000000004ECD51      mov     [rsp+60h+var_50], rcx    ; &hostname[0]+4
.text:00000000004ECD56      mov     [rsp+60h+var_48], 3      ; 3 chars substring
.text:00000000004ECD5F      call    strings_Index
.text:00000000004ECD64      mov     rax, [rsp+60h+var_40]
.text:00000000004ECD69      cmp     rax, 4
.text:00000000004ECD6D      jnz     loc_4ECEEE
.text:00000000004ECD73      mov     rax, [rsp+60h+arg_8]
.text:00000000004ECD78      cmp     rax, 0Ch
.text:00000000004ECD7C      jb      loc_4ECF38
.text:00000000004ECD82      mov     rax, [rsp+60h+arg_0]
.text:00000000004ECD87      add     rax, 7
.text:00000000004ECD8B      mov     [rsp+60h+var_10], rax
.text:00000000004ECD90      mov     [rsp+60h+var_60], rax
.text:00000000004ECD94      mov     [rsp+60h+var_58], 5
.text:00000000004ECD9D      call    main_check
```

hostName must be of length atleast 7. The index of hostname[4:7] in the string must be 4. The string length must be atleast 12
So, we have - the string is of the format **"1234????????????"** where '?' is unknown.

Now, **string[4:7] == "localhost"[4:7]**. Thus the string now is **"1234lho?????????"**. It then calls **main\_check** on string[7:12], which implies, the 5 characters from offset 7 must be digits.

```x86asm
.text:00000000004ECDBA loc_4ECDBA:
.text:00000000004ECDBA      mov     rax, [rsp+60h+var_10]
.text:00000000004ECDBF      mov     [rsp+60h+var_60], rax
.text:00000000004ECDC3      mov     [rsp+60h+var_58], 5
.text:00000000004ECDCC      call    strconv_Atoi
.text:00000000004ECDD1      mov     rax, [rsp+60h+var_48]
.text:00000000004ECDD6      mov     rcx, [rsp+60h+var_50]
.text:00000000004ECDDB      test    rax, rax
.text:00000000004ECDDE      jnz     loc_4ECEDF

.text:00000000004ECDE4      mov     [rsp+60h+var_60], rcx
.text:00000000004ECDE8      call    math_big_NewInt
.text:00000000004ECDED      mov     rax, [rsp+60h+var_58]
.text:00000000004ECDF2      mov     [rsp+60h+var_30], rax        ; var_30 = int(string[7:12])
.text:00000000004ECDF7      mov     [rsp+60h+var_60], 7Bh
.text:00000000004ECDFF      call    math_big_NewInt
.text:00000000004ECE04      mov     rax, [rsp+60h+var_58]
.text:00000000004ECE09      mov     [rsp+60h+var_38], rax        ; var_38 = 0x7b
.text:00000000004ECE0E      mov     [rsp+60h+var_60], 81BBh
.text:00000000004ECE16      call    math_big_NewInt
.text:00000000004ECE1B      mov     rax, [rsp+60h+var_58]
.text:00000000004ECE20      mov     [rsp+60h+var_28], rax        ; var_28 = 0x81bb
.text:00000000004ECE25      mov     [rsp+60h+var_60], 84h
.text:00000000004ECE2D      call    math_big_NewInt
.text:00000000004ECE32      mov     rax, [rsp+60h+var_58]
.text:00000000004ECE37      mov     [rsp+60h+var_20], rax        ; var_20 = 0x84
.text:00000000004ECE3C      mov     [rsp+60h+var_60], 0A7D5h
.text:00000000004ECE44      call    math_big_NewInt
.text:00000000004ECE49      mov     rax, [rsp+60h+var_58]
.text:00000000004ECE4E      mov     [rsp+60h+var_18], rax        ; var_18 = 0xa7d5
```

Now we have, **(var\_30 + var\_38 ^ var\_28) - var\_20 == var\_18**. Thus var\_30 = (var\_18+var\_20 ^ var\_28)-var\_38 = 10599  
The string, now is **1234lho10599???** as a newline is appended as the 15th char.

**main\_handleit** now calls **main\_hasherboy**.

```python
def hasherboy(string):
    hash = map(ord, md5(string[:12]).hexdigest())
    magic = [124, 81, 11, 120, 106, 5, 95, 6, 65, 102, 97, 7, 22, 103, 98, 4, 17, 15, 12, 114, 18, 20, 69, 117, 4, 78, 82, 59, 54, 81, 28, 67]
    ans = []
    for i in xrange(len(magic)):
        ans.append(hash[i] ^ magic[i])
    return ''.join(map(chr, ans))

print 'The Flag is  :   ',
ans = ''
var_D0 = [i for i in var_100]
for i in var_D0:
    print(end='', chr(i))
print hasherboy(string) + "}"
```

Great! now we can find the port of the tcp server easily. Recall that, **var\_100 = [port % i for i in [0x327, 0x125, 0x436, 0xc91, 0x167, 0x282]]** and since the flag starts with **"inctf{"**, we have

```bash
┌─[x0r19x91@x0r19x91]─[~/Desktop/ctf/inctf]
└──╼ $ cat solve.py
#!/usr/bin/env python

magic = [0x327, 0x125, 0x436, 0xc91, 0x167, 0x282]

for port in xrange(0x10000):
    if 'inctf{' == ''.join([chr(port % i & 0xff) for i in magic]):
        print '[*] Port: %d' % port
        break
┌─[x0r19x91@x0r19x91]─[~/Desktop/ctf/inctf]
└──╼ $ python solve.py
[*] Port: 3333
┌─[x0r19x91@x0r19x91]─[~/Desktop/ctf/inctf]
└──╼ $
```

So, the password is **"XX3333tsohlacol"** and the string to be sent to the server at localhost:3333 is **"3333lho10599XXX"** where X can be any character. The flag is **"inctf{" + hasherboy("3333lho10599") + "}"** which is **"inctf{D4mN\_7h4t\_W4s\_T1rinG!!!L0v3\_R3x!}"**

![Image1](/images/inctf18_ultimategoal0.png)
