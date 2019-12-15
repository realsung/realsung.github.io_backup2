---
title: "noxCTF - Raphic"
date: 2018-09-20 01:12:30
tags: [ctf, reversing]
categories: [ctf, reversing]
---

<!--more-->
![Image0](/images/nox/Raphic.png)

Open the file in Radare. I've renamed the function names.
This program takes a single argument - a key.

![Image1](/images/nox/r0.png)

We can see that after calling 'sum.tmp\_...\_b0d', the routine creates a socket with AF\_LOCAL protocol and type SOCK\_SEQPACKET.

![Image2](/images/nox/r1.png)

fcn.00442f60 calls __openat__ with the first argument as AT\_FDCWD. But since the path - "/tmp/..." is absolute, the first argument is ignored. It then writes an array of 0x103f68 bytes of from 0x6b20d0 into the file. The address 0x6b20d0 is in the data section.

```bash
┌─[x0r19x91@x0r19x91]─[~/Desktop]
└──╼ $ objdump -h raphic

raphic:     file format elf64-x86-64

Sections:
Idx Name          Size      VMA               LMA               File off  Algn
  0 .note.ABI-tag 00000020  0000000000400190  0000000000400190  00000190  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  1 .note.gnu.build-id 00000024  00000000004001b0  00000000004001b0  000001b0  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, DATA

                  [ ... snip ... ]

 24 .data         00105a50  00000000006b20c0  00000000006b20c0  000b20c0  2**5
                  CONTENTS, ALLOC, LOAD, DATA

┌─[x0r19x91@x0r19x91]─[~/Desktop]
└──╼ $ hd -n 32 -s 0x0b20d0 raphic
000b20d0  7f 45 4c 46 02 01 01 03  00 00 00 00 00 00 00 00  |.ELF............|
000b20e0  02 00 3e 00 01 00 00 00  50 0a 40 00 00 00 00 00  |..>.....P.@.....|

┌─[x0r19x91@x0r19x91]─[~/Desktop]
└──╼ $ dd if=raphic of=bin bs=1 count=$((0x103f68)) skip=$((0x0b20d0))
```

The array of bytes that's written into the file "/tmp/..." starts with __"\x7fELF"__. So, there's an ELF file at offset 0x0b20d0 of 0x103f68. Let's dump it to a file named 'bin' which I'll analyze later.
The routine then spawns a process which executes the newly created ELF file.

![Image3](/images/nox/r2.png)

The socket connects to __sockaddr\_un { .sun\_family = AF\_LOCAL, .sun\_path = "/tmp/socket.socket" }__ after sleeping for 1 second. Now we have a protocol here. The client, writes some data into the socket and waits for response. If the response is 0, it indicates success. Otherwise, the client exits with exit\_code 1.

```c
struct info {
    void* address;
    int length;
};

struct info inf;
inf.length = strlen(argv[1]);

// ...
inf.address = (void*) 0xaabbccdd;       // the address is changed

write(socket_fd, &inf, sizeof (struct info));
write(socket_fd, argv[1], inf.length);

long ret;
if (-1 == read(socket_fd, &ret, 8) || ret)
    exit(1);

// ...
```

The following addresses are written out - __[ 0x400c59, 0x400cf0, 0x400d42, 0x400d7c, 0x400e08, 0x400edb]__ with argv[1] as the string. The next two writes using addresses __[0x400e36, 0x400f0b]__ use the string at address 0x48b0fe.

### Stage \#2

Let's analyze the file 'bin'

![Image4](/images/nox/r3.png)

So, main starts out by deleting the file __/tmp/...__ and setting up a SIGTRAP handler at address __0x400bab__. It then creates a AF\_LOCAL socket, and unlinks the socket name __"/tmp/socket.socket"__ created by the parent.

![Image5](/images/nox/r4.png)

It then binds the socket to __/tmp/socket.socket__ and waits for connection. Once a connection is established, we have

![Image6](/images/nox/r5.png)

A for loop runs 100 times, calling memset on a __struct info__ variable, which it reads from the client, followed by __info.length__ amount of bytes. If it doesn't receive the expected amount of bytes it prints "Invalid data length" and exits.

```x86asm
je 0x401128
jne 0x401128
```

This implies, that there is garbage in the instructions that follow __'jne'__. It'd have been better to use a single unconditional __'jmp'__ to redirect the control flow

![Image7](/images/nox/r6.png)

This is interesting. The loop looks like this

```c
// ...

for (int i = 0; i <= 0x63; ++i) {
    struct info inf;
    memset(&inf, 0, sizeof (struct info));

    read(socket_fd, &inf, sizeof (struct info));
    read(socket_fd, buffer, inf.length);

    // ...

    long (*function)(char*, long) = (long (*)(char*, long)) inf.address;
    long ret = function(buffer, inf.length);

    write(socket_fd, &ret, 8);
}
```

So, the addresses that are passed by the parent process are called by the child process.
Recall that when the parent reads the status code after it sends data to the child, the __if__ becomes true if a non-zero status (failure) is retured. So, the child must return a zero status code (success).

#### sigtrap\_handler

![Image8](/images/nox/r7.png)

The function at 0x400b5fd, xor's each character with 0x42 in the string passed as argument. I've renamed it to 'x0r\_decrypt'
Here we have,

```c
// ...
int data, index, status;

void x0r_decrypt(char* buffer, int size)
{
    for (int i = 0; i < size; ++i)
        buffer[i] ^= 0x42;
}

void sigtrap_handler(int signal_id)
{
    status = 0;
    if (index == 4) {
        x0r_decrypt(&data, 4);
        if (data != 0x1d110b1d)
            status = -1;
        index = 12;
    } else if (index == 12) {
        if (status == 'MOST')
            status = -1;
        index = 12;
    } else if (index == 0) {
        if (data != 'THIS')
            status = -1;
        index = 12;
    } else {
        exit(1);
    }
}
```

On index = 4, data = (0x1d110b1d ^ 0x42424242). Writing out in little endian, we get __'\_IS\_'__

#### Validation Routine #0 - 0x400c59

![Image9](/images/nox/r8.png)

Another jmp. Okay let's follow it

![Image10](/images/nox/r9.png)

Cool ! It reads a 4 byte dword from string+index and assigns it to 'data', where 'index' is the global variable at address 0x702274 and 'string' is the argument passed to it. Using __int3__ it calls the sigtrap\_handler. So, the first 4 bytes of the string (index = 0) is __'THIS'__. The next 4 bytes (index = 4) is __'\_IS\_'__. At index = 12, we have __'MOST'__.
So, our key till now is - __'THIS\_IS\_????MOST'__ where the '?' represents that we don't know those characters till now. So, the addresses sent by the parent process are validation routines.

#### Validation Routine #1 - 0x400cf0

![Image11](/images/nox/r10.png)

Pretty simple, the validation logic used is - string[8]^string[9] == 0x1c and string[10]^string[11] = 0x1a

#### Validation Routine #2 - 0x400d42

![image12](/images/nox/r11.png)

string[16] == '\_' and string[23] == '\_'
So, our key is now - __'THIS\_IS\_????MOST\_??????\_'__

#### Validation Routine #3 - 0x400d7c

![Image13](/images/nox/r12.png)

Here there are two tasks. Firstly, string[18] == string[22] must be true. Secondly, the __MD5__ of string[17:23] must be __'edc93ee6a56a49ef22369e109c7fe0ab'__ which corresponds to the string __'SECURE'__
So, the key now is - __'THIS\_IS\_????MOST\_SECURE\_'__

#### Validation Routine #4 - 0x400e08

It jumps to 0x400e1d and we have
![Image14](/images/nox/r13.png)

So, string[24:] = __"KEY\_a1"__. The key constructed till now is - __'THIS\_IS\_????MOST\_SECURE\_KEY\_a1'__

#### Validation Routine #5 - 0x400edb

![Image15](/images/nox/r14.png)

It computes the MD5 of the whole key which was passed as argument and stores it in address __0x7050a0__. Accroding to Routine #1, string[8]^string[9] == 0x1c and string[10]^string[11] == 0x1a
Bruteforcing,

```python
>>> def find():
...  p = '_ABCDEFGHIJKLMNOPQRSTUVWXYZ'
...  for i in p:
...   for j in p:
...    for k in p:
...     for l in p:
...      if (ord(i)^ord(j)) == 0x1c and (ord(k)^ord(l)) == 0x1a:
...       print i, j, k, l
>>> find()
_ C _ E
_ C B X
_ C C Y
_ C E _

[ ... snip ... ]

T H _ E
T H B X
T H C Y
T H E _     ; looks promising

[ ... snip ... ]
```

__'THE\_'__ actually makes sense. So, the key is - __'THIS\_IS\_THE\_MOST\_SECURE\_KEY\_a1'__

![Image16](/images/nox/r15.png)
