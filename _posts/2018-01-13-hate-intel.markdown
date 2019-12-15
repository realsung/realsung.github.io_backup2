---
title: "Hate Intel"
date: 2018-01-13 17:01:00
tags: [reversing]
categories: [reversing]
---

<!--more-->
Hi!
This is a challenge from [reversing.kr](http://reversing.kr)

Open the file in IDA. The main function is located at 0x00002224.
Let's take a look at the algorithm

```py3
buffer = # array of 28 bytes at 0x3004

def func(char, index):
    while index:
        char <<= 1
        if char & 255:
            char += 1
        index -= 1
    return char

def sub_232C(s, count):
    for i in range(count):
        for j in range(len(s)):
            s[j] = func(s[j], 1)

def main():
    print('Input Key...')
    key = list(input())
    l = len(key)
    sub_232C(key, 4)

    for i in range(l):
        if key[i] != buffer[i]:
            print('Wrong Key!')
            exit()

    print('Correct Key!')
```

Let char = b7b6b5b4b3b2b1b0. Now char << 1 equals b7b6b5b4b3b2b1b00. ANDing 256 with char results in b700000000. If b7
is set, then the lsb of char is set, i.e. in other words, the function shifts char by 1 to the left and copies the MSB to LSB. So char becomes b6b5b4b3b2b1b0b7.

Hey! this is rotating bits - our favorite x86 ```rol```

In sub\_232C, we can swap the inner and outer loops because s[j] = func(s[j], 1)  is invariant wrt loop order i.e., s[j] = func(func(func(func(s[j], 1), 1), 1), 1) is executed for 0 ≤ j ≤ len(s). So 4 times we rotate left char. If char is b7b6b5b4b3b2b1b0 , it becomes b3b2b1b0b7b6b5b4. To reverse it, we simply need to rotate right 4 bits for each byte in buffer array.

```x86asm
    format ELF64 executable
    entry main

segment executable writeable

    msg         db  0x44, 0xf6, 0xf5, 0x57, 0xf5, 0xc6, 0x96, 0xb6
                db  0x56, 0xf5, 0x14, 0x25, 0xd4, 0xf5, 0x96, 0xe6
                db  0x37, 0x47, 0x27, 0x57, 0x36, 0x47, 0x96, 3
                db  0xe6, 0xf3, 0xa3, 0x92
    msg.size    =   $-msg
                db  10

main:
    mov ecx, msg.size
    mov rsi, msg
    mov edx, ecx
@@:
    rol byte [rsi], 4
    inc rsi
    dec ecx
    jnz @b

    mov eax, 1
    mov edi, 1
    mov rsi, msg
    inc edx
    syscall

    mov eax, 0x3c
    xor edi, edi
    syscall
```

And we have

![Image](/images/hate_intel.png)
