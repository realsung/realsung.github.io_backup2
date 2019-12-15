---
title: "noxCTF - Att3ntion"
date: 2018-09-19 11:16:29
categories: [ctf, reversing]
tags: [reversing, ctf]
---

<!--more-->
![Image0](/images/nox/Att3ntion.png)

Open the file in Radare. Looking at the main routine, we have

![Image1](/images/nox/main.png)

'sym.\_Y2hlY2tLZXk' which validates the argument passed to it. Returning 1 on success

![Image2](/images/nox/func0.png)

So, we have a recursive function. The function takes a string argument and repeatedly calls itself until the null character is reached. Something like this

```c
int validate(char* str)
{
    char ans = 0;               // ans is at ebp-0x9
    if (*str == 0) {
        if (count-- == 0x2e)    // count is at 0x407020
          return 1;             // good jump :-)
        return 2;
    } else {
        count++;
        ans = validate(++str);
        // ...
    }
}
```

![Image3](/images/nox/func1.png)

The remaining part ...

```c
        // ...
        if (ans == 2)
            return 2;
        if (ans == 0 || count == 0)
            return ans;
        if (*str == 0)
            return 1;

        if ((*str ^ _404004[count % 4]) == _405064[count])
            ans = 1;        // good boy
        else
            ans = 0;
        count--;
        return ans;
    }
}
```

The array \_404004 contains the bytes - [0x13, 0x37, 0x73, 0x31]
The length of the input must be 0x2e to return 1 when the string terminator is reached.

The string is processed in reverse. For every character processed, the variable count contains the index of that character

Now getting the flag is trivial

```python
#!/usr/bin/env python

arr = [ 0x7d, 0x58, 0x0b, 0x65, 0x55, 0x4c, 0x35, 0x50, 0x78, 0x52,
  0x53, 0x41, 0x72, 0x44, 0x00, 0x46, 0x7c, 0x45, 0x17, 0x1f,
  0x3d, 0x17, 0x35, 0x58, 0x7d, 0x53, 0x53, 0x42, 0x7c, 0x5a,
  0x16, 0x45, 0x7b, 0x5e, 0x1d, 0x56, 0x33, 0x52, 0x1f, 0x42,
  0x76, 0x17, 0x1a, 0x5f, 0x60, 0x5e ]

magic = [ 0x13, 0x37, 0x73, 0x31 ]
length = 0x2e

for i in xrange(length-1, -1, -1):
    arr[i] = chr(arr[i] ^ magic[i%4])

print ''.join(arr)
```

Which outputs - "__noxTF{Fake password.. Find something else insi__"  
Where is the flag ?????

We have another suspicious function '__sym.\_c2VjcmV0RnVuY3Rpb24__'

The routine sym.\_c2VjcmV0RnVuY3Rpb24 sets up an array of 64 bytes at stack location __ebp-0x51__

![Image4](/images/nox/check0.png)

So, the code expects the first 4 bytes to be 0x55, 0xe9, 0xe5, 0x60. But the first 4 bytes is  
![Image5](/images/nox/check1.png)

Let's xor the respective bytes - 0x55 ^ 0x46, 0xe9 ^ 0xbe, 0xe5 ^ 0x96, 0x60 ^ 0x51, which is __[0x13, 0x37, 0x73, 0x31]__. Hey it's our magic array !!. Xoring the array of 0x1f bytes with our magic array, we have

```x86asm
    push ebp
    mov ebp,esp
    pushad
    xor eax,eax
    mov esi,0x11223344          ; invalid address
    mov edi,0xaabbccdd          ; invalid address

.decode_loop:
    lodsb
    test al,al
    jz .finished
    xor al, 0x17
    stosb
    jmp short .decode_loop

.finished:
    popad
    mov esp,ebp
    pop ebp
    ret

bytes:  db  0x79, 0x78, 0x6f, 0x43, 0x51, 0x6c
        db  0x5f, 0x26, 0x73, 0x73, 0x24, 0x79
        db  0x48, 0x51, 0x42, 0x59, 0x74, 0x20
        db  0x26, 0x27, 0x79, 0x22, 0x48, 0x23
        db  0x65, 0x24, 0x48, 0x54, 0x27, 0x27
        db  0x26, 0x36, 0x6a, 0x00
```

The routine then allocates 3 pages using __VirtualAlloc__ with PAGE\_EXECUTE\_READWRITE permission

![Image6](/images/nox/check2.png)

Here the code fixes the 4 bytes at offsets 0x07 and 0x0c from ebp-0x51, i.e., replaces the addresses 0x11223344 and 0xaabbccdd with the effective address __ebp-0x32__, i.e., the address of the 'bytes' array

Now, the decoding the flag is pretty easy

```python
#!/usr/bin/env python

arr = [0x79, 0x78, 0x6f, 0x43, 0x51, 0x6c, 0x5f, 0x26,
    0x73, 0x73, 0x24, 0x79, 0x48, 0x51, 0x42, 0x59,
    0x74, 0x20, 0x26, 0x27, 0x79, 0x22, 0x48, 0x23, 0x65,
    0x24, 0x48, 0x54, 0x27, 0x27, 0x26, 0x36, 0x6a]

for i in xrange(len(arr)):
    arr[i] ^= 0x17

print ''.join(map(chr, arr))
```

And, the output is

__noxTF{H1dd3n\_FUNc710n5\_4r3\_C001!}__

Yay !! :-)
