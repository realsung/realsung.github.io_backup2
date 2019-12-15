---
title: "BITS CTF - revme"
categories: [reversing]
tags: [reversing, bits_ctf]
date: 2019-02-04
---

<!--more-->

Well this is a pretty easy reversing challenge.  
Let's get started. I've used radare.


![main](/images/bits_ctf0.png)

**[rbp-0x100]** contains the address of the std::string which has the string **1_Kn0w_Y0u_Th0ugh7_7h1s_C0ulD_B3_7h3_FL4G_bu7_:{M}_7h15_I5n'7_S0_K33p_7ry1nG**  
**rbp-0xc0** is an array used to index into the above string.  
So, the flag checker algo is

```python
def validate(flag):
    local_100h = "1_Kn0w...7ry1nG"
    local_c0 = [30, 56, 11, 62, 24, 11, 37, 47, 30, 0, 3,
        39, 71, 0, 31, 22, 1, 54, 31, 31, 48, 1, 12, 39,
        71, 28, 1, 30, 9, 17, 1, 39, 71, 31, 1, 3, 4, 11, 49]
    valid = True
    for i in xrange(0x27):
        if local_100h[local_c0[i]] != flag[i]:
            valid = False
            break
    return valid
```

Now, it's pretty easy to get the flag  

```python
def get_flag():
    str = "1_Kn0w_Y0u_Th0ugh7_7h1s_C0ulD_B3_7h3_FL4G_bu7_:{M}_7h15_I5n'7_S0_K33p_7ry1nG"
    index = [30, 56, 11, 62, 24, 11, 37, 47, 30, 0, 3,
        39, 71, 0, 31, 22, 1, 54, 31, 31, 48, 1, 12, 39,
        71, 28, 1, 30, 9, 17, 1, 39, 71, 31, 1, 3, 4, 11, 49]
    print ''.join(map(lambda i: str[i], index))
```

And here's the flag **BITSCTF{B1n4r13s_533M_h4rD_Bu7_4r3_n0T}**
