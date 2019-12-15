---
title: "UTCTF 2019 - Crackme"
date: 2019-03-11
tags: [reversing]
---

<!--more-->

![intro](/images/utctf/crackme_intro.png)

Well it's really **very easy** challenge. I don't understand how it could be for 1200 points !!

I've used IDA Free only. Let's get started

![i1](/images/utctf/crackme1.png)

Yes it deliberately calls **divide** on 0x20 and 0.

![i2](/images/utctf/divide.png)

The **divide** routine checks if the second parameter is zero. In that case it throws an int of value 8. Otherwise it returns the result of division.
Now since it wants to divide by zero, an exception is thrown by divide. Which is caught by **___cxa_begin_catch**

Let's see the catch block.

![i3](/images/utctf/catch.png)

This x0r's two of the input chars

```
input[0x34] ^= 0x43
input[0x2f] ^= 0x44
```

![l1](/images/utctf/loop1.png)

This loop x0r's each input character with 0x27

![l2](/images/utctf/loop2.png)

This loop does something like this

```python
for i in xrange(0xcb):
    stuff[i] = stuff[i]-1 ^ stuff2[0xca-i]
```

![c0](/images/utctf/correct.png)

So, **stuff** must modify the input string so that it matches the bytes at **test**. Now here's a small script to decode stuff

```c
#include <idc.idc>

static main() {
    auto i;
    auto stuff = 0x602090;
    auto stuff2 = 0x602160;

    for (i = 0; i < 0xcb; i++) {
        auto a = ord(get_bytes(stuff+i, 1, 0))-1;
        auto b = ord(get_bytes(stuff2+0xca-i, 1, 0));
        patch_byte(stuff+i, a^b);
    }
}
```

![s0](/images/utctf/stuff0.png)

So, for each iteration, this block divides 21 by 7 and if the remainder is not 2, it proceeds to 0x60210b.

![s1](/images/utctf/stuff1.png)

This x0r's each input char with 0x33. Extending the script, to get the flag

```c
#include <idc.idc>

static main() {
    auto i;
    auto stuff = 0x602090;
    auto stuff2 = 0x602160;

    for (i = 0; i < 0xcb; i++) {
        auto a = ord(get_bytes(stuff+i, 1, 0))-1;
        auto b = ord(get_bytes(stuff2+0xca-i, 1, 0));
        patch_byte(stuff+i, a^b);
    }

    for (i = 0; i < 0x40; ++i) {
        b = ord(get_bytes(0x602230+i, 1, 0));
        patch_byte(0x602230+i, b^(i+0x33)^0x27);
    }

    b = ord(get_bytes(0x602230+0x34, 1, 0));
    patch_byte(0x602230+0x34, b^0x43);

    b = ord(get_bytes(0x602230+0x2f, 1, 0));
    patch_byte(0x602230+0x2f, b^0x44);

    patch_byte(0x602230+0x3f, 0);
}
```

The flag is : **utflag{1_hav3_1nf0rmat10n_that_w1ll_lead_t0_th3_arr3st_0f_c0pp3rstick6}**