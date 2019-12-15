---
title: "Xiomara CTF - Fortune Jack"
date: 2018-02-25 00:26:00
categories: [ctf]
tags: [ctf]
---

<!--more-->
A rather simple rev task. Using dnSpy to decompile the .NET Executable we can easily write the code to get the flag since the generated key is modulo 1500

```c
#include <openssl/md5.h>
#include <string.h>
#include <stdio.h>

char text[] = { 254, 230, 254, 214, 238, 251, 236, 232, 253, 214, 240, 230, 252, 214, 237, 224, 237, 214, 224, 253, 214, 179, 160 };
char temp[23];
char md5_hash[16];
char match[] = "DB2C17E69713C8604A91AA7A51CBA041";
char fmt_hash[33];
char hexstr[] = "0123456789ABCDEF";

void format_hash()
{
    for (int i = 0; i < 16; i++) {
        fmt_hash[i<<1] = hexstr[0xf & (md5_hash[i]>>4)];
        fmt_hash[i*2+1] = hexstr[md5_hash[i] & 0xf];
    }
}

int main()
{
    for (int key = 1; key < 1500; ++key) {
        for (int i = 0; i < (sizeof text); ++i)
            temp[i] = (char)((int)text[i]^key);

        MD5(temp, 23, md5_hash);
        format_hash();

        if (strncmp(fmt_hash, match, 32) == 0) {
            printf("[=] Flag -> xiomara\x7b%.*s\x7d\n", 23, temp);
            break;
        }
    }
}
```

And the output is

![Image](/images/xiomara/i0.png)
