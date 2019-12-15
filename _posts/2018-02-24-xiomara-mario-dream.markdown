---
title: "Xiomara CTF - Mario's Dream"
date: 2018-02-24 23:34:00
tags: [ctf]
categories: [ctf]
---

<!--more-->
#### Task

Given n, find number of integers such that for each integer x, x ⊕ n > n. It is also mentioned that the time complexity must be O(t lg n) where t is the number of test cases.

#### Observation
Let n = b011 where b is a binary string. So we have first 0 at position 2 from MSB. For the x0r to be greater than n, we must change the zero to one => resulting in 22 combinations i.e., [b100, b101, b110, b111] each of these is greater than n. So the answer is

```python
string = bin(n)[2:][::-1]
answer = sum([1<<i for i in xrange(len(string)) if string[i] == '0'])
```

And the solution is

```c
#include <ctype.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>

long long solve(long n)
{
    long long ans = 0;
    int i = 0;
    while (n)
    {
        if (~n & 1) ans += (1LL << i);
        i++;
        n /= 2;
    }
    return ans;
}

int main()
{
    int handle = socket(AF_INET, SOCK_STREAM, 0);
    char address[] = "\x02\x00\x05\x48\x8b\x3b\x1c\x04\x00\x00\x00\x00"
        "\x00\x00\x00\x00";
    struct sockaddr_in* addr = (struct sockaddr_in*) address;

    printf("[+] Connecting to %s:%d ... ", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));

    if (connect(handle, (struct sockaddr*)addr, 16) == -1)
    {
        puts("\n[!!] Cannot 'connect' to server !");
        close(handle);
        exit(1);
    }

    puts("Connected");

    FILE* stream = fdopen(handle, "rb+");
    char buf[256];

    while (1)
    {
        fgets(buf, 256, stream);
        int len = strlen(buf);
        buf[len-1] = 0;
        printf("[=] Server Said -> %s\n", buf);
        if (isdigit(buf[0]))
            break;
    }

    long test_case_count = strtol(buf, NULL, 10);
    printf("[+] # Test Cases : %ld\n", test_case_count);
    while (test_case_count--)
    {
        fgets(buf, sizeof buf, stream);
        long m;
        sscanf(buf, "%ld", &m);
        fprintf(stream, "%lld\n", solve(m));
    }

    fgets(buf, sizeof buf, stream);
    printf("%s", buf);

    fclose(stream);
    close(handle);
}
```

And the output is

![Image](/images/xiomara/i1.png)
