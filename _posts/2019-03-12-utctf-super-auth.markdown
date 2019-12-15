---
title: "UTCTF 2019 - Super Secure Authentication"
date: 2019-03-12
categories: [reversing, java]
---
<!--more-->

![s0](/images/utctf/java0.png)

This is a Java Crackme. I've used CFR decompiler as it handles Java SE 8+ very well.
There are 8 Verifier classes and one Authentication class. Let's look at **Authentication.class**

```java
/*
 * Decompiled with CFR 0.140.
 */
import java.io.PrintStream;
import java.util.StringTokenizer;

public class Authenticator {
    private static boolean checkFlag(String candidate) {
        try {
            if (!candidate.substring(0, 7).equals("utflag{")) {
                return false;
            }
            if (candidate.charAt(candidate.length() - 1) != '}') {
                return false;
            }
            StringTokenizer st = new StringTokenizer(candidate.substring(7, candidate.length() - 1), "_");
            if (!Verifier0.verifyFlag(st.nextToken())) {
                return false;
            }
            if (!Verifier1.verifyFlag(st.nextToken())) {
                return false;
            }
            if (!Verifier2.verifyFlag(st.nextToken())) {
                return false;
            }
            if (!Verifier3.verifyFlag(st.nextToken())) {
                return false;
            }
            if (!Verifier4.verifyFlag(st.nextToken())) {
                return false;
            }
            if (!Verifier5.verifyFlag(st.nextToken())) {
                return false;
            }
            if (!Verifier6.verifyFlag(st.nextToken())) {
                return false;
            }
            return Verifier7.verifyFlag(st.nextToken());
        }
        catch (Exception e) {
            return false;
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.out.println("usage: java Authenticator [password]");
            return;
        }
        String candidate = args[0];
        if (Authenticator.checkFlag(candidate)) {
            System.out.println("You got it! The flag is: " + candidate);
        } else {
            System.out.println("Oops, try again!");
        }
    }
}
```

Okay so, the flag looks like this - **utflag{A_B_C_D_E_F_G_H}**. Each of those A..H are validated by the respective **Verifier** classes. The Verifiers have a generic structure

```java
/*
 * Decompiled with CFR 0.140.
 */
import java.lang.reflect.Method;

public class VerifierX extends ClassLoader {
    private static byte[] arr = jBaseZ85.decode("...[some huge strings]...");

    public static boolean verifyFlag(String string) throws Exception {
        VerifierX verifierX = new VerifierX();
        Class<?> class_ = verifierX.defineClass("VerifierX", arr, 0, arr.length);
        Object object = class_.getMethod("verifyFlag", String.class).invoke(null, string);
        return (Boolean)object;
    }
}
```

I first tried decompiling the arr. But it looks like the original ! Actually it has been encoded recursively (by Z85 encoding) 26 times !
So, manual decompilation fails !

### Algorithm

1. Parse the class file
2. If there exists no reference to **defineClass**, stop.
3. Otherwise get the **String** references whose length is above 200, decode using Z85 and repeat.

### The Decoded Classes

```java
/*
 * Decompiled with CFR 0.140.
 * 
 * Could not load the following classes:
 *  Verifier0
 */
public class Verifier0 {
    private static byte[] encrypted = new byte[]{50, 48, 45, 50, 42, 39, 54, 49};

    public static boolean verifyFlag(String string) {
        if (string.length() != encrypted.length) {
            return false;
        }
        for (int i = 0; i < encrypted.length; ++i) {
            if (encrypted[i] == (string.charAt(i) ^ 66)) continue;
            return false;
        }
        return true;
    }
}
/*
 * Decompiled with CFR 0.140.
 * 
 * Could not load the following classes:
 *  Verifier1
 */
public class Verifier1 {
    private static byte[] encrypted = new byte[]{115, 117, 111, 105, 120, 110, 97};

    public static boolean verifyFlag(String string) {
        if (string.length() != encrypted.length) {
            return false;
        }
        for (int i = 0; i < encrypted.length; ++i) {
            if (encrypted[i] == string.charAt(encrypted.length - 1 - i)) continue;
            return false;
        }
        return true;
    }
}
/*
 * Decompiled with CFR 0.140.
 * 
 * Could not load the following classes:
 *  Verifier2
 */
public class Verifier2 {
    private static int[] encrypted = new int[]{3080674, 3110465, 3348793, 3408375, 3319002, 3229629, 3557330, 3229629, 3408375, 3378584};

    public static boolean verifyFlag(String string) {
        if (string.length() != encrypted.length) {
            return false;
        }
        for (int i = 0; i < encrypted.length; ++i) {
            if (encrypted[i] == (string.substring(i, i + 1) + "foo").hashCode()) continue;
            return false;
        }
        return true;
    }
}
/*
 * Decompiled with CFR 0.140.
 * 
 * Could not load the following classes:
 *  Verifier3
 */
public class Verifier3 {
    private static String encrypted = "obwaohfcbwq";

    public static boolean verifyFlag(String string) {
        if (string.length() != encrypted.length()) {
            return false;
        }
        for (int i = 0; i < encrypted.length(); ++i) {
            if (!Character.isLowerCase(string.charAt(i))) {
                return false;
            }
            if ((encrypted.charAt(i) - 97 + 12) % 26 == string.charAt(i) - 97) continue;
            return false;
        }
        return true;
    }
}
/*
 * Decompiled with CFR 0.140.
 * 
 * Could not load the following classes:
 *  Verifier4
 */
public class Verifier4 {
    private static int[] encrypted = new int[]{3376, 3295, 3646, 3187, 3484, 3268};

    public static boolean verifyFlag(String string) {
        if (string.length() != encrypted.length) {
            return false;
        }
        for (int i = 0; i < encrypted.length; ++i) {
            if (encrypted[i] == string.charAt(i) * 27 + 568) continue;
            return false;
        }
        return true;
    }
}
/*
 * Decompiled with CFR 0.140.
 * 
 * Could not load the following classes:
 *  Verifier5
 *  javax.xml.bind.DatatypeConverter
 */
import java.security.MessageDigest;
import javax.xml.bind.DatatypeConverter;

public class Verifier5 {
    private static String encrypted = "8FA14CDD754F91CC6554C9E71929CCE7865C0C0B4AB0E063E5CAA3387C1A8741FBADE9E36A3F36D3D676C1B808451DD7FBADE9E36A3F36D3D676C1B808451DD7";

    public static boolean verifyFlag(String string) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
            String string2 = "";
            for (char c : string.toCharArray()) {
                messageDigest.update((byte)c);
                string2 = string2 + DatatypeConverter.printHexBinary((byte[])messageDigest.digest());
            }
            return string2.equals(encrypted);
        }
        catch (Exception exception) {
            return false;
        }
    }
}
/*
 * Decompiled with CFR 0.140.
 * 
 * Could not load the following classes:
 *  Verifier6
 *  javax.xml.bind.DatatypeConverter
 */
import java.security.MessageDigest;
import javax.xml.bind.DatatypeConverter;

public class Verifier6 {
    private static String hash = "1B480158E1F30E0B6CEE7813E9ECF094BD6B3745";

    public static boolean verifyFlag(String string) {
        if (string.length() != 4) {
            return false;
        }
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
            messageDigest.update(string.getBytes());
            String string2 = DatatypeConverter.printHexBinary((byte[])messageDigest.digest());
            return string2.equals(hash);
        }
        catch (Exception exception) {
            return false;
        }
    }
}
/*
 * Decompiled with CFR 0.140.
 * 
 * Could not load the following classes:
 *  Verifier7
 */
public class Verifier7 {
    private static String flag = "goodbye";

    public static boolean verifyFlag(String string) {
        return string.equals(flag);
    }
}
```

Now its trivial to get the flag - **utflag{prophets_anxious_demolition_animatronic_herald_fizz_stop_goodbye}**

### Source Code

```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <sys/sendfile.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/mman.h>
#include <endian.h>
#include <stdint.h>
#include <stdio.h>

#define PAGE_SIZE   4096
#define ALLOC_SIZE  (1000*PAGE_SIZE)
#define THRESH  200
#define TEMP_CLASS  "/tmp/tmp.class"

char ralpha[] = { 68, 0, 84, 83, 82, 72, 0, 75, 76, 70, 65, 0, 63, 62, 69, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 64, 0, 73, 66, 74, 71, 81, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 77, 0, 78, 67, 0, 0, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 79, 0, 80 };

static void
decode_quarter(int32_t* dest, char* src)
{
    static int mul[] = { 52200625, 614125, 7225, 85, 1 };
    int32_t sum = 0;
    for (int i = 0; i < 5; ++i)
        sum += ralpha[src[i]-33]*mul[i];
    *dest = __bswap_32(sum);
}

static void
decode_padding(char* dest, char* src, int len)
{
    uint32_t sum = 0;
    switch (len) {
        case 2:
            sum += ralpha[src[1]-33]*85;
            break;
        case 3:
            sum += ralpha[src[2]-33]*7225;
            break;
        case 4:
            sum += ralpha[src[3]-33]*614125;
            break;
    }
    len = len*4/5;
    sum += ralpha[*src-33];
    for (int i = len-1; i >= 0; --i)
        dest[len-i-1] = (sum >> (i << 3)) & 0xff;
}

void
decode_base85(char* buffer)
{
    int len = strlen(buffer);
    int i = 0;
    int fd = open(TEMP_CLASS, O_WRONLY|O_CREAT|O_TRUNC, 0666);
    int p;
    for (; i < len; i += 5) {
        decode_quarter(&p, buffer+i);
        write(fd, &p, 4);
    }
    if (i < len) {
        decode_padding((char*) &p, buffer+i, len-i);
        write(fd, &p, len-i);
    }
    close(fd);
}

int
get_strings(char* class_file, char* ans)
{
    int fd = open(class_file, O_RDONLY);
    struct stat buf;
    fstat(fd, &buf);
    char* clazz = mmap(NULL, buf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    char* save = ans;
    int status;

    clazz += 8;
    char sizes[] = { 0, 0, 0, 5, 5, 9, 9, 3, 3, 5, 5, 5, 5, 0, 0, 4, 3, 0, 5 };
    int n_entries = be16toh(*(int16_t*) clazz)-1;
    clazz += 2;
    
    char** pool = calloc(n_entries+1, sizeof(char*));
    for (int i = 1; i <= n_entries; ++i) {
        pool[i] = clazz;
        int tag = *clazz;
        if (tag == 1) {
            // utf8
            int32_t len = be16toh(*(int16_t*) (clazz+1));
            clazz += 3+len;
        } else {
            clazz += sizes[tag];
        }
        i += tag == 5 || tag == 6;
    }
    
    int found = 0;
    
    for (int i = 1; i <= n_entries; ++i) {
        int tag = *pool[i];
        if (tag == 10) {
            // check if ref is 'defineClass'
            int name_typ_idx = be16toh(*(int16_t*) (pool[i]+3));
            char* nt_info = pool[name_typ_idx];
            int utf8_idx = be16toh(*(int16_t*) (nt_info+1));
            if (! utf8_idx) continue;
            char* name = pool[utf8_idx];
            int name_len = be16toh(*(int16_t*) (name+1));
            if (! strncmp(name+3, "defineClass", name_len)) {
                // need to extract strings
                found = 1;
                break;
            }
        }
    }
    if (! found) {
        status = 0;
        goto cleanup;
    }
    for (int i = 1; i <= n_entries; ++i) {
        char tag = *pool[i];
        if (tag == 8) {
            int idx = be16toh(*(int16_t*) (pool[i]+1));
            char* name = pool[idx];
            int name_len = be16toh(*(int16_t*) (name+1));
            if (name_len > THRESH) {
                memcpy(ans, name+3, name_len);
                ans += name_len;
            }
        }
    }
    *ans = 0;
    status = 1;

cleanup:
    free(pool);
    munmap(clazz, buf.st_size);
    close(fd);
    return status;
}

void
copy_file(char* dst, char* src)
{
    int in = open(src, O_RDONLY);
    int out = open(dst, O_WRONLY|O_CREAT|O_TRUNC, 0666);
    struct stat buf;
    fstat(in, &buf);
    sendfile(out, in, NULL, buf.st_size);
    close(out);
    close(in);
}

void
decode_class(char* clazz_file)
{
    printf("[*] Decoding %s ...\n", clazz_file);
    copy_file(TEMP_CLASS, clazz_file);
    char* page = mmap(NULL, ALLOC_SIZE, PROT_WRITE|PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    char* ans = page;
    int len;
    setbuf(stdout, NULL);

    do
    {
        if (! get_strings(TEMP_CLASS, ans))
        {
            puts("\n[*] Done !");
            break;
        }
        putchar('.');
        decode_base85(ans);
        memset(page, 0, ALLOC_SIZE);
    } while (1);

    char* tmp = 0;
    char* src = strdup(clazz_file);
    *strchr(src, '.') = 0;
    asprintf(&tmp, "%s_decoded.class", src);
    copy_file(tmp, TEMP_CLASS);
    free(tmp);
    free(src);
    munmap(page, ALLOC_SIZE);
    unlink(TEMP_CLASS);
}

int
main(int argc, char *argv[])
{
    char name[] = "VerifierX.class";
    for (int i = 0; i < 8; ++i) {
        name[8] = 0x30+i;
        decode_class(name);
    }
    return 0;
}
```