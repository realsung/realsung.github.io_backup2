---
title: "AceBear Security Contest - HackSpeed"
date: 2018-01-31 09:24:00
categories: [ctf]
tags: [ctf]
---

<!--more-->
This is a nice crackme of 1000 points (964 now, as 7 teams have already solved it)

![Image](/images/acebear/status.png)

Let's open the file in radare

![Image0](/images/acebear/radare.png)

We can clearly see that it invokes **NtQueryInformationProcess** to check if the executable is being run in a debugger. If not, it sets up a keyboard hook and starts pumping messages.

Let's take a look at the hook callback.
The procedure checks if 'Enter' Key has been pressed otherwise it checks whether the key pressed is in the set [0-9a-z] and adds to a buffer at 0x4053f0 using the following code. A dword at 0x405428 keeps track of the number of characters added.

```x86asm
0x004012c4      8b0d28544000   mov ecx, dword [0x405428]
0x004012ca      83c408         add esp, 8
0x004012cd      a00c544000     mov al, byte [0x40540c]
0x004012d2      8881f0534000   mov byte [ecx + 0x4053f0], al
0x004012d8      41             inc ecx
0x004012d9      890d28544000   mov dword [0x405428], ecx

0x00401323      a128544000     mov eax, dword [0x405428]
0x00401328      83c404         add esp, 4
0x0040132b      83f814         cmp eax, 0x14
0x0040132e      730e           jae 0x40133e
0x00401330      c680f0534000.  mov byte [eax + 0x4053f0], 0     ; Terminate buffer
0x00401337      e824010000     call 0x401460                    ; Validation Routine
```

When Enter key is pressed and the count is not zero (count must be ≤ 20), the control is transferred to the validation routine @ 0x401460
If count is 16, we can see a beautiful tree printed by 0x401460. It then creates a Binary Search Tree using the characters at 0x4053f0

```x86asm
0x004014ff      8b1508544000   mov edx, dword [0x405408]
0x00401505      33f6           xor esi, esi
0x0040150a      393528544000   cmp dword [0x405428], esi
0x00401507      83c438         add esp, 0x38
0x00401510      7e51           jle 0x401563
0x00401512      57             push edi
0x00401513      0fbebef05340.  movsx edi, byte [esi + 0x4053f0]
0x0040151a      85d2           test edx, edx
0x0040151c      7524           jne 0x401542
0x0040151e      6a0c           push 0xc
0x00401520      e824060000     call fcn.00401b49           ; malloc
0x00401525      8bd0           mov edx, eax
0x00401527      83c404         add esp, 4
0x0040152a      893a           mov dword [edx], edi        ; create new node
0x0040152c      c74204000000.  mov dword [edx + 4], 0
0x00401533      c74208000000.  mov dword [edx + 8], 0
0x0040153a      891508544000   mov dword [0x405408], edx
0x00401540      eb17           jmp 0x401559
0x00401542      8d4a04         lea ecx, [edx + 4]
0x00401545      393a           cmp dword [edx], edi
0x00401547      7f03           jg 0x40154c
0x00401549      8d4a08         lea ecx, [edx + 8]
0x0040154c      8bd7           mov edx, edi
0x0040154e      e8edfaffff     call fcn.00401040           ; insert_into_BST
0x00401553      8b1508544000   mov edx, dword [0x405408]
0x00401559      46             inc esi
0x0040155a      3b3528544000   cmp esi, dword [0x405428]
0x00401560      7cb1           jl 0x401513
```

Here's the structure of node, left is pointer to left subtree and right is pointer to right subtree and the value stored in the current node is data.

```c
struct node_t
{
    int32_t data;
    struct node_t* left;
    struct node_t* right;
};
```

The root of the BST is stored at 0x405408. If root is NULL then the first character inserted into the BST is made the root and for the other characters in the buffer, we have

```c
// ...
ptr = &root->left;
if (buffer[current] >= root->data)
    ptr = &root->right;

    insert_into_BST(ptr, buffer[current]);
    // ...

void insert_into_BST(TREE** ptr, char data)
{
    TREE** curr = ptr;
    while (*curr) {
        if (data >= curr[0]->data)
            curr = &curr[0]->right;
        else
            curr = &curr[0]->left;
    }
    TREE* node = malloc(12);
    node->data = data;
    node->left = node->right = NULL;
    *curr = node;
}
```

Well, this is a very common routine. Can you identify it ?

```x86asm
0x00401563      5e             pop esi
0x00401564      85d2           test edx, edx             ; root of BST
0x00401566      7426           je 0x40158e
0x00401568      8b4a04         mov ecx, dword [edx + 4]  ; left subtree
0x0040156b      e820fbffff     call fcn.00401090
0x00401570      8b4a08         mov ecx, dword [edx + 8]  ; right subtree
0x00401573      e818fbffff     call fcn.00401090
0x00401578      8b0d20544000   mov ecx, dword [0x405420]
0x0040157e      8b02           mov eax, dword [edx]
0x00401580      89048d305440.  mov dword [ecx*4 + 0x405430], eax
0x00401587      41             inc ecx
0x00401588      890d20544000   mov dword [0x405420], ecx
; ......
; What does the following routine do ??
; ......
0x00401090      56             push esi
0x00401091      8bf1           mov esi, ecx
0x00401093      85f6           test esi, esi
0x00401095      7426           je 0x4010bd
0x00401097      8b4e04         mov ecx, dword [esi + 4]
0x0040109a      e8f1ffffff     call fcn.00401090
0x0040109f      8b4e08         mov ecx, dword [esi + 8]
0x004010a2      e8e9ffffff     call fcn.00401090
0x004010a7      8b0d20544000   mov ecx, dword [0x405420]
0x004010ad      8b06           mov eax, dword [esi]
0x004010af      89048d305440.  mov dword [ecx*4 + 0x405430], eax
0x004010b6      41             inc ecx
0x004010b7      890d20544000   mov dword [0x405420], ecx
0x004010bd      5e             pop esi
0x004010be      c3             ret
```

Yes the routine performs the postorder traversal of Binary Search Tree. And the postorder traversal sequence is stored at 0x405430 and the number of characters are stored in 0x405420. Lets call the postorder sequence as post\_seq.

```x86asm
0x0040158e      a130544000     mov eax, dword [0x405430]  ; post_seq[0]
0x00401593      8b0d34544000   mov ecx, dword [0x405434]  ; post_seq[1]
0x00401599      33c1           xor eax, ecx
0x0040159b      83f804         cmp eax, 4
0x0040159e      7555           jne 0x4015f5               ; bad jump
0x004015a0      a138544000     mov eax, dword [0x405438]  ; post_seq[2]
0x004015a5      33c1           xor eax, ecx               ; post_seq[1]
0x004015a7      83f807         cmp eax, 7
0x004015aa      7549           jne 0x4015f5               ; prints "GoodBye"
0x004015ac      a13c544000     mov eax, dword [0x40543c]  ; post_seq[3]
0x004015b1      330540544000   xor eax, dword [0x405440]  ; post_seq[4]
0x004015b7      83f808         cmp eax, 8
0x004015ba      7539           jne 0x4015f5               ; and exits
0x004015bc      a144544000     mov eax, dword [0x405444]  ; post_seq[5]
0x004015c1      330548544000   xor eax, dword [0x405448]  ; post_seq[6]
0x004015c7      83f850         cmp eax, 0x50
0x004015ca      7529           jne 0x4015f5
0x004015cc      a154544000     mov eax, dword [0x405454]  ; post_seq[9]
0x004015d1      8b0d58544000   mov ecx, dword [0x405458]  ; post_seq[10]
0x004015d7      33c1           xor eax, ecx
0x004015d9      83f819         cmp eax, 0x19
0x004015dc      7517           jne 0x4015f5
0x004015de      a160544000     mov eax, dword [0x405460]  ; post_seq[12]
0x004015e3      33c1           xor eax, ecx               ; post_seq[10]
0x004015e5      83f802         cmp eax, 2
0x004015e8      750b           jne 0x4015f5

0x0040160a      e811fdffff     call check2
0x0040160f      85c0           test eax, eax
0x00401611      7425           je 0x401638
0x00401613      e8f8fdffff     call fcn.00401410  ; Check #3
0x00401618      85c0           test eax, eax
0x0040161a      741c           je 0x401638
0x0040161c      eb1b           jmp 0x401639

0x00401639      e8c2fcffff     call sub.Submit_flag_this:_ACEBEAR__s_300
```

So if the following condition is true we can proceed to our Good Boy message

```
post_seq[0] ^ post_seq[1] == 4
post_seq[1] ^ post_seq[2] == 7
post_seq[3] ^ post_seq[4] == 8
post_seq[5] ^ post_seq[6] == 0x50
post_seq[9] ^ post_seq[10] == 0x19
post_seq[10] ^ post_seq[12] == 2
```

Well we have another check at 'check2'

```x86asm
0x0040134e      bb00010000     mov ebx, 0x100
0x00401353      8bf8           mov edi, eax
0x00401355      8d0437         lea eax, [edi + esi]
0x00401358      50             push eax
0x00401359      ff150c314000   call dword [sym.imp.srand]
0x0040135f      83c404         add esp, 4
0x00401362      ff1510314000   call dword [sym.imp.rand]
0x00401368      8806           mov byte [esi], al
0x0040136a      8d7601         lea esi, [esi + 1]
0x0040136d      83eb01         sub ebx, 1
0x00401370      75e3           jne 0x401355
0x00401372      8b3528544000   mov esi, dword [0x405428]
0x00401378      33d2           xor edx, edx
0x0040137a      8b7de4         mov edi, dword [ebp-0x1C]
0x0040137d      c745ecf6e7e3.  mov dword [ebp-0x14], 0xf8e3e7f6
0x00401384      c745f0dde316.  mov dword [ebp-0x10], 0x1d16e3dd
0x0040138b      c745f4e6ecec.  mov dword [ebp-0x0C], 0xccecece6
0x00401392      c745f8e7e0e9.  mov dword [ebp-0x08], 0x7e9e0e7
0x00401399      85f6           test esi, esi
0x0040139b      7e1e           jle 0x4013bb
0x0040139d      0f1f00         nop dword [eax]

0x004013a0      8b0495305440.  mov eax, dword [edx*4 + 0x405430]
0x004013a7      0fb60c38       movzx ecx, byte [eax + edi]
0x004013ab      33c8           xor ecx, eax
0x004013ad      0fb64415ec     movzx eax, byte [ebp + edx - 0x14]
0x004013b2      3bc8           cmp ecx, eax
0x004013b4      7526           jne 0x4013dc
0x004013b6      42             inc edx
0x004013b7      3bd6           cmp edx, esi
0x004013b9      7ce5           jl 0x4013a0
```

The above snippet works like this

```c
char mem[256];

for (int i = 0; i < 256; ++i) {
    srand(i+1);
    mem[i] = rand() & 0xFF;
}

char buf[] = {
    0xf6, 0xe7, 0xe3, 0xf8,
    0xdd, 0xe3, 0x16, 0x1d,
    0xe6, 0xec, 0xec, 0xcc,
    0xe7, 0xe0, 0xe9, 0x07
};

for (int i = 0; i < count; ++i) {
    if (buf[i] != mem[post_seq[i]]^post_seq[i]) {
        printf("Noob\n");
        // exit ...
    }
}
```

From validation  #2, we can generate some postorder sequences. But one one of such sequences is valid. We need to use Visual C++ Compiler for rand() since libc's rand would not generate same sequences

```c
/*
 * Author : x0r19x91
 * Compile with MSVC
*/

int main()
{
    char mem[256];
    for (int i = 0; i < 256; ++i) {
        srand(i+1);
        mem[i] = rand()&0xFF;
    }
    char set[] = "0123456789abcdefghijklmnopqrstuvwxyz";

    char buf[] = {
        0xf6, 0xe7, 0xe3, 0xf8,
        0xdd, 0xe3, 0x16, 0x1d,
        0xe6, 0xec, 0xec, 0xcc,
        0xe7, 0xe0, 0xe9, 0x07
    };
    for (int count = 0; count < 16; ++count) {
        char f = 0;
        printf("[*] Offset %d -> ", count);
        for (int i = 0; count < 16 && i < 36; ++i) {
            if (buf[count] == (set[i]^mem[set[i]])) {
                printf("%c ", set[i]);
                f = 1;
            }
        }
        putchar(10);
    }
}
```

Here's the output

```
[*] Offset 0 -> 0
[*] Offset 1 -> 4 p
[*] Offset 2 -> 3 5
[*] Offset 3 -> 1
[*] Offset 4 -> 9 v
[*] Offset 5 -> 3 5
[*] Offset 6 -> e
[*] Offset 7 -> g
[*] Offset 8 -> l
[*] Offset 9 -> 6 k r
[*] Offset 10 -> 6 k r
[*] Offset 11 -> y
[*] Offset 12 -> 4 p
[*] Offset 13 -> m
[*] Offset 14 -> i
[*] Offset 15 -> a
```

There can be 2\*\*5\*9 = 288 postorder sequences. Applying Validation Check \#1, we get **"043195eglkrypmia"** as the postorder sequence. Given a postorder sequence, there can be many sequences which generate the same postorder.

Let's see the last validation check - Validation Check \#3 at fcn.00401410

```x86asm
0x00401420      c745ec51015a.  mov dword [ebp-0x14], 0x5c5a0151
0x00401427      33c0           xor eax, eax
0x00401429      c745f0490456.  mov dword [ebp-0x10], 0xc560449
0x00401430      c745f458121e.  mov dword [ebp-0x0C], 0x491e1258
0x00401437      c745f817540c.  mov dword [ebp-0x08], 0x130c5417
0x0040143e      6690           nop

0x00401440      8a0c85305440.  mov cl, byte [eax*4 + 0x405430]
0x00401447      3288f0534000   xor cl, byte [eax + 0x4053f0]
0x0040144d      3a4c05ec       cmp cl, byte [ebp + eax - 0x14]
0x00401451      7519           jne 0x40146c
0x00401453      40             inc eax
0x00401454      83f810         cmp eax, 0x10
0x00401457      7ce7           jl 0x401440
```

This is very simple

```
post_seq[i]^input_seq[i] == buffer[i] for i in range(16)
```

where 'input\_seq' is the array of alphanumeric characters we entered as input and 'buffer' is an array of 16 bytes at ebp-0x14

We x0r our postorder sequence with the bytes at ebp-0x14 to get our input - **"a5imp13k4yl0g9er"**.
So, our flag is **"ACEBEAR{a5imp13k4yl0g9er}"**
