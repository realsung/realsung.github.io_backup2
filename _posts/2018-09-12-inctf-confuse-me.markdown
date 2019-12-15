---
title:  "INCTF - Confuse Me"
date:   2018-09-12 21:04:23
categories: [ctf]
tags: [ctf]
---

<!--more-->
Fire up Radare and open the binary

![Image1](/images/confuseme/i0.png)

```x86asm
push   rbp
mov    rbp,rsp
sub    rsp,0x50
mov    rax,QWORD PTR fs:0x28

mov    QWORD PTR [rbp-0x8],rax
xor    eax,eax
mov    esi,0x40109b
mov    edi,0xb
call   0x4abd40
mov    BYTE PTR [rbp-0x20],0x4d        ; "MGNCHXWIZDJAOKPELYSFUTV"
mov    BYTE PTR [rbp-0x1f],0x47
mov    BYTE PTR [rbp-0x1e],0x4e
mov    BYTE PTR [rbp-0x1d],0x43
mov    BYTE PTR [rbp-0x1c],0x48
mov    BYTE PTR [rbp-0x1b],0x58
mov    BYTE PTR [rbp-0x1a],0x57
mov    BYTE PTR [rbp-0x19],0x49
mov    BYTE PTR [rbp-0x18],0x5a
mov    BYTE PTR [rbp-0x17],0x44
mov    BYTE PTR [rbp-0x16],0x4a
mov    BYTE PTR [rbp-0x15],0x41
mov    BYTE PTR [rbp-0x14],0x4f
mov    BYTE PTR [rbp-0x13],0x4b
mov    BYTE PTR [rbp-0x12],0x50
mov    BYTE PTR [rbp-0x11],0x45
mov    BYTE PTR [rbp-0x10],0x4c
mov    BYTE PTR [rbp-0xf],0x59
mov    BYTE PTR [rbp-0xe],0x53
mov    BYTE PTR [rbp-0xd],0x46
mov    BYTE PTR [rbp-0xc],0x55
mov    BYTE PTR [rbp-0xb],0x54
mov    BYTE PTR [rbp-0xa],0x56
mov    esi,0x54fa2a                     ; "Enter Input:"
mov    edi,0x7accc0
call   0x40e670
mov    DWORD PTR [rbp-0x48],0x0
loop_0:
    cmp    DWORD PTR [rbp-0x48],0x16
    jg     end_0
    lea    rdx,[rbp-0x40]
    mov    eax,DWORD PTR [rbp-0x48]
    cdqe   
    add    rax,rdx
    mov    rsi,rax
    mov    edi,0x7acde0
    call   0x408ca0
    add    DWORD PTR [rbp-0x48],0x1
    jmp    loop_0

end_0:
mov    eax,0x17
mov    DWORD PTR [rbp-0x44],eax
mov    edx,DWORD PTR [rbp-0x44]         ; length
lea    rcx,[rbp-0x40]
lea    rax,[rbp-0x20]
mov    rsi,rcx                          ; our input string
mov    rdi,rax                          ; magic string
call   check
mov    eax,DWORD PTR [rip+0x3aabc7]        # 0x7abd70
cmp    eax,0x17
jne    invalid_input
lea    rax,[rbp-0x40]
mov    rdi,rax
call   print_flag
jmp    finish

invalid_input:
    mov    esi,0x54fa25                ; "Nope"
    mov    edi,0x7accc0
    call   0x40e670

finish:
    mov    eax,0x0
    mov    rcx,QWORD PTR [rbp-0x8]
    xor    rcx,QWORD PTR fs:0x28

    je     $+7
    call   0x50a840
    leave  
    ret
```

The routine validates a string of length atleast 23 bytes using the magic string "MGNCHXWIZDJAOKPELYSFUTV".
Let's take a look at check routine.

```x86asm

│           0x00400eb4      55             push rbp
│           0x00400eb5      4889e5         mov rbp, rsp
│           0x00400eb8      4883ec30       sub rsp, 0x30               ; '0'
│           0x00400ebc      48897de8       mov qword [local_18h], rdi
│           0x00400ec0      488975e0       mov qword [local_20h], rsi
│           0x00400ec4      8955dc         mov dword [local_24h], edx
│           0x00400ec7      488b45e0       mov rax, qword [local_20h]
│           0x00400ecb      0fb600         movzx eax, byte [rax]
│           0x00400ece      0fbec8         movsx ecx, al
│           0x00400ed1      8b55dc         mov edx, dword [local_24h]
│           0x00400ed4      488b45e8       mov rax, qword [local_18h]
│           0x00400ed8      89ce           mov esi, ecx
│           0x00400eda      4889c7         mov rdi, rax
│           0x00400edd      e88cffffff     call fcn.00400e6e
│           0x00400ee2      8945fc         mov dword [local_4h], eax
│           0x00400ee5      837dfc00       cmp dword [local_4h], 0
│       ┌─< 0x00400ee9      741a           je 0x400f05
│       │   0x00400eeb      488b45e0       mov rax, qword [local_20h]
│       │   0x00400eef      488d4801       lea rcx, rax + 1            ; 1
│       │   0x00400ef3      8b55fc         mov edx, dword [local_4h]
│       │   0x00400ef6      488b45e8       mov rax, qword [local_18h]
│       │   0x00400efa      4889ce         mov rsi, rcx
│       │   0x00400efd      4889c7         mov rdi, rax
│       │   0x00400f00      e8afffffff     call fcn.00400eb4
│       └─> 0x00400f05      8b45dc         mov eax, dword [local_24h]
│           0x00400f08      83e801         sub eax, 1
│           0x00400f0b      3b45fc         cmp eax, dword [local_4h]
│       ┌─< 0x00400f0e      7434           je 0x400f44
│       │   0x00400f10      8b45dc         mov eax, dword [local_24h]
│       │   0x00400f13      2b45fc         sub eax, dword [local_4h]
│       │   0x00400f16      8d50ff         lea edx, rax - 1
│       │   0x00400f19      8b45fc         mov eax, dword [local_4h]
│       │   0x00400f1c      4898           cdqe
│       │   0x00400f1e      488d4801       lea rcx, rax + 1            ; 1
│       │   0x00400f22      488b45e0       mov rax, qword [local_20h]
│       │   0x00400f26      4801c1         add rcx, rax                ; '#'
│       │   0x00400f29      8b45fc         mov eax, dword [local_4h]
│       │   0x00400f2c      4898           cdqe
│       │   0x00400f2e      488d7001       lea rsi, rax + 1            ; 1
│       │   0x00400f32      488b45e8       mov rax, qword [local_18h]
│       │   0x00400f36      4801f0         add rax, rsi                ; '+'
│       │   0x00400f39      4889ce         mov rsi, rcx
│       │   0x00400f3c      4889c7         mov rdi, rax
│       │   0x00400f3f      e870ffffff     call fcn.00400eb4
│       └─> 0x00400f44      488b45e0       mov rax, qword [local_20h]
│           0x00400f48      0fb600         movzx eax, byte [rax]
│           0x00400f4b      0fbec0         movsx eax, al
│           0x00400f4e      89c7           mov edi, eax
│           0x00400f50      e869feffff     call fcn.00400dbe
│           0x00400f55      90             nop
│           0x00400f56      c9             leave
└           0x00400f57      c3             ret
```

The above routine is equivalent to the following

```c
int count = 0;
void match(char ch)  // fcn.00400dbe
{
    char buf[] = "MNGHCWZIJDXOPKLESUVTFYA";
    if (buf[count] == ch) ++count;
}

void check(char* str, char* answer, int n) // fcn.00400eb4
{
    int pos = find_char(str, answer[0], n);
    if (pos != 0)
        check(str, answer+1, pos);
    if (pos != n-1)
        check(str+pos+1, answer+pos+1, n-pos-1);
    match(answer[0]);
}

int main()
{
    char magic[] = "MGNCHXWIZDJAOKPELYSFUTV";
    char answer[1024];
    // read answer of length atleast 23 bytes
    check(magic, answer, 0x17);
    if (count == 0x17) {
      // print flag
    } else {
      // print "Nope"
    }
}
```

Let the value of count be 0x16. So we need to match only one character. Since count is 0x16, so the character expected is buf[count] = 'A'. So this must be the first character of answer.

The routine check finds the offset of the first character in the answer and splits the search into two halves. The first half must be a permutation of magic[0..pos] and the second half must be a permutation of magic[pos+1..0x16]. Now answer is 'A' :: {MGNCHXWIZDJ} :: {OKPELYSFUTV}.

Now we need to split using 'Y' because it's the second last match - 'A' :: {MGNCHXWIZDJ} :: 'Y' :: {OKPEL} :: {FSTUV}, and so on.

To simplify, lets see the first five characters of magic and buf.

magic[:5] = "MGNCH"
buf[:5] = "MNGHC"

We can make a binary tree

```
    C
   / \
{MGN} H
```

C is matched last, preceded by H which is preceded by G. We can observe that the character that is matched is the root of a subtree denoted by the magic string as

{left subtree of R} :: R :: {Right Subtree of R}

```
    C
   / \
  G   H
 / \
M   N
```

Therefore the required input is the preorder traversal of the binary tree where 'magic' denotes the _inorder traversal_ and 'buf' denotes the _postorder traversal_

```c
#include <stdio.h>

char magic[] = "MGNCHXWIZDJAOKPELYSFUTV";
char buffer[] = "MNGHCWZIJDXOPKLESUVTFYA";
char answer[sizeof magic];
int last = 0x16;
/*
 * Observation
 * ---------------------------------------------------------------------------
 * the count must be 0x17
 * Let the value of count be 0x16, i.e., the last char of buf
 * needs to be matched with the input's first character (backtrack)
 * and the routine terminates.
 * the last character of buf is 'A' which needs to be the first character
 * of our input.
 * With observation, one can find out that the magic string:
 * "MGNCHXWIZDJAOKPELYSFUTV" is the inorder traversal of a binary tree
 * and buf:"MNGHCWZIJDXOPKLESUVTFYA" is the postorder traversal of the binary
 * tree. The valid input is the preorder traversal
 * ---------------------------------------------------------------------------
 */

void solve(int low, int high, int index)
{
  if (low == high) {
    answer[index] = magic[low];
    --last;
  } else {
    char root = buffer[last];
    int pos = low;
    for (; pos <= high; ++pos) {
      if (magic[pos] == root) {
        last--;
        break;
      }
    }
    answer[index] = root;
    solve(pos+1, high, pos-low+index+1);
    solve(low, pos-1, index+1);
  }
}

int main(int argc, char const *argv[]) {
  solve(0, last, 0);
  printf("[*] %s\n", answer);
  return 0;
}
```
And here's the output

![Output](/images/confuseme/i1.png)
