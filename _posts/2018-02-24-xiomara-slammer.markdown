---
title: "Xiomara CTF - Slammer"
date: 2018-02-24 23:26:00
categories: [ctf]
tags: [ctf]
---

<!--more-->
Here we have an ELF binary whose code is xor encrypted with each character of the flag.  
The code looks like

```x86asm
;
; ...
    cmp byte [rcx], XX
    jz decode_next_part

bad_boy:
    mov eax, 1
    mov edi, 1
    mov rsi, 0x4000f3
    mov edx, 8
    syscall
    mov eax, 0x3c
    mov edi, 1
    syscall

decode_next_part:
    mov rax, qword [rcx]
    mov edi, LENGTH
    xor esi, esi

d_loop:
    cmp esi, edi
    je NEXT_ADDRESS
    xor byte [esi + NEXT_ADDRESS], al
    inc esi
    jmp d_loop

NEXT_ADDRESS:
; ...
;
```

where XX is a character in the flag, LENGTH is the number of bytes to decode in the next xored block, NEXT_ADDRESS denotes the starting address of the next block

So, each block of code decodes the next block of code validating each byte of the flag

```python

#!/usr/bin/python
# Task : slammer
# Author : x0r19x91

handle = open('slammer', 'rb')
data = map(ord, handle.read())
handle.close()

flag = ''
offset = 0
count = len(data)

while offset < len(data):

	# Search for cmp byte [rcx], XX ...
	pos = offset
	while pos < offset+count-3:
		if data[pos] == 0x80 and data[pos+1] == 0x39:
			next_char = chr(data[pos+2])
			flag += next_char
			break
		pos += 1

	if pos == offset+count-3:
		# [!] No Comparison Found !
		break

	# Find count value
	while pos < offset+count-3:
		if data[pos] == 0x48 and data[pos+1] == 0x8b and data[pos+2] == 1:
			break
		pos += 1

	if data[pos+3] == 0xBF and data[pos+12] == 0x74:
		count = data[pos+7]
		count = (count << 8) | data[pos+6]
		count = (count << 8) | data[pos+5]
		count = (count << 8) | data[pos+4]
		offset = pos+14+data[pos+13]

		for i in xrange(count):
			data[i+offset] ^= ord(flag[-1])

	else:
		# [!] No "mov edi, XXX" instr found !
		break

print '[*] Flag : %s' % flag
handle = open('final_binary', 'wb')
handle.write(''.join(map(chr, data)))
handle.close()
```

And, here's the flag

**xiomara{cool\_thumbs\_up\_if\_solved\_using\_r2pipe}**

but I think, I didn't get a :)
