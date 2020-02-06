---
title: "2019 X-MAS CTF Discount VMProtect"
date: 2020-2-7
tags: [X-MAS]
categories: [X-MAS]
---

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  printf("Enter password: ", a2, a3);
  memset(s, 0, 256uLL);
  fgets(s, 255, stdin);
  if ( s[0] )
    s[strlen(s) - 1] = 0;
  sub_400857();
  sub_400857();
  if ( byte_6025A0[0] == 1 )
    puts("Yay, you got the flag!");
  else
    puts("NOOOOOOOOOOOOOOO!");
  return 0LL;
}
```

VM Create

0x2361ca를 스택으로 푸시 한 다음 0x636465로 XOR한다. XOR 후의 값은 0x40087f이고 가상화 코드들이 존재한다.

```
.text:0000000000400857 sub_400857 proc near                    ; CODE XREF: main+76↓p
.text:0000000000400857                                         ; main+82↓p
.text:0000000000400857
.text:0000000000400857 var_38= qword ptr -38h
.text:0000000000400857 var_28= qword ptr -28h
.text:0000000000400857 var_8= dword ptr -8
.text:0000000000400857 var_4= dword ptr -4
.text:0000000000400857
.text:0000000000400857 ; __unwind {
.text:0000000000400857 push    rbp
.text:0000000000400858 mov     rbp, rsp
.text:000000000040085B sub     rsp, 30h
.text:000000000040085F mov     [rbp+var_28], rdi
.text:0000000000400863 mov     [rbp+var_8], 0
.text:000000000040086A mov     [rbp+var_4], 0
.text:0000000000400871 push    236C1Ah
.text:0000000000400876 xor     [rsp+38h+var_38], 636465h
.text:000000000040087E retn
.text:000000000040087E sub_400857 endp ; sp-analysis failed
```

stack을 이용해 값들을 연산한다.

```c
// jumptable 00000000004008C3 default case
signed __int64 __usercall sub_40087F@<rax>(__int64 a1@<rbp>)
{
  int v1; // eax

  while ( 1 )
  {
    *(_BYTE *)(a1 - 23) = *(_BYTE *)((signed int)(*(_DWORD *)(a1 - 4))++ + *(_QWORD *)(a1 - 40));
    v1 = *(unsigned __int8 *)(a1 - 23);
    switch ( (unsigned int)off_400E38 )
    {
      case 0x30u:
        return 1LL;
      case 0x31u:
        *(_BYTE *)(a1 - 9) = *(_BYTE *)((signed int)(*(_DWORD *)(a1 - 4))++ + *(_QWORD *)(a1 - 40));
        *(_BYTE *)(a1 - 9) = byte_6025A0[*(unsigned __int8 *)(a1 - 9)];
        s[(*(_DWORD *)(a1 - 8))++ + 256] = *(_BYTE *)(a1 - 9);
        break;
      case 0x32u:
        s[*(signed int *)(a1 - 8) + 256] = s[*(_DWORD *)(a1 - 8) + 255];
        ++*(_DWORD *)(a1 - 8);
        break;
      case 0x33u:
        s[*(_DWORD *)(a1 - 8) + 255] = s[(unsigned __int8)s[*(_DWORD *)(a1 - 8) + 255]];
        break;
      case 0x34u:
        *(_BYTE *)(a1 - 10) = *(_BYTE *)((signed int)(*(_DWORD *)(a1 - 4))++ + *(_QWORD *)(a1 - 40));
        if ( !s[*(_DWORD *)(a1 - 8) + 255] )
          *(_DWORD *)(a1 - 4) = *(unsigned __int8 *)(a1 - 10);
        --*(_DWORD *)(a1 - 8);
        break;
      case 0x35u:
        *(_BYTE *)(a1 - 11) = s[*(_DWORD *)(a1 - 8) + 255];
        *(_BYTE *)(a1 - 11) = (*(_BYTE *)(a1 - 11) << 7) | ((signed int)*(unsigned __int8 *)(a1 - 11) >> 1);
        s[*(_DWORD *)(a1 - 8) + 255] = *(_BYTE *)(a1 - 11);
        break;
      case 0x36u:
        *(_BYTE *)(a1 - 12) = *(_BYTE *)((signed int)(*(_DWORD *)(a1 - 4))++ + *(_QWORD *)(a1 - 40));
        s[(*(_DWORD *)(a1 - 8))++ + 256] = *(_BYTE *)(a1 - 12);
        break;
      case 0x37u:
        *(_BYTE *)(a1 - 14) = s[*(_DWORD *)(a1 - 8) + 255];
        *(_BYTE *)(a1 - 13) = s[*(_DWORD *)(a1 - 8) + 254];
        *(_BYTE *)(a1 - 14) ^= *(_BYTE *)(a1 - 13);
        s[(*(_DWORD *)(a1 - 8))-- + 254] = *(_BYTE *)(a1 - 14);
        break;
      case 0x38u:
        *(_BYTE *)(a1 - 16) = s[*(_DWORD *)(a1 - 8) + 255];
        *(_BYTE *)(a1 - 15) = s[*(_DWORD *)(a1 - 8) + 254];
        *(_BYTE *)(a1 - 16) += *(_BYTE *)(a1 - 15);
        s[(*(_DWORD *)(a1 - 8))-- + 254] = *(_BYTE *)(a1 - 16);
        break;
      case 0x39u:
        *(_BYTE *)(a1 - 18) = s[*(_DWORD *)(a1 - 8) + 255];
        *(_BYTE *)(a1 - 17) = s[*(_DWORD *)(a1 - 8) + 254];
        *(_BYTE *)(a1 - 18) = *(_BYTE *)(a1 - 17) - *(_BYTE *)(a1 - 18);
        s[(*(_DWORD *)(a1 - 8))-- + 254] = *(_BYTE *)(a1 - 18);
        break;
      case 0x61u:
        *(_BYTE *)(a1 - 19) = s[*(_DWORD *)(a1 - 8) + 255];
        *(_BYTE *)(a1 - 19) = ~*(_BYTE *)(a1 - 19);
        s[*(_DWORD *)(a1 - 8) + 255] = *(_BYTE *)(a1 - 19);
        break;
      case 0x62u:
        if ( dword_602580 == 27 && ptrace(0, 0LL, 1LL, 0LL) == -1 )
        {
          puts("NOOOOOOOOOOOOOOO!");
          exit(0);
        }
        ++dword_602580;
        break;
      case 0x63u:
        byte_6025A0[0] = 1;
        strcpy(dest, &src);
        break;
      case 0x64u:
        *(_BYTE *)(a1 - 21) = *(_BYTE *)((signed int)(*(_DWORD *)(a1 - 4))++ + *(_QWORD *)(a1 - 40));
        *(_BYTE *)(a1 - 20) = s[(*(_DWORD *)(a1 - 8))-- + 255];
        byte_6025A0[*(unsigned __int8 *)(a1 - 21)] = *(_BYTE *)(a1 - 20);
        break;
      case 0x65u:
        *(_BYTE *)(a1 - 22) = s[*(_DWORD *)(a1 - 8) + 255];
        *(_BYTE *)(a1 - 22) = byte_6025A0[*(unsigned __int8 *)(a1 - 22)];
        s[*(_DWORD *)(a1 - 8) + 255] = *(_BYTE *)(a1 - 22);
        break;
      default:
        continue;
    }
  }
}
```

structure

```python
pc = 0 # a1-4
rbp_8 = 0 # a1-8
state = [] # a1-40 -> unk = bytes code
register = [0]*256
s = [0]*1280
dword_602580 = 0
# s = input
def case48(): # exit
	print 'return 1;'

def case49(): # push register
	# global pc; global rbp_8; global state; global
	a = state[pc]
	pc += 1
	b = regsiter[a]
	s[rbp_8 + 256] = b & 0xff
	rbp_8 += 1
	print '[{}] s[rbp_8 + 256] = register[{}]'.format(pc,a)
	print '[{}] rbp_8++'.format(pc)

def case50():
	s[rbp_8 + 256] = s[rbp_8 + 255]
	rbp_8 += 1
	print '[{}] s[rbp_8 + 256] = s[rbp_8 + 255]'.format(pc)

def case51():
	s[rbp_8 + 255] = s[s[rbp_8 + 255]]
	print '[{}] s[rbp_8 + 255] = s[s[rbp_8 + 255]]'.format(pc)

def case52():
	a = state[pc]
	pc += 1
	if s[rbp_8 + 255] == 0:
		pc = a
		rbp_8 -= 1
	print '[{}] if s[rbp_8+255] == 0: pc = state[{}]'.format(pc,pc-1)
	print '[{}] rbp_8--'.format(pc)

def case53():
	a = s[rbp_8 + 255]
	b = (a <<  7) | (a >> 1)
	s[rbp_8 + 255] = b & 0xff
	print '[{}] s[rbp_8 + 255] = (s[rbp_8 + 255] << 7) | (s[rbp_8 + 255] >> 1)'.format(pc)

def case54():
	a = state[pc]
	pc += 1
	s[rbp_8 + 256] = a & 0xff
	rbp_8 += 1
	print '[{}] s[rbp_8 + 256] = state[{}]'.format(pc,pc-1)
	print '[{}] rbp_8++'.format(pc)

def case55():
	a = s[rbp_8 + 255]
	b = s[rbp_8 + 254]
	a ^= b
	s[rbp_8 + 254] = a & 0xff
	rbp_8 -= 1
	print '[{}] s[rbp_8 + 254] ^= s[rbp_8 + 255]'.format(pc)
	print '[{}] rbp_8--'.format(pc)

def case56():
	a = s[rbp_8 + 255]
	b = s[rbp_8 + 254]
	a += b
	s[rbp_8 + 254] = a & 0xff
	rbp_8 -= 1
	print '[{}] s[rbp_8 + 254] += s[rbp_8 + 255]'.format(pc)
	print '[{}] rbp_8--'.format(pc)

def case57():
	a = s[rbp_8 + 255]
	b = s[rbp_8 + 254]
	a = b - a
	s[rbp_8 + 254] = a & 0xff
	rbp_8 -= 1
	print '[{}] s[rbp_8 + 254] -= s[rbp_8 + 255]'.format(pc)
	print '[{}] rbp_8--'.format(pc)

def case97():
	a = s[rbp_8 + 255]
	a = ~a
	s[rbp_8 + 255] = a & 0xff
	print '[{}] s[rbp_8 + 255] = ~s[rbp_8 + 255]'.format(pc)

def case98():
	global dword_602580
	dword_602580 += 1
	print 'Anti DEBUG'
	print '[{}] dword_602580++'.format(pc)

def case99():
	register[0] = 1
	print 'strcpy'

def case100():
	a = state[pc]
	pc += 1
	b = s[rbp_8 + 255]
	rbp_8 -= 1
	register[a] = b & 0xff
	print '[{}] register[state[{}]] = s[rbp_8 + 255]'.format(pc.pc-1)
	print '[{}] rbp_8--'.format(pc)

def case101():
	a = s[rbp_8 + 255]
	b = register[a]
	s[rbp_8 + 255] = b & 0xff
	print '[{}] s[rbp_8 + 255] = register[s[rbp_8 + 255]]'.format(pc)
```

src로 strcpy해주고 연산들 해준다. 가상화 코드를 애뮬레이팅하면 아래와 같은식으로 나온다.

```python
src = [0x18,0x72,0xa2,0xa4,0x9d,0x89,0x1f,0xa2,0x8d,0x9b,0x94,0x0d,0x6d,0x9b,0x95,0xec,0xec,0x12,0x9b,0x94,0x23,0x16,0x9b,0x6c,0x13,0x0e,0x6d,
0x0d,0x96,0x8d,0x0e,0x90,0x13,0x97,0x8a,0xbb,0xcf,0x64,0x7e,0xd3,0x1a,0x40,0x23,0xec,0xdf]
byte_6025A0[0] = 1
inpt = raw_input()
for i in range(35):
	a = inpt[i]
	a = ((a << 7) | (a >> 1))
	a = a & 0xff
	a ^= 99 
	a += 152
	a = a & 0xff
	a = ~a
	a = a & 0xff
	if a != src[i]:
		byte_6025A0[0] = 0
		break
if byte_6025A0[0] == 1:
	print "Yay, you got the flag!"
else:
	print "NOOOOOOOOOOOOOOO!"
```

BruteForce

> solve.py

```python
src = [0x18,0x72,0xa2,0xa4,0x9d,0x89,0x1f,0xa2,0x8d,0x9b,0x94,0x0d,0x6d,0x9b,0x95,0xec,0xec,0x12,0x9b,0x94,0x23,0x16,0x9b,0x6c,0x13,0x0e,0x6d,
0x0d,0x96,0x8d,0x0e,0x90,0x13,0x97,0x8a,0xbb,0xcf,0x64,0x7e,0xd3,0x1a,0x40,0x23,0xec,0xdf]
flag = ''
for i in range(len(src)):
	for j in range(128):
		a = ((j << 7) | (j >> 1))
		a &= 0xff
		a ^= 99
		a += 152
		a &= 0xff
		a = ~a
		a &= 0xff
		if a == src[i]:
			flag += chr(j)
			break
print flag
```

**FLAG : `X-MAS{VMs_ar3_c00l_aNd_1nt3resting}`**

