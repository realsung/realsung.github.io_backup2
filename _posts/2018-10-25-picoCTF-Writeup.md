---
title: 2018 Pico CTF Writeup
date: 2018-10-25
tags: [PicoCTF]
categories: [CTF]
---

> NickName : ind3x

> TeamName : sunrin

> Score : 16785

![](https://user-images.githubusercontent.com/32904385/47508115-71cd7700-d8ae-11e8-95c6-afd740577543.png)

### Forensics Warmup 1 - Point : 50 [Forensics]

압축 파일을 받고 열어보니 `flag.jpg`파일이 있었다.

![](https://user-images.githubusercontent.com/32904385/47508166-8b6ebe80-d8ae-11e8-833d-5616aedb76dd.jpg)

##### Flag : `picoCTF{Welcome_to_forensics}`

<br />

### Forensics Warmup 2 - Point : 50 [Forensics]

png 파일을 받았는데 `flag.png`에 flag가 적혀있었다.

![](https://user-images.githubusercontent.com/32904385/47508221-a6413300-d8ae-11e8-938a-780dcf6247f2.png)

##### Flag : `picoCTF{extensions_are_a_lie}`

<br />

### General Warmup 1 - Point : 50 [General Skills]

16진법 0x61을 아스키코드로 바꾸라고한다.

##### Flag : ` picoCTF{A}`

<br />

### General Warmup 2 - Point : 50 [General Skills]

10진수인 27을 2진수로 변환하라고 한다.

##### Flag : `picoCTF{11011}`

<br />

### General Warmup 3 - Point : 50 [General Skills]

0x3D를 10진수로 변환하라고 한다.

##### Flag : `picoCTF{61}`

<br />

### Resources - Point : 50 [General Skills]

웹 사이트에서 flag를 찾으라고 한다. 그냥 들어가서 command + f 누르고 picoCTF{} 플래그 형식검색했더니 나왔다.

##### Flag : ` picoCTF{xiexie_ni_lai_zheli}`

<br />

### Reversing Warmup 1 - Point : 50 [Reversing]

Radare2를 통해서 run 파일을 열고 확인해본 결과 `picoCTF{welc0m3_t0_r3VeRs1nG}` 라는 문구를 넘겨주고 있었다.

![](https://user-images.githubusercontent.com/32904385/47508258-ba853000-d8ae-11e8-8b2f-f267f783c40b.png)

##### Flag : `picoCTF{welc0m3_t0_r3VeRs1nG}`

<br />

### Reversing Warmup 2 - Point : 50 [Reversing]

dGg0dF93NHNfczFtcEwz 를 아스키형식으로 Base64 디코딩 하면 된다.

##### Flag : `picoCTF{th4t_w4s_s1mpL3}`

<br />

### Crypto Warmup 1 - Point : 50 [Cryptography]

`llkjmlmpadkkc` 를 키 값인 `thisisalilkey` 를 주고 답을 찾으라 한다. 키 값을 주고 문자열을 바꾸는 형식인 **Vigenere Cipher**를 참고해 풀었다.

##### Flag : `picoCTF{secretmessage}`

<br />

### Crypto Warmup 2 - Point : 50 [Cryptography]

`cvpbPGS{guvf_vf_pelcgb!}` 이런 문자가 주어졌는데 rot13으로 파이썬 코드 짜서 돌려줬다.

```python
import codecs
flag = codecs.encode('cvpbPGS{guvf_vf_pelcgb!}','rot_13')
print(flag)
```

##### Flag : `picoCTF{this_is_crypto!}`

<br />

### Grep 1 - Point : 75 [General Skills]

file이라는 이름의 파일이 주어졌는데 이 문제의 제목처럼 유닉스 계열의 명령어 grep으로 flag형식 문자열을 추출했다.

```
$ cat file | grep 'picoCTF'
picoCTF{grep_and_you_will_find_d66382d8}
```

##### Flag : `picoCTF{grep_and_you_will_find_d66382d8}`

<br />

### net cat - Point : 75 [General Skills]

nc 접속하는 법을 알면 쉽게 풀 수 있다. 쉽게 터미널 열어서 접속해주면 된다.

```
$ nc 2018shell2.picoctf.com 37721
That wasn't so hard was it?
picoCTF{NEtcat_iS_a_NEcESSiTy_0b4c4174}
```

##### Flag : `picoCTF{NEtcat_iS_a_NEcESSiTy_0b4c4174}`

<br />

### HEEEEEEERE'S Johnny! - Points : 100 [Cryptography]

passwd 파일을 칼리리눅스에서 Johnny이였나 거기에 넣어주고 하면 root계정의 비밀번호가 나온다.

##### Flag : `picoCTF{J0hn_1$_R1pp3d_289677b5}`

<br />

### strings - Point : 100 [General Skills]

유닉스 명령어 strings만 사용할 줄 알면 쉽게 풀 수 있다.

```
$ strings strings | grep pico
picoCTF{sTrIngS_sAVeS_Time_d3ffa29c}
```

##### Flag : `picoCTF{sTrIngS_sAVeS_Time_d3ffa29c}`

<br />

### pipe - Point : 110 [General Skills]

nc 서버로 접속하고 파이프를 사용해서 grep으로 문자열을 찾아줬다.

```
$ nc 2018shell2.picoctf.com 44310 | grep pico
picoCTF{almost_like_mario_a13e5b27}
```

##### Flag : `picoCTF{almost_like_mario_a13e5b27}`

<br />

### Inspect Me - Point : 125 [Web Exploitation]

개발자도구를 들어가서 sources를 보면 html css js 소스가 있다. 소스를 확인해본 결과 flag가 주석처리 되어있다.

![](https://user-images.githubusercontent.com/32904385/47508291-c83ab580-d8ae-11e8-99a2-21a02ad06a5f.png)

![](https://user-images.githubusercontent.com/32904385/47508267-bd802080-d8ae-11e8-80db-e379c3be1d72.png)

##### Flag : `picoCTF{ur_4_real_1nspect0r_g4dget_b4887011}`

<br />

### grep2 - Point : 125 [General Skills]

쉘 서버에 grep을 사용해서 풀었다. `/problems/grep-2_3_826f886f547acb8a9c3fccb030e8168d/` 안에 엄청 수 많은 폴더들이 있었다. grep의 -r 옵션이 하위 디렉토리의 파일들의 문자열을 찾아준다.

```
$ grep -r pico
files/files2/file20:picoCTF{grep_r_and_you_will_find_556620f7}
```

##### Flag : `picoCTF{grep_r_and_you_will_find_556620f7}` 

<br />

### Client Side is Still Bad - Point : 150 [Web Exploitation]

딱 웹 사이트 들어가자마자 Secure Login Sever를 들어가려면 자격이 필요하다나.. 그래서 소스를 보니 자바스크립트가 있었다.

자바스크립트를 보면 verify라는 함수에서 입력 조건이 써있어서 그대로 써주고 그 입력 조건이 맞으면 alert 뜨게 하는거였다. `picoCTF{client_is_bad_9117e9}` 이걸 넣어주면 You got the flag! 틀리면 Incorrect password라고 뜬다.

##### Flag : `picoCTF{client_is_bad_9117e9}`

<br />

### Recovering From the Snap - Point : 150 [Forensics]

animals.dd 파일을 받았는데 용량이 10MB나 됐다... 먼저 시그니처를 별다른게 없어서 밑으로 조금 내리다가 보니까 오프셋 `9A00` 에서 `FF D8 FF E0 00 10 4A 46 49 46` jpg 시그니처를 확인하고는 animals.dd파일 안에 여러 이미지가 담겨 있는 것을 알게되었다.  

jpg의 푸터 시그니처인 `FF D9`를 찾았다. 오프셋 `A400`까지였다. 9A00 ~ A400까지 한 이미지를 추출해냈다. 

하지만 이 그림에는 flag가 없었다. 이런 문제는 보통 그림에 photoshop을 사용해서 들어간다. 

그래서 photoshop이라는 텍스트를 검색해서 photoshop이 포함되어있는 jpg 파일을 추출해냈다.

 오프셋 `2DCA00` 부터 `2E67B0` 까지였다. 이 오프셋 범위만 따로 추출해냈더니 flag 이미지가 나왔다.

![](https://user-images.githubusercontent.com/32904385/47508293-c8d34c00-d8ae-11e8-9347-ace7349c4aec.png)

##### Flag : `picoCTF{th3_5n4p_happ3n3d}`

<br />

### admin panel - Point : 150 [Forensics]

data.pcap 파일을 내려받아서 `wireshark` 를 이용해 pcap 폴더를 열었다. 여기서 프로토콜이 HTTP인 것을 확인해보니 login, logout, %2f, admin 등등 여러 패킷이 전송된 것을 볼 수 있었다. 이 패킷들을 따로 추출해서 확인해봤다.

텍스트파일중 login(2)를 확인해봤더니 flag가 적혀있었다. `user=admin&password=picoCTF{n0ts3cur3_df598569}` 

##### Flag : `picoCTF{n0ts3cur3_df598569}`

<br />

### caesar cipher 1 - Point : 150 [Cryptography]

ciphertext라는 text파일을 받고 열어본 결과 `picoCTF{grpqxdllaliazxbpxozfmebotlvlicmr}` 이렇게 나와있는데 대괄호 안을 카이사르 암호로 치환하면 된다. 파이썬 코드로 돌렸더니 ROT23번째가 flag였다.

```python
def translate(string, key, mode):
    translated_string = ""
 
    if mode == 'decrypt':
        key = -key
 
    for char in string:
        if char.isalpha():
            num = ord(char)
            num += key
 
            if char.isupper():
                if num > ord('Z'):
                    num -= 26
                elif num < ord('A'):
                    num += 26
            elif char.islower():
                if num > ord('z'):
                    num -= 26
                elif num < ord('a'):
                    num += 26
            translated_string += chr(num)
        else:
            translated_string += char
    return translated_string

encrypted = 'grpqxdllaliazxbpxozfmebotlvlicmr' # input
for i in range(1, 26):
    decrypted = translate(encrypted, i, 'decrypt')
    print ("".join(['ROT', str(i), ': ', decrypted]))
```

##### Flag : `picoCTF{justagoodoldcaesarcipherwoyolfpu}`

<br />

### environ - Points : 150 [General Skills]

유닉스 셸 명령어 env를 이용해서 환경변수를 확인했다.

```
$ env | grep pico
SECRET_FLAG=picoCTF{eNv1r0nM3nT_v4r14Bl3_fL4g_3758492}
```

##### Flag : `picoCTF{eNv1r0nM3nT_v4r14Bl3_fL4g_3758492}`

<br />

### hex editor - Points : 150 [Forensics]

HxD로 Find로 pico 형식을 입력하니까 바로 나왔다. 

##### Flag : `picoCTF{and_thats_how_u_edit_hex_kittos_8BcA67a2}`

<br />

### Secret Agent - Points : 200 [Web Exploitation]

시크릿 에이전트를 사용할 줄 몰라서 시간 엄청 뺏긴 문제다. `http://2018shell2.picoctf.com:3827/flag` 이 링크에서 flag를 누르면 이상한게 뜨는데 내가 사용하는 크롬,웨일,사파리 등등 뜨길래 당황했다. 정말 이런 문제 처음 접해봤지만 신기했다. flag를 누르면 너는 구글이 아니라고 뜨길래 구글에서 엄청 찾다가 `구글 봇`이라는 걸 찾았다. 내가 사용하고있는 에이전트를 구글 봇으로 바꿔주면 된다. 

개발자모드(F12) 들어가서 NetWork 들어가서 밑에 콘솔창 옆에 점 세개 있는거 누르고 NetWork Conditions 누르고 거기서 에이전트를 구글봇으로 바꿔주고 다시 웹 사이트 접속해서 FLAG 눌러주면 flag가 나온다.

![](https://user-images.githubusercontent.com/32904385/47508295-c96be280-d8ae-11e8-8be8-06e24e61a4e1.png)

##### Flag : `picoCTF{s3cr3t_ag3nt_m4n_12387c22}`

<br />

### Truly an Artist - Points : 200 [Forensics]

HxD로 pico형식 찾으니까 바로 나왔다.

##### Flag : `picoCTF{look_in_image_7e31505f}`

<br />

### now you don't - Points : 200 [Forensics]

배경이 완전히 빨강색이고 PNG이길래 그림판으로 색을 덮어줬더니 Flag가 나왔다.

![](https://user-images.githubusercontent.com/32904385/47508296-ca047900-d8ae-11e8-9f9b-fd2602a42efe.png)

##### Flag : `picoCTF{n0w_y0u_533_m3}`

<br />

#### what base is this? - Points : 200 [General Skills]

nc로 접속하면 진수를 아스키코드를 30초안에 바꾸라고 나온다. 쉽게 쓱싹 바꿔줬다.

```
$ nc 2018shell2.picoctf.com 1225
We are going to start at the very beginning and make sure you understand how data is stored.
apple
Please give me the 01100001 01110000 01110000 01101100 01100101 as a word.
To make things interesting, you have 30 seconds.
Input:
 apple
Please give me the 67696d70 as a word.
Input:
gimp
Please give me the  164 165 162 164 154 145 as a word.
Input:
turtle
You got it! You're super quick!
Flag: picoCTF{delusions_about_finding_values_451a9a74}
```

<br />

### store - Points : 400 [General Skills]

r2 열어서 분석했더니 쉽게 나왔다. 

이런게 400점이나…

##### Flag : `picoCTF{numb3r3_4r3nt_s4f3_cbb7151f}`

<br />

### quackme - Points : 200 [Reversing]

주소의 값을 가져와서 xor 연산해주면 된다. 여기서 알게된 점이 flag 형식을 통해 문제를 푸는 방법을 듣고 좋은 팁을 알아갔다.

```python
table = [0x29, 0x6, 0x16, 0x4f, 0x2b, 0x35, 0x30, 0x1e, 0x51, 0x1b, 0x5b, 0x14, 0x4b, 0x8, 0x5d, 0x2b, 0x52, 0x17, 0x1, 0x57, 0x16, 0x11, 0x5c, 0x7, 0x5d]
flag = [0x59, 0x6f, 0x75, 0x20, 0x68, 0x61, 0x76, 0x65, 0x20, 0x6e, 0x6f, 0x77, 0x20, 0x65, 0x6e, 0x74, 0x65, 0x72, 0x65, 0x64, 0x20, 0x74, 0x68, 0x65, 0x20, 0x44, 0x75, 0x63, 0x6b]
answer = ""
for i in range(len(table)):
    answer += chr(table[i]^flag[i])
print(answer)
```

![](https://user-images.githubusercontent.com/32904385/47508294-c96be280-d8ae-11e8-9a2c-6f5174fbf160.png)

##### Flag : `picoCTF{qu4ckm3_7ed36e4b}`

<br />

### quackme up - Points : 350 [Reversing]

`11 80 20 E0 22 53 72 A1 01 41 55 20 A0 C0 25 E3 95 20 15 35 20 15 00 70 C1` 이 값이 나오도록 만들라고 해서 이 문제는 노가다로 1을 입력하면 05 이런식으로 나오길래 알파벳, 특수기호, 번호를 입력해서 값을 찾아서 일일이 매칭시켜줬다.

##### Flag : `picoCTF{qu4ckm3_8c02c0af}`

<br />

### 후기

우리반에서 보안 공부하는 애들과 함께 나간 대회이다. 이 기회를 통해 친구들과 재밌게 즐겼던거 같다. 포렌식 문제들은 거의 스테가노 문제였고 많이 풀었던 형식들이라 쉽게 풀 수 있었지만 어려운 포렌식 문제는 아직 능력이 안되서 그런지 풀지 못했다. 리버싱은 대회가 끝나고 친구의 도움으로 풀었다. 아직은 너무 부족하고 열심히 공부해서 내년에는 꼭 풀 수 있도록 해야겠다.q