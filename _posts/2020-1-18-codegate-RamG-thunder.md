---
title: "2017 Codegate RamG thunder"
date: 2020-1-18
tags: [Codegate]
categories: [Codegate]
---

처음에서 4번을 누르면 hidden menu가 존재한다. 해당 hidden menu에서 2번을 누르면 Game을 플레이할 수 있다. 이 함수에서 마지막 보면 fwrite로 c라는 파일을 생성해주는데 여기까지 가면 플래그를 얻을 수 있다. 5개 스테이지를 넘기면 된다. 

이런 유형의 문제들은 보통 원하는 루틴을 다 건너가야지만 제대로된 파일을 생성할 수 있다. 각 Stage마다 c라는 파일을 만들어줄 데이터들을 넣게되는데 이 값들을 제대로 만들어줘야지 제대로된 파일이 생성될 수 있다.

## Stage 1

비교하는 부분이 있는데 테이블 긁어와서 xor해주면 된다. 또 뒤에 IsDebuggerPresent 우회해주면 된다. 

```python
# [*] Stage 1

v40 = '4D56594C58595541524A'.decode('hex')
v45 = '3437343539'.decode('hex')
stage1 = ''.join(chr(ord(v40[i])^ord(v45[i%5]))for i in range(len(v40)))
print stage1
```

**Stage 1 : `yamyambugs`**

<br />

## Stage 2

MAC주소 불러와서 비교하는데 dump 떠서 값만 변경해주면 된다.

```
ebx+0x194 : 0xc8
ebx+0x195 : 0x59
ebx+0x196 : 0x78
```

<br />

## Stage 3

레지스트리 불러와서 다 비교하는데 그냥 eip 우회해서 3가지 갈래길이 있는데 hel부분으로 가게하면 된다.

<br />

## Stage 4

`GetAdaptersInfo` 라는 API로 정보를 긁어오는데 그냥 각각 값을 0x0, 0xc, 0x29로 맞춰주면 우회할 수 있습니다.

Stage5가기전에 CheckRemoteDebuggerPresent도 우회해주면 된다.

<br />

## Stage 5

이 부분도 Stage 1과 마찬가지로 테이블 긁어와서 xor해주면 된다.

```python
# [*] Stage 5

v38 = '33363734323331303936'.decode('hex')
v36 = '5B535B585D4457594A5EEC'.decode('hex')
stage2 = ''.join(chr(ord(v38[i])^ord(v36[i])) for i in range(len(v38)))
print stage2
```

**Stage 5 : `hellowfish`**

<br />

![](https://user-images.githubusercontent.com/32904385/72642971-f5dab580-39b0-11ea-8fdb-a13f7bbc6cfb.png)

그러면 우리가 루틴을 지나면서 값들을 넣어준걸 가지고 값들을 슥슥 연산하는 부분이 있는데 이 부분만 분석해서 풀 수도 있다. 어쨌든 조건들 다 우회했으니까 c라는 파일을 생성해준다. 그리고 보면 PNG파일이 존재했다.

![](https://user-images.githubusercontent.com/32904385/72642999-0d19a300-39b1-11ea-8909-95158f4de0ed.png)

**FLAG : `ThANk_yOu_my_PeOP1E`**