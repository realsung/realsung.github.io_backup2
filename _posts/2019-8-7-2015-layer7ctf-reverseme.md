---
title: "2015 Layer7 CTF ReverseM"
date: 2019-8-7
tags: [CTF]
categories: [CTF]
---

 `로꾸꺼` 는 2015년 Layer7 CTF에서라는 리버싱 150점짜리 문제이다.

`ReverseMe.mp3` 라는 파일이 주어졌다. 근데 이 mp3를 열어보면 로꾸꺼 노래가 나오고 정말 수상햇다. 

```python
f = open('ReverseMe.mp3','rb')
f2 = open("ReverseMe.exe","wb")
data = f.read()
f.close()
f2.write(data[::-1])
f2.close()
```

hex 값을 보니까 PE 헤더가 다 로꾸꺼하게 되있어서 우선 파일의 값을 다 로꾸꺼해주었다.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  printf("input : ");
  scanf("%s", &hostlong);
  if ( sub_401060() )
  {
    printf("Correct !\n");
    printf("flag is %s\n", &hostlong);
  }
  else
  {
    printf("InCorrect ..");
  }
  return 0;
}
```

main의 흐름은 입력받아 입력 받은 값이 맞는지 비교해주고 Correct ! 떠서 맞으면 입력한 값이 플래그다.

```c
BOOL sub_401060()
{
  u_long v1; // edi
  u_long v2; // ebx
  signed int v3; // esi
  int v4; // edi
  unsigned int v5; // eax
  int v6; // eax

  if ( strlen(&hostlong) != 8 )
    return 0;
  v1 = dword_40336C;
  v2 = htonl(hostlong);
  v3 = 0;
  v4 = htonl(v1);
  do
  {
    switch ( v3 )
    {
      case 0:
        v5 = sub_401110(v4);
        goto LABEL_9;
      case 1:
        v5 = sub_401160(v4);
        goto LABEL_9;
      case 2:
        v5 = sub_4011B0(v4);
        goto LABEL_9;
      case 4:
        v5 = sub_401200(v4);
LABEL_9:
        v2 ^= v5;
        break;
      default:
        break;
    }
    v6 = v2;
    ++v3;
    v2 = v4;
    v4 = v6;
  }
  while ( v3 < 4 );
  return v6 == 0x72659830 && v2 == 0x64C38B40;
}
```

우선 8바이트를 input 받는다는걸 알았다. 그리고 htonl 함수를 써서 4바이트씩 나눠서 연산하는 것 같다.

- 참고

```c
u_long htonl(u_long hostlong); 
unsigned int a = 0x12345678;
printf("%#x %#x\n",a, htonl(a));
>> 0x12345678 0x56781234
```

그래서 `AAAABBBB` 를 입력해주고 마지막 리턴해줄 때 참을 만들어야한다.

앞에 `AAAA` 4바이트를 입력한건 어떠한 연산을 하고 eax에 저장한 후 v6와 비교한다.

뒤에 `BBBB` 4바이트를 입력한건 어떠한 연산을 하고 ebx에 저장한 후 v2와 비교한다.

디버깅해보면서 마지막에 비교할 때 eax 값을 보니까 `0x4141BE14` 였는데 

앞에 두 글자는 그대로 들어가고 뒤에 두 글자는 어떠한 연산을 해서 나온다는 걸 알 수 있다.

그리고 ebx 값을 보면 `0x42E8BD42` 이런식으로 들어가는데

첫 글자와 마지막 글자만 입력한 그대로 들어가는 것 같다.

이번에는 `BBBBAAAA` 를 넣게되면 eax는 `0x4242BD17` , ebx는 `0x41EBBE0x41` 이렇게 들어가있다. 

그래서 현재까지 알아낸건 아래와 같다.

```
flag[0] = 0x72
flag[1] = 0x65
flag[4] = 0x64
flag[7] = 0x40 
flag = 're??d??@'
```

현재까지 `re??d??@` 4글자 알아냈다.

나머지는 xor 연산을 해주는걸 알게되었다.

`0x4141` 2바이트 입력하게되면 `0xBE14` 가 나온다. 그러면 역연산을 하면 된다. 

```
0xBE14 ^ 0x4141 = 65365
0xBD16 ^ 0x4242 = 65365
```

그러면 이제 입력한 값과 65365와 xor한 값이 0x9830이 나와야한다.

```
0x9830 ^ 65365 = 0x6765 
```

그러므로 2번째 인덱스의 값은 0x67(g), 3번째 인덱스의 값은 0x65(e)이다.

현재까지 `reged??@` 이만큼 구했다. 이제 5,6번째 인덱스의 값만 구해주면 된다.

아까처럼 역연산해주면 된다.

```
0xE8BD ^ 0x4242 = 43775
0xEBBE ^ 0x4141 = 43775
```

이제 입력한 값과 43775와 xor한 값이 0xC38B이 나오면 된다.

```
0xc38b ^ 43775 = 0x6974
```

5번째 인덱스는 0x69(i), 6번째 인덱스는 0x74(t) 이다.

그러면 이제 다 구했다.

`regedit@` 을 입력하면 Correct가 뜰 것이다.

![](https://user-images.githubusercontent.com/32904385/62561352-f9262d00-b8b9-11e9-839b-6b0071f92de1.png)

**FLAG : `regedit@`**