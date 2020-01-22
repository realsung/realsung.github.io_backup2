---
title: "2018 ASIS CTF baby C"
date: 2020-1-22
tags: [ASIS]
categories: [ASIS]
---

`mov`, `jmp` 등 이런 instrucion만 이용한 [movfuscator](https://github.com/xoreaxeaxeax/movfuscator) 로 난독화된 바이너리다. 

이런 문제는 [demovfuscator ](https://github.com/kirschju/demovfuscator)를 이용해서 풀면 된다.

demov Option

```
-h 옵션 설명
-i 입력란에서 기호를 파생하여 기호.idc에 저장
-o 명시적 제어 흐름 및 일부 패치가 적용된 실행 파일 생성
-g 제어 흐름을 포함하는 UNIX 도트 호환 파일 생성
그래프(IDA의 그래프 보기보다 읽기 쉬울 수 있음)
.dot 파일을 사용 가능한 것으로 변환
cat cfg.dot | dot -Tpng > cfg.png
```

옵션을 하나씩 살펴보자

* -i Option

.idc파일로 저장해준다. IDA에서 해당 idc파일을 불러와서 적용해주면 보기 쉽게 바꿔준다.

```c
#include <idc.idc>

static main() {
	MakeName(0x804d050, "R0");
	MakeName(0x804d054, "R1");
	MakeName(0x804d058, "R2");
	MakeName(0x804d05c, "R3");
	MakeName(0x804d060, "R4");
	MakeName(0x804d064, "R5");
	MakeName(0x804d070, "D0");
	MakeName(0x804d078, "D1");
	MakeName(0x83f6160, "demov_sel_target");
	MakeName(0x804b4fb, "demov_end");
	MakeName(0x85f6300, "demov_DISCARD");
	MakeName(0x83f6174, "demov_SYM_DATA");
	MakeName(0x85f61c8, "demov_FAULT");
	MakeName(0x804bc94, "demov_end");
	MakeName(0x81f5b70, "demov_SYM_ALU_MUL_SUMS");
	MakeName(0x83f6168, "demov_target_reg");
	MakeName(0x804d100, "demov_SYM_ALU_TRUE");
	MakeName(0x83f6158, "demov_on");
	MakeName(0x83f6150, "demov_sel_on");
	MakeName(0x804d310, "demov_SYM_ALU_FALSE");
	MakeName(0x8048290, "demov_DISPATCH");
	MakeName(0x83f6130, "demov_esp");
	MakeName(0x8060f30, "demov_add");
	MakeName(0x8050600, "demov_equal");
	MakeName(0x804d0a0, "demov_bool_and");
	MakeName(0x83f6170, "demov_SYM_SEL_DATA");
	MakeName(0x8161050, "demov_SYM_ALU_INV16");
	MakeName(0x804f190, "demov_SYM_ALU_B7");
}
```

* -o Option

-o 옵션을 적용하면 필요없는 부분을 없애고 흐름을 쉽게 바꿔서 패치한 바이너리를 output한다.

* -g Option

아래와 같이 .dot파일을 생성해주는데 Control Flow Graph를 쉽게 보기위해 만들어주는 것이다. 이걸 토대로 해당 바이너리가 분기와 흐름이 어떻게 이루어지는지 볼 수 있다.

```
digraph fun_804899e {
node [shape = box];
0 [label="804899e"];
3 [label="8049853_f"];
4 [label="804b5d0"];
6 [label="8049b26_f"];
7 [label="804b3f6"];
9 [label="8049e50_f"];
11 [label="804a17a_f"];
13 [label="804a6fc_f"];
14 [label="804b21c"];
16 [label="804aa08_f"];
17 [label="804b042"];
18 [label="804b97c"];
0 -> 3 [label=false, color=red];
0 -> 4 [label=true, color=green];
3 -> 6 [label=false, color=red];
3 -> 7 [label=true, color=green];
4 -> 18;
6 -> 7 [label=true, color=green];
6 -> 9 [label=false, color=red];
7 -> 4;
9 -> 7 [label=true, color=green];
9 -> 11 [label=false, color=red];
11 -> 13 [label=false, color=red];
11 -> 14 [label=true, color=green];
13 -> 16 [label=false, color=red];
13 -> 17 [label=true, color=green];
14 -> 7;
16 -> 18 [label=jmp];
17 -> 14;
}

digraph calls {
}
```

이런식으로 .dot파일을 가지고 png로 변환해서 쉽게 볼 수 있다.

우선 graphviz를 다운로드해야된다. 

```
$ sudo apt install graphviz
```

그러면 아래와 같은식으로 옵션을 주면 

```
$ dot -Tpng <target.dot> -o <output.png>
```

![](https://user-images.githubusercontent.com/32904385/72902234-73fed980-3d6e-11ea-9208-a9cee84488ed.png)

이런식으로 흐름을 쉽게 볼 수 있다. 이외에도 [이 사이트](http://www.webgraphviz.com/) 에서도 .dot 코드만 있으면 쉽게 변환해준다.

```
$ demov -i babyc.idc -o patch -g cfg.dot ./babyc
```

나는 patch된 바이너리를 분석해서 풀었다.

```
.text:0804933D                 mov     eax, offset aM0vfu3c4t0r ; "m0vfu3c4t0r!"
.text:080498DB                 mov     dword_804D058, 41h ; 'A'
.text:08049C05                 mov     dword_804D058, 68h ; 'h'
.text:08049F2F                 mov     dword_804D058, 5Fh ; '_'
.text:0804A7BD                 mov     dword_804D058, 79306E6Eh ; 'nn0y'
```

결국엔 `Ah_m0vfu3c4t0r!..nn0y1ng:(` 를 입력하면 Correct :) 를 띄워준다.

**FLAG : `ASIS{574a1ebc69c34903a4631820f292d11fcd41b906}`**

<br />

## Reference

http://swtv.kaist.ac.kr/courses/cs492-fall17/coverage/lec5.5-cfg-generation.pdf

https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf