---
title: "ARM Architecture"
date: 2019-7-20
tags: [ARM]
categories: [Reversing]
---

ARM 아키텍쳐에 대해 정리해놓으려고 한다.

[참고 : Reference](http://infocenter.arm.com/help/index.jsp)

<br />

## Register

```
R0 ~ R12 : 범용 레지스터 (다목적 레지스터)
R0 : 함수 리턴 값 저장 (EAX 같은 느낌)
R0 ~ R3 : 함수 호출 인자 전달
R13 ~ R15 : 특수 레지스터
R13(SP) : 스택 포인터 : 스택의 맨 위를 가리킴
R14(LR) : 링크 레지스터 : 서브루틴 후에 돌아갈 리턴 주소 저장
R15(PC) : 프로그램 카운터 : 현재 fetch되고 있는 명령어의 주소 - 따라서 현재 실행되는 명령어의 다음다음 주소
```

![](https://user-images.githubusercontent.com/32904385/61888031-bff6d000-af3d-11e9-9044-da6ffca518fb.png)

<br />

## CSPR Register

CSPR(Current Program Status Register)

CPSR의 레이아웃은 32비트를 기준으로 8 비트씩, 플래그(Flag) 비트, 상태(Status) 비트, 확장(Extension)비트, 제어(Control)비트로 나뉜다.

![](https://user-images.githubusercontent.com/32904385/61804158-64a9dc80-ae6e-11e9-9cab-d30ec4dd19af.png)

```
N(Negative) : 음수 플래그 (연산 결과가 음수일 경우)
Z(Zero) : 제로 플래그 (연산 결과가 0일 경우, 비교 결과가 같을 경우)
C(Carry) : 캐리 플래그 (연산 결과에서 자리 올림이 발생한 경우)
V(oVerflow) : 오버플로우 플래그 (연산 결과가 오버플로우 난 경우)
```

<br />

## Instruction

```
형식 : <Operation>{<cond>}{S} Rd, Rn, Op2
- Operation : 명령어
- cond : 접미사
- S : CSPR Setting
- Rd(Destination Register) : 목적지 레지스터
- Rn : 레지스터
- 두 번째 OPERAND : 레지스터 or 상수(앞에 #이 붙음)

ex) ADD r0, r1, r2 ; r0 = r1 + r2
```

<br />

## 접미사

```
EQ	: Z Set	-> equal
NE	: Z Clear -> not equal
GE	: N equal V -> greater or equal
LT	: N not equal V	-> less than
GT	: Z Clear and (N equal V) -> greater than
LE	: Z Set or (N not equal V) -> less than or equal
S	  : Execution Instruction and CPSR Register Setting

ex) ADDEQ r0, r1, r2 ; if(ZF) r0 = r1 + r2 -> if(r0 == r1+r2){ }
```

![](https://user-images.githubusercontent.com/32904385/61806777-40043380-ae73-11e9-8948-709d3dad72e0.jpg)

<br />

## Function Calling

```
1) 프롤로그 (서브루틴을 호출하기 직전)에 r4 부터 r11 까지 스택에 저장(push)하고 r14(리턴어드레스)를 스택에 저장(push)한다.
2) r0 - r3 중에 함수에 전달할 인자값이 있으면 이것을 r4 - r11 (임의)로 복사한다.
3) 나머지 지역변수들은 r4 - r11 중 남아있는 곳에 할당한다. 
4) 연산을 수행한 후 다른 서브루틴이 있다면 호출한다.
5) r0 에 리턴값(결과)를 저장한다.
6) 에필로그(원래있던 곳으로 복귀)에 스택에서 r4 - r11 을 꺼내고 r15(프로그램 카운터)에서 리턴어드레스(복귀주소)를 꺼낸다.
```

<br />

## 명령어

```assembly
산술 연산 (<Operation>{<cond>}{S} Rd, Rn, Op2) 
ADD r0, r1, r2 ; r0 = r1 + r2
SUB r0, r1, r2 ; r0 = r1 - r2
MUL r0, r1, r2 ; r0 = r1 * r2
UMULL r0, r1, r2, r3 ; 부호가 없는 곱하기 r2 * r3 해서 하위 32비트를 r0에, 상위 32비트를 r1에 저장
SMULL r0, r1, r2, r3 ; r2와 r3의 값을 2의 보수 부호 있는 정수로 해석하고 둘을 곱하고 하위 32비트를 r0, 상위 32비트를 r1에 저장
[예제]
SUBNE r1, r2, r3 ; if(!ZF) r1 = r2 - r3
MULEQ r1, r2, r3 ; if(ZF) r1 = r2 * r3


비교 연산 (<Operation>{<cond>} Rn, Op2)
- 비교 연산 결과는 CPSR의 플래그 설정
CMP r0, r1 ; r0 - r1 
TST r0, r1 ; r0 & r2

[예제]
CMP r0 #10 ; r0이 10이면 Zero Flag 0으로 세팅


논리 연산 (<Operation>{<cond>}{S} Rd, Rn, Op2)
AND r0 r1 ; r0 & r1
EOR r0 r1 ; r0 ^ r1
ORR r0 r1 ; r0 | r1

[예제]
AND r0, r1, r2 ; r0 = r1 & r2
EORNE r0, r1, r2 ; if(!ZF) r0 = r1 ^ r2
EORGT r0, r1, r2 ; Greater than r0 = r1 ^ r2

데이터 이동 
- 메모리 접근 불가 (<Operation>{<cond>}{S} Rd, Op2)
MOV r0 r1; r0 <- r1
MVN r0 r1; r0 <~ ~r1

- 메모리 접근 가능 (<Operation>{<cond>}{B, H}{S} Rn, Op2)
* LDR과 STR은 값을 넣는 오퍼랜드 방향이 반대임
LDR r0 r1; r0 = r1(Memory)
STR r0 r1; r1(Memory) = r0

[예제]
MOVEQS r0, r1, LSR #3 ; if(ZF)r0 = (r1 >> 3); CPSR
LDRB r0, [r1], LSL # 2 ; r0 = *(Byte*)r1 << 2
LDR r0, [r1] ; r0 = *r1
LDR r0, 0xdeadbeef ; r0 = *0xdeadbeef
STR r0, [r1, #4] ; *(r1+4) = r0
STR r0, [r1], #4 ; *(r1) = r0 그리고 r1 += 4
LDRB r0, [r1, r2] ; r0 = *(Byete*)(r1+r2)
STRH r0, [r1] ; *(Half Word*)r1 = r0


주소 분기 (<Operation> {<cond>}{S} Label(function))
B operand1 ; Jump operand1
BL operand1, LR ; operand1 함수 호출 LR은 리턴 주소 저장

[예제]
BL _printf ; printf 함수 호출
BL sub_404040 ; sub_404040 함수 호출
B aaaa ; aaaa로 분기 
BEQ success ; 제로 플래그 세팅되어 있으면 success로 분기

베럴 쉬프트 (<Operation> {<cond>}{S} Rd, Rn, Op2, {<Barrel>} Shift)
LSL ; 왼쪽으로 쉬프트, 빈자리 0
LSR ; 오른쪽으로 쉬프트, 빈자리 0
ASL ; 왼쪽으로 쉬프트, 빈자리 부호
ASR; 오른쪽으로 쉬프트, 빈자리 부호

[예제]
MOV r0, r1, LSL #2 ; r0 = r1 << 2
ADD r0, r1, r2, LSL #3 ; r0 = r1 + (r2 << 3)
EOREQ r0, r1, r2, LSR r4 ; if(ZF) r0 = r1 ^ (r2 >> r4)
AND r0, r1, r2 LSR r3 ; r0 = r1 & (r2 >> r3)
```

<br />

## Analysis Setting

`arm-linux-gnueabi-gcc a.c -o a` : ARM Cross Compile

`qemu-arm ./a` : File Execute

`qemu-arm-static -L /usr/arm-linux-gnueabihf ./a` : File Execute

### GDB

`qemu-arm-static -L /usr/arm-linux-gnueabi -g 1234 ./analysis1` : terminal1

`gdb-multiarch -q` : terminal2 

`target remote localhost:1234` : terminal2

<br />

[* ARM Setting *](https://zer0day.tistory.com/356)

[* 실행 오류시 참고 *](https://stackoverflow.com/questions/16158994/how-to-solve-error-while-loading-shared-libraries-when-trying-to-run-an-arm-bi)

<br />