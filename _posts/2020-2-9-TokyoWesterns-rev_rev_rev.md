---
title: "2017 TokyoWesterns CTF 3rd rev_rev_rev"
date: 2020-2-9
tags: [TokyoWesterns]
categories: [TokyoWesterns]
---

```c
int __cdecl main()
{
  char s; // [esp+1Bh] [ebp-2Dh]
  unsigned int v2; // [esp+3Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  puts("Rev! Rev! Rev!");
  printf("Your input: ");
  if ( !fgets(&s, 33, stdin) )
  {
    puts("Input Error.");
    exit(0);
  }
  sub_80486B9(&s);
  sub_80486DB(&s);
  sub_8048738(&s);
  sub_80487B2(&s);
  if ( !strcmp(&s, s2) )
    puts("Correct!");
  else
    puts("Invalid!");
  return 0;
}
```

입력한 값을 연산해준 값이 s2여야한다. c++로 브포코드 짰다. 근데 IDA만 보고 정적으로 풀어서 그렇지만 컴파일할 때 최적화되서 그런데 MUL 연산이 아니라 내부에서는 쉬프트연산 해주고 있다.

```
sub_80486B9 : \n -> \x00 replace
sub_80486DB : str reverse
sub_8048738 : shift, and, or operation
sub_80487B2 : bit not operation
```

> solve.py

```c++
#include <iostream>
#include <algorithm>
using namespace std;

int main(){
	//char input[32];
	string input;
    unsigned char s2[32] = {
    0x41, 0x29, 0xD9, 0x65, 0xA1, 0xF1, 0xE1, 0xC9, 0x19, 0x09, 0x93, 0x13, 0xA1, 0x09, 0xB9, 0x49, 
    0xB9, 0x89, 0xDD, 0x61, 0x31, 0x69, 0xA1, 0xF1, 0x71, 0x21, 0x9D, 0xD5, 0x3D, 0x15, 0xD5, 0x00 };
    // for(int i=0; i<sizeof(s2)/sizeof(unsigned char); i++){
    // 	s2[i] = ~s2[i];
    // }
    for(unsigned int i=0; i<sizeof(s2); i++){
    	for(unsigned char j=32; j<127; j++){
    		unsigned char c = j;
    		c = (2 * (c & 0x55)) | ((c >> 1) & 0x55);
        c = (4 * (c & 0x33)) | ((c >> 2) & 0x33);
        c = 16 * c | (c >> 4);
        c = ~c & 0xff;
        if(c == s2[i]){
            input.push_back(j);
        }
    	}
    }
    reverse(input.begin(),input.end());
    cout << input;
}
```

**FLAG : `TWCTF{qpzisyDnbmboz76oglxpzYdk}`**