---
title: "2017 Dimi CTF Prequal ToHard"
date: 2019-7-27
tags: [dimi,angr]
categories: [Dimi]
---

디컴파일을 하면 이렇게 나온다. mips로 짠 문제다. 그냥 angr로 슥삭 돌리면 풀린다.

```c
undefined4 main(void)
{
  int iVar1;
  int local_78;
  int local_74;
  byte local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  byte local_4c [30];
  byte local_2e;
  byte abStack45 [37];
  
  local_6c = 0x7e067d4b;
  local_68 = 0x2b74014c;
  local_64 = 0xb3d4113;
  local_60 = 0x52763724;
  local_5c = 0x2c5f7e5e;
  local_58 = 0x41097120;
  local_54 = 0x40246d5b;
  local_50 = 0x334e2e00;
  printf("INPUT: ");
  __isoc99_scanf(&DAT_00400cb8,local_4c);
  strncpy((char *)(abStack45 + 1),(char *)local_4c,0x20);
  local_78 = 1;
  while (local_78 < 0x1f) {
    abStack45[local_78 + 1] = abStack45[local_78 + 1] ^ abStack45[local_78];
    local_78 = local_78 + 1;
  }
  local_78 = 0;
  while (local_78 < (int)(uint)(local_2e % 0x1f)) {
    local_74 = 0x1f;
    while (-1 < local_74) {
      if (local_74 == 0) {
        local_4c[0] = local_70;
      }
      else {
        if (local_74 == 0x1f) {
          local_70 = local_2e;
        }
        else {
          local_4c[local_74] = *(byte *)((int)&local_50 + local_74 + 3);
        }
      }
      local_74 = local_74 + -1;
    }
    local_78 = local_78 + 1;
  }
  local_78 = 0;
  while (local_78 < 0x1f) {
    local_4c[local_78] = local_4c[local_78] ^ abStack45[local_78 + 1];
    local_78 = local_78 + 1;
  }
  local_78 = 0xf;
  while (local_78 < 0x1f) {
    abStack45[local_78 + 1] = local_4c[local_78];
    local_78 = local_78 + 1;
  }
  local_78 = 0;
  while (local_78 < 0x20) {
    abStack45[local_78 + 1] = abStack45[local_78 + 1] ^ *(byte *)((int)&local_6c + local_78);
    local_78 = local_78 + 1;
  }
  iVar1 = strncmp((char *)(abStack45 + 1),"Oh_You_Finally_Match_The_Keys!!",0x1f);
  if (iVar1 == 0) {
    puts("Correct!");
  }
  else {
    puts("Try Again");
  }
  return 0;
}
```

<br />

```python
import angr
p = angr.Project('./ToHard',load_options={"auto_load_libs":True})
ex = p.surveyors.Explorer(find=0x0400ad8, avoid=0x0400aec)
ex.run()
print ex.found[0].state.posix.dumps(0)
```

**FLAG : `1_L0VE_Th1s_A1g0r1thm_AnD_M1pS!`**