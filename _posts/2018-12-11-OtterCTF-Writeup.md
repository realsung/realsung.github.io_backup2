---
title: "2018 Otter CTF Writeup"
date: 2018-12-11
tags: [OtterCTF]
categories: [CTF]
---

### 1 - What the password? - 100pt

> you got a sample of rick's PC's memory. can you get his user password? 

format: CTF{...}

```
$ vol.py -f OtterCTF.vmem --profile=Win7SP1x64 hashdump -s 0xfffff8a0016d4010

Volatility Foundation Volatility Framework 2.6
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Rick:1000:aad3b435b51404eeaad3b435b51404ee:518172d012f97d3a8fcc089615283940:::
```

hivescan 해준걸 hashdump떠서 봤는데 이렇게 3개의 계정이 나왔다.

```
$ vol.py -f OtterCTF.vmem --profile=Win7SP1x64 lsadump
Volatility Foundation Volatility Framework 2.6
DefaultPassword
0x00000000  28 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   (...............
0x00000010  4d 00 6f 00 72 00 74 00 79 00 49 00 73 00 52 00   M.o.r.t.y.I.s.R.
0x00000020  65 00 61 00 6c 00 6c 00 79 00 41 00 6e 00 4f 00   e.a.l.l.y.A.n.O.
0x00000030  74 00 74 00 65 00 72 00 00 00 00 00 00 00 00 00   t.t.e.r.........

DPAPI_SYSTEM
0x00000000  2c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ,...............
0x00000010  01 00 00 00 36 9b ba a9 55 e1 92 82 09 e0 63 4c   ....6...U.....cL
0x00000020  20 74 63 14 9e d8 a0 4b 45 87 5a e4 bc f2 77 a5   .tc....KE.Z...w.
0x00000030  25 3f 47 12 0b e5 4d a5 c8 35 cf dc 00 00 00 00   %?G...M..5......
```

lsadump 떠줘서 가져왔다.

예시 : https://www.aldeid.com/wiki/Volatility/Retrieve-password

lsadump plugin : https://github.com/volatilityfoundation/volatility/blob/master/volatility/plugins/registry/lsadump.py

FLAG : `CTF{MortyIsReallyAnOtter}`

<br />

### 2 - General Info - 75pt

> Let's start easy - whats the PC's name and IP address?

format: CTF{flag}

#### PC name

hive스캔을 먼저 떠줬다.

```
$ vol.py -f OtterCTF.vmem --profile=Win7SP1x64 hivelist
```

그리고 컴퓨터 이름이 저장된 레지스트리로 가서 가져왔다.

**컴퓨터 이름 레지스트리 : HKLM\SYSTEM\ControlSet00X\Control\ComputerName\ActiveComputerName**

```
$ vol.py -f OtterCTF.vmem --profile=Win7SP1x64 printkey -o 0xfffff8a000024010 -K \ControlSet001\\Control\\ComputerName\\ActiveComputerName
Volatility Foundation Volatility Framework 2.6
Legend: (S) = Stable   (V) = Volatile

----------------------------
Registry: \REGISTRY\MACHINE\SYSTEM
Key name: ActiveComputerName (V)
Last updated: 2018-08-04 19:26:11 UTC+0000

Subkeys:

Values:
REG_SZ        ComputerName    : (V) WIN-LO6FAF3DTFE
```

FLAG : `CTF{WIN-LO6FAF3DTFE}`

<br />

#### PC IP

netscan 해줘서 local Adress를 가져왔다.

```
$ vol.py -f OtterCTF.vmem --profile=Win7SP1x64 netscan
```

FLAG : `CTF{192.168.202.131}`

<br />

### 3 - Play Time - 50pt

> Rick just loves to play some good old videogames. can you tell which game is he playing? whats the IP address of the server?

format: CTF{flag}

#### Game name

프로세스 목록들보면 LunarMs.exe라는 게임을 하고 있었다.

FLAG : `CTF{LunarMS}`

<br />

#### Server IP

netscan따서 192.168.202.131과 LunarMs의 Foreign Address를 가져왔다.

FLAG : `CTF{77.102.199.102}`

<br />

### 4 - Name Game - 100pt

> We know that the account was logged in to a channel called Lunar-3. what is the account name?

format: CTF{flag}

```
$ vol.py -f OtterCTF.vmem --profile=Win7SP1x64 memdump -p 708 -D .
```

먼저 LunarMS 게임을 덤프 떠서 가져온다. LunarMS의 pid는 708이다

```
strings -a 708.dmp > prob3.txt
```

거기서 strings로 따서 Lunar-3를 검색해보면 Lunar-3 밑에 `0tt3r8r33z3` 가 적혀있었다. FLAG같아서 인증했다.

FLAG : `CTF{CTF{0tt3r8r33z3}}`

<br />

### 5 - Name Game2 - 150pt

> From a little research we found that the username of the logged on character is always after this signature: 0x64 0x??{6-8} 0x40 0x06 0x??{18} 0x5a 0x0c 0x00{2} What's rick's character's name? 

format: CTF{...}

No solve

<br />

### 6 - Silly Rick - 100pt

> Silly rick always forgets his email's password, so he uses a Stored Password Services online to store his password. He always copy and paste the password so he will not get it wrong. whats rick's email password?

format: CTF{flag}

복사 붙여넣기를 사용한다고 했다. clipboard 플러그인을 사용해서 해당 값을 가져왔다.

```
$ vol.py -f OtterCTF.vmem --profile=Win7SP1x64 clipboard
Volatility Foundation Volatility Framework 2.6
Session    WindowStation Format                         Handle Object             Data
---------- ------------- ------------------ ------------------ ------------------ --------------------------------------------------
         1 WinSta0       CF_UNICODETEXT                0x602e3 0xfffff900c1ad93f0 M@il_Pr0vid0rs
         1 WinSta0       CF_TEXT                          0x10 ------------------
         1 WinSta0       0x150133L              0x200000000000 ------------------
         1 WinSta0       CF_TEXT                           0x1 ------------------
         1 ------------- ------------------           0x150133 0xfffff900c1c1adc0
```

FLAG : `CTF{M@il_Pr0vid0rs}`

<br />

### 7 - Hide And Seek - 100pt

> The reason that we took rick's PC memory dump is because there was a malware infection. Please find the malware process name (including the extension)

BEAWARE! There are only 3 attempts to get the right flag!

format: CTF{flag}

FLAG : `CTF{vmware-tray.exe}`

<br />

### 10 - Bit 4 Bit - 100pt

> We've found out that the malware is a ransomware. Find the attacker's bitcoin address.

format: CTF{...}

```
vol.py -f OtterCTF.vmem --profile=Win7SP1x64 procdump -D dump/ -p 3720
```

https://transfer.sh/Dss8z/hidd.exe 이걸 사용해 비트코인 주소를 뽑아낼 수 있다.

FLAG : `CTF{1MmpEmebJkqXG8nQv4cjJSmxZQFVmFo63M}`

<br />

### 11 - Graphics is for the weak - 150pt

> There's something fishy in the malware's graphics.

format: CTF{...}

dnspy를 이용해서 열면 확인할 수있다.

FLAG : `CTF{S0_Just_M0v3_Socy}`

