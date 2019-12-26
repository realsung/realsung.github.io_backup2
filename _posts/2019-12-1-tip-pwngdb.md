---
title: "Pwngdb 명령어 정리"
date: 2019-12-1
tags: [Pwngdb]
categories: [Tip]
---

`magic` - glibc에서 유용한 변수와 함수를 표시

`rop` - ROP gadget 표시

`heapinfoall` - 모든 힙 정보 표시

`parseheap` - 할당되거나 free된 Chunk 정보 표시

`arenainfo` - arena 정보 표시

`heap` - heap base 정보 표시

`heapinfo` - free된 티캐시, 패스트빈 목록 확인 가능 , tcache가 사용 가능한 경우 tcache 항목에 대한 정보 표시

`orange [File 주소]` - house of orange 조건 - _IO_flush_lockp (glibc버전 <= 2.23)

`findsyscall` - syscall 찾기

`mergeinfo [주소]` - 병합된 정보 표시

`got` - 글로벌 오프셋 테이블 정보 인쇄

`fp [주소]` - 파일 구조 표시

`chunkinfo [주소]` - 청크 정보 표시 

`chunkptr - [ptr주소]` - 청크 정보 표시

`heapbase` - heap base 주소 표시

`codebase` - code base 주소 표시

`tracemalloc on` -  malloc 추적

`libc` - libc base 출력

