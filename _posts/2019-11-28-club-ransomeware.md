---
title: "동아리 프로젝트 랜섬웨어 개발"
date: 2019-11-28
tags: [Club, Project]
categories: [Club]
---

동아리 프로젝트로 [랜섬웨어](https://github.com/realsung/Ransomeware)를 개발하게 되었다.

파일을 암호화, 복호화 할 수 있다. 암호화 방식은 AES, SHA256를 이용하였다.

바탕화면에 있는 모든 파일을 암호화 시켜줄 수 있다.

발표 PPT : [랜섬웨어_발표.pptx](https://github.com/realsung/realsung.github.io_backup/files/3991220/_.pptx) - password : 3131

# Ransomeware?

랜섬웨어(RansomWare)란 몸값을 의미하는 Ransom, 소프트웨어의 Software 가 합쳐진 것이다. 이 프로그램은 사용자의 파일을 허가 없이 암호화한 후, 복호화를 빌미로 사용자에게 돈을 갈취하는 악성 프로그램이다. 

# 개발

개발 환경 : Python 3.7.0

Crypto라는 모듈을 사용해 AES암호화 방식

1. 서버에서 Key 값을 가져와서 Base64로 키 값을 복호화 후 AES 암호화 시킴

2. Decode할 때도 Key 값을 가져와서 AES 복호화

