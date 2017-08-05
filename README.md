# Arp Spoof
BOB6기 취약점 분석 트랙 정주영

이경문멘토님 과제 3.

## 리포트
arp spoofing 프로그램을 구현하라.

victim(sender)에서 ping 통신이 원활히 작동하면 과제 완료.

## 프로그램
```sh
arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]

ex : arp_spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2
```

## 학습
지난번 과제를 완료를 해야만 본 과제를 진행할 수 있음.

오늘 배운 "ARP spoofing의 모든 것" PPT 숙지할 것.

## ps
소스 코드는 가급적 C, C++(다른 programming language에 익숙하다면 그것으로 해도 무방).

bob@gilgil.net 계정으로 자신의 git repository 주소를 알려 줄 것.

절대 BoB AP 네트워크를 대상으로 테스트하지 말 것.

개인 허니팟을 띄워 하거나 BoBMil이라는 AP(암호는 BoB AP와 동일)를 사용할 것.

필요에 따라 thread도 써야 하고, arp spoofing session을 list 관리도 해야 하고... 이번 과제부터 멘붕이 오기 시작할 것임. C++ 사용 추천.
