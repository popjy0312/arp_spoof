# Send Arp
BOB6기 취약점 분석 트랙 정주영

이경문멘토님 과제 2.


## 리포트
sender(victim)의 arp table을 변조하라.

## 프로그램
```sh
send_arp <interface> <sender ip> <target ip>
```
```sh
ex : send_arp wlan0 192.168.10.2 192.168.10.1
```

sender ip는 victim ip라고도 함.

target ip는 일반적으로 gateway임.

## 학습

구글링을 통해서 arp header의 구조(각 필드의 의미)를 익힌다.

pcap_sendpacket 함수를 이용해서 user defined buffer를 packet으로 전송하는 방법을 익힌다.

attacker(자신) mac 정보를 알아 내는 방법은 구글링을 통해서 코드를 베껴 와도 된다.

arp infection packet 구성에 필요한 sender mac 정보는 프로그램 레벨에서 자동으로(정상적인 arp request를 날리고 그 arp reply를 받아서) 알아 오도록 코딩한다.

최종적으로 상대방을 감염시킬 수 있도록 eth header와 arp header를 구성하여 arp infection packet을 보내고 sender에서 target arp table이 변조되는 것을 확인해 본다.
