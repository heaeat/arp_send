# arp_send
Repository for arp_send homework (feat. gilgil Mentor) 

## Before Start
### How ARP packet works?
1. 출발지에서 ARP table에 목적지 MAC주소가 있는지 확인  
2. ARP table에 없으면 ARP request **브로드캐스트**(~~브로드캐스트! 만세~~)
3. ARP request 패킷을 받은 쪽에서 자신의 MAC주소를 ARP reply 패킷으로 알려줌
4. ARP reply패킷을 받은 출발지는 ARP 테이블에 해당 정보를 기록
(중간중간 게이트웨이가 리커버리 하기는 함)


### Reference
* https://www.winpcap.org/docs/docs_40_2/html/group__wpcap__tut8.html
* https://linux.die.net/man/3/pcap_sendpacket

### ARP header structure
`Hardware type` : 2 byte  
`Protocol type` : 2 byte  
`H/W address length` : 1 byte  
`protocol address length` : 1 byte  
`Operation` : 2 byte  
`Source MAC` : 6 byte  
`Source IP` : 4 byte  
`Destination MAC` : 6 byte  
`Destination IP` : 4 byte  
