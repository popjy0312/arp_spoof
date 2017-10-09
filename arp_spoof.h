#include <stdio.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>   /*  for struct ether_header */
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <arpa/inet.h>  /* for inet_pton */
#include <string.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/stat.h>     /* for mkdir */
#include <time.h>

#define IP_ADDRLEN 4
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#define MAX_THREAD_NUM 10
#define MAX_FOLDER_NAME_LEN 25
#define MAX_FILEPATH_LEN 100

#define LOG(file, ...)\
{\
    FILE* f = fopen(file, "a");\
    fprintf(f, __VA_ARGS__);\
    fclose(f);\
}

const static unsigned char BROADCAST_MAC[ETHER_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

struct __attribute__((packed)) arp_addr{
    struct ether_addr SenderMac;
    struct in_addr SenderIP;
    struct ether_addr TargetMac;
    struct in_addr TargetIP;
};

struct Pdata{
    uint32_t idx;
    char* dev;
    char* SenderIP;
    char* TargetIP;
    char* fold;
};


void* thread_main(void* arg);

/* input dev */
/* output LocalIP Address */
int GetLocalIP(char* dev, struct in_addr* LocalIP);


/* input dev */
/* output LocalMac Address */
int GetLocalMac(char* dev, struct ether_addr* LocalMac);


/* input handle, LacalMac, LocalIP, SenderIP */
/* output SMac(Sender Mac address) */
/* send normal ARP request packet and recieve ARP reply packet */
int GetMac(char* LogFilePath, pcap_t *handle, struct ether_addr LocalMac, struct in_addr LocalIP, struct in_addr SenderIP, struct ether_addr* SMac);


/* input DMac, SMac, OpCode, SenderIP, SenderMac, TargetIP, TargetMac */
/* output packet, size */
int GenArpPacket(struct ether_addr DMac, struct ether_addr SMac, uint16_t OpCode, struct in_addr SenderIP, struct ether_addr SenderMac, struct in_addr TargetIP, struct ether_addr TargetMac, char** packet, uint32_t* size);


/* input handle, SenderMac, LocalMac, TargetIP, SenderIP */
int AttackPacket(pcap_t* handle, struct ether_addr SenderMac, struct ether_addr LocalMac, struct in_addr TargetIP, struct in_addr SenderIP);


int ArpSpoof(char* LogFilePath, pcap_t* handle, struct ether_addr SenderMac, struct ether_addr LocalMac, struct in_addr LocalIP, struct in_addr TargetIP, struct ether_addr TargetMac, struct in_addr SenderIP);

int CheckPacket(const u_char* packet, struct ether_addr shost, struct ether_addr LocalMac, struct in_addr LocalIP, struct in_addr sIp, struct in_addr dIp);

int relay(char* LogFilePath, pcap_t* handle, const u_char* packet, struct ether_addr LocalMac, struct ether_addr SenderMac, struct ether_addr TargetMac, uint32_t size);

