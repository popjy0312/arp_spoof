all: arp_spoof

arp_spoof: arp_spoof.o main.o
	gcc -W -Wall -o arp_spoof arp_spoof.o main.o -lpcap
arp_spoof.o: arp_spoof.c arp_spoof.h
	gcc -c -o arp_spoof.o arp_spoof.c
main.o: main.c arp_spoof.h
	gcc -c -o main.o main.c

clean:
	rm *.o arp_spoof
