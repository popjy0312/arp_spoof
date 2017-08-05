all: send_arp

send_arp: send_arp.o main.o
	gcc -W -Wall -o send_arp send_arp.o main.o -lpcap
send_arp.o: send_arp.c send_arp.h
	gcc -c -o send_arp.o send_arp.c
main.o: main.c send_arp.h
	gcc -c -o main.o main.c

clean:
	rm *.o send_arp
