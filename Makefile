all: pcap1

pcap1 : pcap1.c
	gcc -o pcap1 pcap1.c -lpcap -I/usr/include/pcap

clean:
	rm *.o pcap1
