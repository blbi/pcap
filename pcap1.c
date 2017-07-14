#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
//====struct====
#include <netinet/if_ether.h> 
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
//===============
#define TIMEOUT     1000
#define PROMISC     0
#define MAXCOUNT    0

int length;
//print data
void print_data(const u_char *data){
	printf("Data :\n");
	int cnt=1;
	while(length){
		printf("%02x  " ,*data++);
		if(cnt%16==0) printf("\n");
		cnt++;
		length--;
	}
	printf("\n\n");	
}

//print source, destination mac, ip address, port
void print_addr (u_char *not_used, const struct pcap_pkthdr *h, const u_char *p){

    	int i;
    	struct ether_header *eh = (struct ether_header *)p;
    
    	printf("========================packet info==========================\n\n");
	
	//length
	length=h->len;
	printf("Length: %d\n\n", length);

	//mac address
    	printf("Source mac address: ");

    	for (i=0; i<ETH_ALEN-1; i++)
    	{
        	printf ("%02x:", eh->ether_shost[i]);
    	}
	printf("%02x\n\n", eh->ether_shost[ETH_ALEN-1]);

    	printf("Destination mac address: ");
    	for (i=0; i<ETH_ALEN-1; i++)
    	{
        	printf ("%02x:", eh->ether_dhost[i]);
    	}
	printf ("%02x\n\n", eh->ether_dhost[ETH_ALEN-1]);

	//ip address
	struct ip *iph = (struct ip *)(p+sizeof(struct ether_header));

	char srcIP[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(iph->ip_src), srcIP, INET_ADDRSTRLEN);
	printf("Source Ip Address : %s\n\n", srcIP);
		
	char dstIP[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(iph->ip_dst), dstIP, INET_ADDRSTRLEN);
	printf("Destination Ip Address : %s\n\n", dstIP);	
	
	//tcp port
	struct tcphdr *tcph = (struct tcphdr *)(p+sizeof(struct ether_header)+sizeof(struct ip));
	
	printf("Source Port : %d\n\n", ntohs(tcph->source));
	printf("Destination Port : %d\n\n", ntohs(tcph->dest));

	//data
	print_data(p+sizeof(struct ether_header)+sizeof(struct ip)+sizeof(struct tcphdr)+12);//12:nop,timestamp
	
	printf("==============================================================\n\n");
}

int main(int argc, char *argv[])
{
	pcap_t  *pcd;

	char errbuf[PCAP_ERRBUF_SIZE];
	char *dev = pcap_lookupdev(errbuf);

	if ((pcd = pcap_open_live(dev, BUFSIZ, PROMISC, TIMEOUT, errbuf)) == NULL) {
        	fprintf (stderr, "Device open failed\n");
        	exit (1);
    	}
	printf("Device: %s\n\n", dev);
    	
	//print
	if (pcap_loop(pcd, MAXCOUNT, print_addr, NULL) < 0) {
        	fprintf (stderr, "Error in pcap_loop()\n");
        	exit (1);
    	}
   	pcap_close (pcd);
	
	return(0);
}
