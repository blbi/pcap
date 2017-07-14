#include <stdio.h>
#include <pcap.h>

#include <unistd.h>
#include <stdlib.h>
#include <netinet/if_ether.h> // for 'struct ether_header'
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#define TIMEOUT     1000
#define PROMISC     0
#define MAXCOUNT    0

void print_addr (u_char *not_used, const struct pcap_pkthdr *h, const u_char *p)
{
    	int i;
    	struct ether_header *eh = (struct ether_header *)p;
    
	
    	printf("source mac address: ");
    	for (i=0; i<ETH_ALEN-2; i++)
    	{
        	printf ("%02x:", eh->ether_shost[i]);
    	}
	printf("%02x\n\n", eh->ether_shost[ETH_ALEN-1]);
   // printf (" -> ");
    	printf("destination mac address: ");
    	for (i=0; i<ETH_ALEN-2; i++)
    	{
        	printf ("%02x:", eh->ether_dhost[i]);
    	}
	printf ("%02x\n\n", eh->ether_dhost[ETH_ALEN-1]);

//	unsigned short ether_type = ntohs(eh->ether_type);

	struct ip *iph = (struct ip *)(p+sizeof(struct ether_header));


//	if (ether_type == ETHERTYPE_IP){

//	printf ("%s\n",ether_type);
		char srcIP[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &(iph->ip_src), srcIP, INET_ADDRSTRLEN);
		printf("Src ip Address : %s\n\n", srcIP);
		
		char dstIP[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &(iph->ip_dst), dstIP, INET_ADDRSTRLEN);
		printf("Dst ip Address : %s\n\n", dstIP);	
		
        //`	printf("Dst Address : %s\n", inet_ntoa(iph->ip_dst));
	//	printf("ip source address : %s\n", inet_ntoa(iph->ip_src));
	//	printf("ip destination address : %s\n", inet_ntoa(iph->ip_dst));
    	//	printf (" length = %d\n", h->len);
//	}
	
	struct tcphdr *tcph = (struct tcphdr *)(p+sizeof(struct ether_header)+sizeof(struct ip));
	
	printf("Source Port : %d\n\n", ntohs(tcph->source));
	printf("Destination Port : %d\n\n", ntohs(tcph->dest));
}

int main(int argc, char *argv[])
{
	struct bpf_program fp;
	pcap_t  *pcd;
	char filter_exp[]="port 80";

	char errbuf[PCAP_ERRBUF_SIZE];
	char *dev = pcap_lookupdev(errbuf);

	if ((pcd = pcap_open_live(dev, BUFSIZ, PROMISC, TIMEOUT, errbuf)) == NULL) {
        fprintf (stderr, "Device open failed\n");
        exit (1);
    	}
	pcap_compile(pcd,&fp,filter_exp,0,net);
	pcap_setfilter(pcd, &fp);

    	if (pcap_loop(pcd, MAXCOUNT, print_addr, NULL) < 0) {
        fprintf (stderr, "Error in pcap_loop()\n");
        exit (1);
    	}
   	pcap_close (pcd);


	 printf("Device: %s\n", dev);
	 return(0);
}
