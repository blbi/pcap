#include <stdio.h>
#include <pcap.h>

#include <unistd.h>
#include <stdlib.h>
#include <netinet/if_ether.h> // for 'struct ether_header'
#define TIMEOUT     1000
#define PROMISC     0
#define MAXCOUNT    0

void print_addr (u_char *not_used, const struct pcap_pkthdr *h, const u_char *p)
{
    int i;
    struct ether_header *eh = (struct ether_header *)p;
    printf("\n\nsource mac address: ");
    for (i=0; i<ETH_ALEN; i++)
    {
        printf ("%02x:", eh->ether_shost[i]);
    }
   // printf (" -> ");
    printf("\n\ndestination mac address: ");
    for (i=0; i<ETH_ALEN; i++)
    {
        printf ("%02x:", eh->ether_dhost[i]);
    }
    printf (" length = %d\n", h->len);
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
    	if (pcap_loop(pcd, MAXCOUNT, print_addr, NULL) < 0) {
        fprintf (stderr, "Error in pcap_loop()\n");
        exit (1);
    	}
   	pcap_close (pcd);


	 printf("Device: %s\n", dev);
	 return(0);
}
