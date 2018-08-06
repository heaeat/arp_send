#include <stdio.h>  /* Standard I/O */
#include <stdlib.h> /* Standard Library */
#include <string.h>
#include <errno.h>  /* Error number and related */
 #define ENUMS
#include <sys/socket.h>
#include <net/route.h>
#include <net/if.h>
#include <features.h> /* for the glibc version number */
#if __GLIBC__ >= 2 && __GLIBC_MINOR >= 1
#include <netpacket/packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#else
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h> /* The L2 protocols */
#endif
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <netdb.h>
 #include <pcap.h>

#define MACLEN 6

typedef struct _ethernet_header{
	u_int8_t ether_dhost[MACLEN];
	u_int8_t ether_shost[MACLEN];
	u_int16_t ether_type;
}ethernet_hdr;

typedef struct _arp_header{
	u_int16_t ar_hrd;
	u_int16_t ar_pro;
	u_int8_t ar_hln;
	u_int8_t ar_pln;
	u_int16_t ar_op;
	u_int8_t *ar_src_mac;
	u_int32_t ar_src_ip;
	u_int8_t *ar_dst_mac;
	u_int32_t ar_dst_ip;
}arp_hdr;

int get_local_mac(const char *dev, unsigned char *mac);
void send_request(char *dev, u_int32_t victim,u_int32_t gateway);
void send_reply(char *dev, u_int32_t victim, u_int32_t gateway);

int main(int argc, char *argv[])
{

	char *dev = argv[1];
	u_int32_t vic_ip = *(uint32_t *)argv[2];
	u_int32_t gate_ip = *(uint32_t *)argv[3];
	send_reply(dev, vic_ip, gate_ip);
	
}


int get_local_mac(const char *dev, u_int8_t *mac)
{
	struct ifreq ifr;
	int fd;
	int rv;		// return value - error value from df or ioctl call

	/* determine the local MAC address */
	strcpy(ifr.ifr_name, dev);
	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (fd < 0)
		rv = fd;
	else
	{
		rv = ioctl(fd, SIOCGIFHWADDR, &ifr);
		if (rv >= 0) /* worked okay */
			memcpy(mac, ifr.ifr_hwaddr.sa_data, IFHWADDRLEN);
	}

	return rv;
}


void send_request(char *dev, u_int32_t victim, u_int32_t host){


}

void send_reply(char *dev, u_int32_t victim, u_int32_t gateway){
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_char packet[32];

	if ( (fp = pcap_open_live(dev, BUFSIZ, 0, 0, errbuf)) == NULL){
		fprintf(stderr, "tt");
		return;
	}
	/* make arp packet! */
	arp_hdr *arp_h = (arp_hdr *)malloc(sizeof(arp_hdr));
	arp_h->ar_src_mac = (u_int8_t *)malloc(sizeof(u_int8_t) * MACLEN);
	arp_h->ar_dst_mac = (u_int8_t *)malloc(sizeof(u_int8_t) * MACLEN);

	arp_h->ar_hrd = 0x0001;
	arp_h->ar_pro = 0x0800;
	arp_h->ar_hln = 0x06;
	arp_h->ar_pln = 0x04;
	arp_h->ar_op = 0x0002;		

	get_local_mac(dev, arp_h->ar_src_mac);
	
	for(int i = 0 ; i <MACLEN; i++){
		printf("%02x ", arp_h->ar_src_mac[i]);
	}
	
	for(int i = 0 ; i <MACLEN; i++){
		arp_h->ar_dst_mac[i] = 0xff;
	}
	
	arp_h->ar_src_ip = (uint32_t)gateway;
	arp_h->ar_dst_ip = (u_int32_t)victim;
}

