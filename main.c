
#include <stdio.h>  /* Standard I/O */
#include <stdlib.h> /* Standard Library */
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

u_int8_t my_mac[6];
u_int32_t vic_ip, gate_ip;

typedef struct arp_header{
	u_int16_t hw_type;
	u_int16_t protocol;
	u_int8_t mac_len;
	u_int8_t ip_len;
	u_int16_t op_code;
	u_int8_t sender_mac[6];
	u_int32_t sender_ip;
	u_int8_t target_mac[6];
	u_int32_t target_ip;
}arp_h;

int main(int argc, char *argv[])
{

	char *dev = argv[1];
	get_local_mac(dev,(unsigned char *) my_mac);
	char *vic_ip = argv[2];
	char *gate_ip = argv[3];
	
	send_packet(dev, vic_ip, gate_ip);
	/*
	int i;
	for (i = 0; i < IFHWADDRLEN; i++)
	{
		printf("%02X:", my_mac[i]);
	}
	*/
}


u_int8_t *get_local_mac(const char *ifname, unsigned char *mac)
{
	struct ifreq ifr;
	int fd;
	int *rv; // return value - error value from df or ioctl call

	/* determine the local MAC address */
	strcpy(ifr.ifr_name, ifname);
	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (fd < 0)
		rv = fd;
	else
	{
		*rv = ioctl(fd, SIOCGIFHWADDR, &ifr);
		if (*rv >= 0) /* worked okay */
			memcpy(mac, ifr.ifr_hwaddr.sa_data, IFHWADDRLEN);
	}

	return rv;
}

void send_packet(char *dev, char *victim, char *gateway){
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_char packet[32];

	if((fp = pcap_open(dev,32,1, 1000, NULL, errbuf)) == NULL){
		fprintf(stderr, "tt");
		return;
	}
	/* make arp packet! */
	arp_h *arp = (arp_h *)malloc(sizeof(arp_h));
	arp->hw_type = 0x0001;
	arp->protocol = 0x0800;
	arp->mac_len = 0x06;
	arp->ip_len = 0x04;
	arp->op_code = 0x0002;		
	arp->sender_mac = get_local_mac(dev,(unsigned char *)my_mac);
	arp->sender_ip = gateway;
//	arp->target_mac = 
	arp->target_ip = victim;
	printf("%12\n", arp->sender_ip);
}
