#include <stdio.h>  /* Standard I/O */
#include <stdlib.h> /* Standard Library */
#include <string.h>
#include <errno.h> /* Error number and related */
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

typedef struct _ethernet_header
{
	u_int8_t ether_dhost[MACLEN];
	u_int8_t ether_shost[MACLEN];
	u_int16_t ether_type;
} ethernet_hdr;

typedef struct _arp_header
{
	u_int16_t ar_hrd;
	u_int16_t ar_pro;
	u_int8_t ar_hln;
	u_int8_t ar_pln;
	u_int16_t ar_op;
	u_int8_t *ar_src_mac;
	u_int32_t ar_src_ip;
	u_int8_t *ar_dst_mac;
	u_int32_t ar_dst_ip;
} arp_hdr;

int get_local_mac(const char *dev, unsigned char *mac);
void send_request(char *dev, const char *victim, const char *host);
void send_reply(char *dev, const char *victim, const char *gateway);

int main(int argc, char *argv[])
{
	if (argc < 4)
	{
		printf("wrong!\n[format] sudo ./send_arp <devname> <victim ip> <gateway ip>\n");
		return -1;
	}
	char *dev = argv[1];
	//const char *vic_ip = *(uint32_t *)argv[2];
	const char *vic_ip = (const char *)argv[2];
	const char *gate_ip = (const char *)argv[3];
	send_reply(dev, vic_ip, gate_ip);
	return 0;
}

int get_local_mac(const char *dev, u_int8_t *mac)
{
	struct ifreq ifr;
	int fd;
	int rv; // return value - error value from df or ioctl call

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

void ipchar_to_uint(const char *char_ip, unsigned int *int_ip)
{
	unsigned int byte3;
	unsigned int byte2;
	unsigned int byte1;
	unsigned int byte0;
	char dummyString[2];

	/* The dummy string with specifier %1s searches for a non-whitespace char
    * after the last number. If it is found, the result of sscanf will be 5
    * instead of 4, indicating an erroneous format of the ip-address.
    */
	if (sscanf(char_ip, "%u.%u.%u.%u%1s",
			   &byte3, &byte2, &byte1, &byte0, dummyString) == 4)
	{
		if ((byte3 < 256) && (byte2 < 256) && (byte1 < 256) && (byte0 < 256))
		{
			*int_ip = (byte3 << 24) + (byte2 << 16) + (byte1 << 8) + byte0;

			//return 1;
		}
	}

	//return 0;
}

void send_request(char *dev, const char *victim, const char *host)
{
}

void send_reply(char *dev, const char *victim, const char *gateway)
{
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_char packet[32];

	if ((fp = pcap_open_live(dev, BUFSIZ, 0, 0, errbuf)) == NULL)
	{
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

	for (int i = 0; i < MACLEN; i++)
	{
		printf("%02x ", arp_h->ar_src_mac[i]);
	}

	for (int i = 0; i < MACLEN; i++)
	{
		arp_h->ar_dst_mac[i] = 0xff;
	}


	ipchar_to_uint(gateway, &arp_h->ar_src_ip);
	printf("src_ip : %x\n", arp_h->ar_src_ip);

	ipchar_to_uint(victim, &arp_h->ar_dst_ip);
	printf("dst_ip : %x\n", arp_h->ar_dst_ip);

}
